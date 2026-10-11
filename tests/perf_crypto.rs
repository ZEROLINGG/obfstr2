//! 原语运行时开销实测（报告-only）：各原语 dec 等价体 × 长度扫描，拟合
//! `ns = fixed + k·len`，以同 harness 下 Ascon-128 斜率为 L=80 锚点换算建议 L 分。
//!
//! - 只产 **L** 数据；S 维持论证口径，本文件不碰。
//! - 每格先 roundtrip 断言（错即 panic 中止），再 `Instant` 自适应计时；数字只展示不断言。
//! - 跑法：`cargo test --test perf_crypto -- --ignored --nocapture`
//!   （每次新建临时工程冷构建 × 3 次取中位数，约数分钟；需联网拉取 guest 依赖）。

use lib_unknown::dyntest::DnyRun;
use std::time::Duration;

const LENGTHS: [usize; 5] = [8, 16, 32, 64, 256];
const REPEATS: usize = 3;
const TIMEOUT_SECS: u64 = 600;

/// 报告行序（`trunc` 一行同时覆盖 #13 PKCS7 与 #14 标签，二者 dec 同构）。
const ROWS: [&str; 17] = [
    "memcpy",
    "xor",
    "ascon",
    "cbc",
    "add",
    "mul",
    "rotxor",
    "mse_no_ps",
    "mse_no_s",
    "mse",
    "sbox_static",
    "p_dyn",
    "s_dyn",
    "r8x3",
    "p_multi",
    "ps_multi",
    "trunc",
];

fn timeout() -> Option<Duration> {
    Some(Duration::from_secs(TIMEOUT_SECS))
}

fn guest_deps() -> String {
    [
        "lib-unknown = { version = \"0.1.6\", features = [\"crypto\", \"std\"] }",
        "ascon-aead = { version = \"0.6\", default-features = false, features = [\"alloc\"] }",
        "aead = \"0.6\"",
    ]
    .join("\n")
}

const GUEST: &str = r##"use aead::{Aead, KeyInit};
use ascon_aead::{AsconAead128, Nonce};
use lib_unknown::crypto::base::*;
use std::hint::black_box;
use std::time::Instant;

const KEY: u64 = 0x0123_4567_89AB_CDEF;
const IV: u8 = 0x5A;
const LENS: [usize; 5] = [8, 16, 32, 64, 256];

fn fresh(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect()
}

fn finish(v: Vec<u8>) {
    black_box(v.into_iter().map(|b| b as u64).sum::<u64>());
}

/// 每格自适应 LOOPS 到至少 20ms 或 500 万次；输入每次重建并 black_box，防常量折叠。
fn bench(name: &str, len: usize, mut op: impl FnMut()) {
    let mut iters: u64 = 1000;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            op();
        }
        let el = t.elapsed();
        if el.as_millis() >= 20 || iters >= 5_000_000 {
            println!(
                "{}\t{}\t{:.3}\t{}",
                name,
                len,
                el.as_nanos() as f64 / iters as f64,
                iters
            );
            return;
        }
        iters *= 4;
    }
}

fn check() {
    let cipher = AsconAead128::new_from_slice(&[0x42; 16]).unwrap();
    let nonce = Nonce::<AsconAead128>::from([0x24; 16]);
    for &len in &LENS {
        let x = fresh(len);
        // #0 CBC-XOR
        let mut e = x.clone();
        let mut l = IV;
        for c in e.iter_mut() {
            *c ^= KEY.rotate_left(l as u32) as u8;
            l = *c;
        }
        let mut d = e.clone();
        l = IV;
        for c in d.iter_mut() {
            let n = *c;
            *c ^= KEY.rotate_left(l as u32) as u8;
            l = n;
        }
        assert_eq!(d, x, "#0 len {len}");
        // #1 add
        let mut e = x.clone();
        for (i, c) in e.iter_mut().enumerate() {
            *c = c.wrapping_add((KEY ^ IV as u64).rotate_right(i as u32) as u8);
        }
        let mut d = e.clone();
        for (i, c) in d.iter_mut().enumerate() {
            *c = c.wrapping_sub((KEY ^ IV as u64).rotate_right(i as u32) as u8);
        }
        assert_eq!(d, x, "#1 len {len}");
        // #2 mul
        let mut e = x.clone();
        for (i, c) in e.iter_mut().enumerate() {
            *c = c.wrapping_mul(inv_mul8((KEY.rotate_right(i as u32) as u8) | 1));
        }
        let mut d = e.clone();
        for (i, c) in d.iter_mut().enumerate() {
            *c = c.wrapping_mul((KEY.rotate_right(i as u32) as u8) | 1);
        }
        assert_eq!(d, x, "#2 len {len}");
        // #3 rot+xor
        let mut e = x.clone();
        for (i, c) in e.iter_mut().enumerate() {
            let rot = (KEY.rotate_right(i as u32) % 8) as u32;
            *c = c.rotate_left(rot) ^ (KEY >> ((i * 8) % 64)) as u8;
        }
        let mut d = e.clone();
        for (i, c) in d.iter_mut().enumerate() {
            let rot = (KEY.rotate_right(i as u32) % 8) as u32;
            *c ^= (KEY >> ((i * 8) % 64)) as u8;
            *c = c.rotate_right(rot);
        }
        assert_eq!(d, x, "#3 len {len}");
        // #4/#5/#6 lib 原语对
        let mut e = x.clone();
        mse_no_ps(&mut e, KEY, IV);
        let mut d = e.clone();
        imse_no_ps(&mut d, KEY, IV);
        assert_eq!(d, x, "#4 len {len}");
        let mut e = x.clone();
        mse_no_s(&mut e, KEY, IV);
        let mut d = e.clone();
        imse_no_s(&mut d, KEY, IV);
        assert_eq!(d, x, "#5 len {len}");
        let mut e = x.clone();
        mse(&mut e, KEY, IV);
        let mut d = e.clone();
        imse(&mut d, KEY, IV);
        assert_eq!(d, x, "#6 len {len}");
        // #7 静态表
        let mut e = x.clone();
        for c in e.iter_mut() {
            *c = s8(*c, &SBOX_BASE[0]);
        }
        let mut d = e.clone();
        for c in d.iter_mut() {
            *c = s8(*c, &SBOX_BASE[1]);
        }
        assert_eq!(d, x, "#7 len {len}");
        // #8 动态 P
        let p = gen_p(KEY);
        let mut e = x.clone();
        for c in e.iter_mut() {
            *c = p8(*c, &p);
        }
        let p_inv = inv_p(&p).unwrap();
        let mut d = e.clone();
        for c in d.iter_mut() {
            *c = p8(*c, &p_inv);
        }
        assert_eq!(d, x, "#8 len {len}");
        // #9 动态 S
        let s = gen_s(KEY);
        let mut e = x.clone();
        for c in e.iter_mut() {
            *c = s8(*c, &s);
        }
        let s_inv = inv_s(&s).unwrap();
        let mut d = e.clone();
        for c in d.iter_mut() {
            *c = s8(*c, &s_inv);
        }
        assert_eq!(d, x, "#9 len {len}");
        // #10 3×r8
        let mut e = x.clone();
        for (i, c) in e.iter_mut().enumerate() {
            let mut val = *c;
            let mut rk = mix64(KEY ^ (IV as u64) ^ (i as u64).rotate_left(7));
            for round in 0..3usize {
                val = r8(val, IV, round, rk as u128, None, None);
                rk = mix64_next(rk);
            }
            *c = val;
        }
        let mut d = e.clone();
        for (i, c) in d.iter_mut().enumerate() {
            let mut val = *c;
            let k0 = mix64(KEY ^ (IV as u64) ^ (i as u64).rotate_left(7));
            let k1 = mix64_next(k0);
            let k2 = mix64_next(k1);
            val = ir8(val, IV, 2, k2 as u128, None, None);
            val = ir8(val, IV, 1, k1 as u128, None, None);
            val = ir8(val, IV, 0, k0 as u128, None, None);
            *c = val;
        }
        assert_eq!(d, x, "#10 len {len}");
        // #11 多轮 P
        let rounds = ((KEY >> 8) % 3) as usize + 3;
        let mut e = x.clone();
        for round in 0..rounds {
            let mut prev = IV ^ (round as u8);
            let seed = mix64(KEY.rotate_right((round * 11) as u32));
            let mut p = gen_p(seed);
            let rk = (KEY as u128) ^ ((round as u128) << 64);
            for (i, c) in e.iter_mut().enumerate() {
                let ct = r8(*c, prev, i, rk, Some(&mut p), None);
                prev = ct;
                *c = ct;
            }
        }
        let mut d = e.clone();
        for round in (0..rounds).rev() {
            let mut prev = IV ^ (round as u8);
            let seed = mix64(KEY.rotate_right((round * 11) as u32));
            let p_box = gen_p(seed);
            let mut p_inv = inv_p(&p_box).unwrap();
            let rk = (KEY as u128) ^ ((round as u128) << 64);
            for (i, c) in d.iter_mut().enumerate() {
                let pt = ir8(*c, prev, i, rk, Some(&mut p_inv), None);
                prev = *c;
                *c = pt;
            }
        }
        assert_eq!(d, x, "#11 len {len}");
        // #12 3 轮 P+S
        let mut e = x.clone();
        for round in 0..3u64 {
            let mut prev = IV.rotate_left(round as u32);
            let seed = mix64_next(KEY.wrapping_add(round));
            let mut p = gen_p(seed);
            let mut s = gen_s(mix64(seed));
            let rk = (KEY as u128) ^ ((round as u128) << 80);
            for (i, c) in e.iter_mut().enumerate() {
                let ct = r8(*c, prev, i, rk, Some(&mut p), Some(&mut s));
                prev = ct;
                *c = ct;
            }
        }
        let mut d = e.clone();
        for round in (0..3u64).rev() {
            let mut prev = IV.rotate_left(round as u32);
            let seed = mix64_next(KEY.wrapping_add(round));
            let p_box = gen_p(seed);
            let s_box = gen_s(mix64(seed));
            let mut p_inv = inv_p(&p_box).unwrap();
            let mut s_inv = inv_s(&s_box).unwrap();
            let rk = (KEY as u128) ^ ((round as u128) << 80);
            for (i, c) in d.iter_mut().enumerate() {
                let pt = ir8(*c, prev, i, rk, Some(&mut p_inv), Some(&mut s_inv));
                prev = *c;
                *c = pt;
            }
        }
        assert_eq!(d, x, "#12 len {len}");
        // ascon 对拍
        let ct = cipher.encrypt(&nonce, &x[..]).unwrap();
        let pt = cipher.decrypt(&nonce, &ct[..]).unwrap();
        assert_eq!(pt, x, "ascon len {len}");
    }
}

fn main() {
    check();
    let cipher = AsconAead128::new_from_slice(&[0x42; 16]).unwrap();
    let nonce = Nonce::<AsconAead128>::from([0x24; 16]);
    for &len in &LENS {
        bench("memcpy", len, || {
            let v = black_box(fresh(len));
            finish(v);
        });
        bench("xor", len, || {
            let mut v = black_box(fresh(len));
            for c in v.iter_mut() {
                *c ^= 0xA5;
            }
            finish(v);
        });
        bench("ascon", len, || {
            let pt = black_box(fresh(len));
            let ct = cipher.encrypt(&nonce, &pt[..]).unwrap();
            black_box(ct.len());
        });
        bench("cbc", len, || {
            let mut v = black_box(fresh(len));
            let mut l = IV;
            for c in v.iter_mut() {
                let n = *c;
                *c ^= KEY.rotate_left(l as u32) as u8;
                l = n;
            }
            finish(v);
        });
        bench("add", len, || {
            let mut v = black_box(fresh(len));
            for (i, c) in v.iter_mut().enumerate() {
                *c = c.wrapping_sub((KEY ^ IV as u64).rotate_right(i as u32) as u8);
            }
            finish(v);
        });
        bench("mul", len, || {
            let mut v = black_box(fresh(len));
            for (i, c) in v.iter_mut().enumerate() {
                *c = c.wrapping_mul((KEY.rotate_right(i as u32) as u8) | 1);
            }
            finish(v);
        });
        bench("rotxor", len, || {
            let mut v = black_box(fresh(len));
            for (i, c) in v.iter_mut().enumerate() {
                let rot = (KEY.rotate_right(i as u32) % 8) as u32;
                *c ^= (KEY >> ((i * 8) % 64)) as u8;
                *c = c.rotate_right(rot);
            }
            finish(v);
        });
        bench("mse_no_ps", len, || {
            let mut v = black_box(fresh(len));
            imse_no_ps(&mut v, KEY, IV);
            finish(v);
        });
        bench("mse_no_s", len, || {
            let mut v = black_box(fresh(len));
            imse_no_s(&mut v, KEY, IV);
            finish(v);
        });
        bench("mse", len, || {
            let mut v = black_box(fresh(len));
            imse(&mut v, KEY, IV);
            finish(v);
        });
        bench("sbox_static", len, || {
            let mut v = black_box(fresh(len));
            for c in v.iter_mut() {
                *c = s8(*c, &SBOX_BASE[1]);
            }
            finish(v);
        });
        bench("p_dyn", len, || {
            let mut v = black_box(fresh(len));
            let p = gen_p(KEY);
            let p_inv = inv_p(&p).unwrap();
            for c in v.iter_mut() {
                *c = p8(*c, &p_inv);
            }
            finish(v);
        });
        bench("s_dyn", len, || {
            let mut v = black_box(fresh(len));
            let s = gen_s(KEY);
            let s_inv = inv_s(&s).unwrap();
            for c in v.iter_mut() {
                *c = s8(*c, &s_inv);
            }
            finish(v);
        });
        bench("r8x3", len, || {
            let mut v = black_box(fresh(len));
            for (i, c) in v.iter_mut().enumerate() {
                let mut val = *c;
                let k0 = mix64(KEY ^ (IV as u64) ^ (i as u64).rotate_left(7));
                let k1 = mix64_next(k0);
                let k2 = mix64_next(k1);
                val = ir8(val, IV, 2, k2 as u128, None, None);
                val = ir8(val, IV, 1, k1 as u128, None, None);
                val = ir8(val, IV, 0, k0 as u128, None, None);
                *c = val;
            }
            finish(v);
        });
        bench("p_multi", len, || {
            let mut v = black_box(fresh(len));
            let rounds = ((KEY >> 8) % 3) as usize + 3;
            for round in (0..rounds).rev() {
                let mut prev = IV ^ (round as u8);
                let seed = mix64(KEY.rotate_right((round * 11) as u32));
                let p_box = gen_p(seed);
                let mut p_inv = inv_p(&p_box).unwrap();
                let rk = (KEY as u128) ^ ((round as u128) << 64);
                for (i, c) in v.iter_mut().enumerate() {
                    let pt = ir8(*c, prev, i, rk, Some(&mut p_inv), None);
                    prev = *c;
                    *c = pt;
                }
            }
            finish(v);
        });
        bench("ps_multi", len, || {
            let mut v = black_box(fresh(len));
            for round in (0..3u64).rev() {
                let mut prev = IV.rotate_left(round as u32);
                let seed = mix64_next(KEY.wrapping_add(round));
                let p_box = gen_p(seed);
                let s_box = gen_s(mix64(seed));
                let mut p_inv = inv_p(&p_box).unwrap();
                let mut s_inv = inv_s(&s_box).unwrap();
                let rk = (KEY as u128) ^ ((round as u128) << 80);
                for (i, c) in v.iter_mut().enumerate() {
                    let pt = ir8(*c, prev, i, rk, Some(&mut p_inv), Some(&mut s_inv));
                    prev = *c;
                    *c = pt;
                }
            }
            finish(v);
        });
        bench("trunc", len, || {
            let src = black_box(fresh(len + 16));
            let mut v = Vec::with_capacity(len);
            v.extend_from_slice(&src[..len]);
            finish(v);
        });
    }
}
"##;

/// 解析 guest stdout（`ROW\tLEN\tNS\tITERS`），非数据行直接忽略。
fn parse(stdout: &str) -> Vec<(String, usize, f64)> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split('\t');
        let (Some(name), Some(len), Some(ns), Some(_)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Ok(len) = len.parse::<usize>() else {
            continue;
        };
        let Ok(ns) = ns.parse::<f64>() else {
            continue;
        };
        out.push((name.to_string(), len, ns));
    }
    out
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

/// 最小二乘拟合 `ns = fixed + k·len`，返回 `(fixed, k, r2)`。
fn fit(pts: &[(f64, f64)]) -> (f64, f64, f64) {
    let n = pts.len() as f64;
    let (sx, sy) = pts
        .iter()
        .fold((0.0, 0.0), |(ax, ay), &(x, y)| (ax + x, ay + y));
    let (mx, my) = (sx / n, sy / n);
    let (mut cov, mut var, mut tot) = (0.0, 0.0, 0.0);
    for &(x, y) in pts {
        cov += (x - mx) * (y - my);
        var += (x - mx) * (x - mx);
        tot += (y - my) * (y - my);
    }
    if var == 0.0 || tot == 0.0 {
        return (my, 0.0, 1.0);
    }
    let k = cov / var;
    (my - k * mx, k, cov * cov / (var * tot))
}

#[test]
#[ignore]
fn perf_crypto_report() {
    let mut samples: Vec<Vec<(String, usize, f64)>> = Vec::with_capacity(REPEATS);
    for _ in 0..REPEATS {
        let mut runner = DnyRun::new(GUEST, &guest_deps());
        runner.release(true);
        let ret = runner.run(timeout());
        assert!(ret.ok, "构建或运行失败:\n{ret}");
        let parsed = parse(&ret.stdout);
        assert_eq!(
            parsed.len(),
            ROWS.len() * LENGTHS.len(),
            "数据行数不对，实际 stdout:\n{}",
            ret.stdout
        );
        samples.push(parsed);
    }

    // 每 (row,len) 取中位数后拟合。
    let mut fitted: Vec<(String, f64, f64, f64)> = Vec::with_capacity(ROWS.len());
    for row in ROWS {
        let mut pts = Vec::with_capacity(LENGTHS.len());
        for len in LENGTHS {
            let mut vals = Vec::with_capacity(REPEATS);
            for s in &samples {
                vals.extend(
                    s.iter()
                        .filter(|(r, l, _)| r == row && *l == len)
                        .map(|(_, _, ns)| *ns),
                );
            }
            assert_eq!(vals.len(), REPEATS, "[{row} × {len}] 样本缺失");
            pts.push((len as f64, median(vals)));
        }
        let (fixed, k, r2) = fit(&pts);
        fitted.push((row.to_string(), fixed, k, r2));
    }

    let k_ascon = fitted
        .iter()
        .find(|(r, _, _, _)| r == "ascon")
        .map(|(_, _, k, _)| *k)
        .unwrap_or(0.0);
    assert!(k_ascon > 0.0, "ascon 斜率异常，无法换算");

    eprintln!("\n| 原语行 | fixed(ns) | k(ns/B) | R² | k/k_ascon | 建议L(=80·比值) |");
    eprintln!("| :--- | :--- | :--- | :--- | :--- | :--- |");
    for (row, fixed, k, r2) in &fitted {
        let ratio = k / k_ascon;
        let flag = if *r2 < 0.9 { " ⚠️" } else { "" };
        eprintln!(
            "| {row:<12} | {fixed:.1} | {k:.2} | {r2:.3}{flag} | {ratio:.3} | {:.1} |",
            80.0 * ratio
        );
    }
    // median 原始矩阵 + total@16 换算（短串真实 dec 代价口径；拟合截距有 ±100ns 级噪音，
    // 如 mse_no_ps 截距为负，total 取实测中位数而非拟合值，避免荒谬外推）。
    eprintln!(
        "\n| 原语行 | 8B | 16B | 32B | 64B | 256B | total16/total16_ascon | L16(=80·比值,封顶100) |"
    );
    eprintln!("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |");
    let med = |row: &str, len: usize| -> f64 {
        let mut vals = Vec::with_capacity(REPEATS);
        for s in &samples {
            vals.extend(
                s.iter()
                    .filter(|(r, l, _)| r == row && *l == len)
                    .map(|(_, _, ns)| *ns),
            );
        }
        median(vals)
    };
    let t16_ascon = med("ascon", 16);
    for row in ROWS {
        let t16 = med(row, 16);
        let ratio = t16 / t16_ascon;
        eprintln!(
            "| {row:<12} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {ratio:.3} | {:.1} |",
            med(row, 8),
            t16,
            med(row, 32),
            med(row, 64),
            med(row, 256),
            (80.0 * ratio).min(100.0)
        );
    }
    eprintln!(
        "\n口径：dec 等价体（含建表）+ 统一样本壳（`fresh` 分配填充 + 求和钉死），\
每次调用输入重建并 black_box；`trunc` 一行同时覆盖 #13/#14；\
fixed 为短串场景参考，k 用于 L 换算；R²<0.9 标 ⚠️（单值 L 失真）；\
S 不在本文件度量范围内；数字只展示不断言（多态 + 机器抖动）。"
    );
}
