//! 性能对比测试（报告-only）：明文基线 vs CasualX vs `b1/b2/b3` 的四维数据。
//!
//! - 编译耗时 / 运行耗时：`dyntest` 原生能力（`DnyResult::build_duration` / `run_duration`）；
//! - 每次去混淆耗时：（行耗时 − 基线耗时）/ 2000，基线行记 `—`，负值属噪声原样显示；
//! - 展开大小：`DnyRun::cargo(&["expand"])` 输出字符数（需执行机安装 `cargo-expand`，缺失记 `n/a`）；
//! - 产物体积：`DnyRun::bin_path()` + `fs::metadata` 的未 strip 二进制大小；
//! - 只断言构建成功与解密校验和正确，**不对任何数字断言**（冷构建 + 多态 + 机器抖动，必 flaky）；
//! - 结果以 `eprintln!` 打印 Markdown 表，需 `--nocapture` 查看，方便贴进 README；
//! - 默认忽略，手动跑：`cargo test --test perf -- --ignored --nocapture`
//!   （6 个 release 冷构建，`b3` 最重，本机约数分钟；另需联网拉取 `obfstr`）；
//! - 每个用例独立 `DnyRun`（目录唯一），无共享状态、无 `clear_dny_project`（并行 hang 教训见 `nostd.rs` 头注）；
//! - 本文件内单测串行执行，避免多个 `cargo build` 并发抢锁。
//!
//! 口径：128B 全 `a` 载荷（与 `nostd.rs` 收敛值对齐），release profile，guest 内循环 2000 次解密求校验和
//! （`run_duration` 含进程启动开销，单次解密会被启动噪声淹没，必须循环放大；循环体内均有 `black_box`，
//! 防编译器把循环不变的解密外提——`CasualX` 行曾缺此屏障，已补齐拉平）；每用例跑 3 次取中位数，压机器抖动与
//! 计时轮询粒度误差；同机横向参考，跨机器不可比。

use lib_unknown::dyntest::DnyRun;
use std::time::Duration;

/// 128 个 `a`：`128 * b'a' * 2000 == 24832000`，各 guest 的期望校验和。
const PAYLOAD_LEN: usize = 128;
const LOOPS: u32 = 2000;
const EXPECTED_SUM: u64 = PAYLOAD_LEN as u64 * b'a' as u64 * LOOPS as u64;
/// 每用例重复次数（取中位数）。
const REPEATS: usize = 3;

fn payload() -> String {
    "a".repeat(PAYLOAD_LEN)
}

fn obfstr2_dep() -> String {
    format!("obfstr2 = {{ path = {:?} }}", env!("CARGO_MANIFEST_DIR"))
}

fn casual_dep() -> String {
    "obfstr = \"0.4\"".to_string()
}

/// guest 模板：循环解密求校验和并打印。`{body}` 为单次解密求和片段（内联使用，满足 CasualX E0716 限制）。
fn guest(body: &str) -> String {
    format!(
        r#"fn main() {{
    let mut sum: u64 = 0;
    for _ in 0..{LOOPS} {{
        {body}
    }}
    println!("{{sum}}");
}}"#
    )
}

struct Row {
    name: String,
    build: Duration,
    run: Duration,
    expand_chars: Option<usize>,
    bin_bytes: Option<u64>,
}

fn case(name: &str, code: &str, deps: &str) -> Row {
    let mut runner = DnyRun::new(code, deps);
    runner.release(true);
    let timeout = Some(Duration::from_secs(300));

    let ret = runner.run(timeout);
    assert!(ret.ok, "[{name}] 构建或运行失败:\n{ret}");
    let got: u64 = ret
        .stdout
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("[{name}] 校验和不是数字，实际 stdout:\n{}", ret.stdout));
    assert_eq!(got, EXPECTED_SUM, "[{name}] 解密校验和错误");

    let bin_bytes = std::fs::metadata(runner.bin_path()).map(|m| m.len()).ok();
    let expand_res = runner.cargo(&["expand"], timeout);
    let expand_chars = expand_res.ok.then_some(expand_res.stdout.len());

    Row {
        name: name.to_string(),
        build: ret.build_duration,
        run: ret.run_duration,
        expand_chars,
        bin_bytes,
    }
}

/// 单用例跑 `n` 次取中位数：`build`/`run` 直接排序取中；`expand_chars`/`bin_bytes`
/// （多态导致每次展开不同，同样取中）取 `Some` 值的中位数，全缺才记 `n/a`。
fn median_case(name: &str, code: &str, deps: &str, n: usize) -> Row {
    let mut builds = Vec::with_capacity(n);
    let mut runs = Vec::with_capacity(n);
    let mut expands = Vec::with_capacity(n);
    let mut bins = Vec::with_capacity(n);
    for _ in 0..n {
        let r = case(name, code, deps);
        builds.push(r.build);
        runs.push(r.run);
        expands.extend(r.expand_chars);
        bins.extend(r.bin_bytes);
    }
    builds.sort();
    runs.sort();
    expands.sort();
    bins.sort();
    Row {
        name: name.to_string(),
        build: builds[n / 2],
        run: runs[n / 2],
        expand_chars: expands.get(expands.len() / 2).copied(),
        bin_bytes: bins.get(bins.len() / 2).copied(),
    }
}
/// 每次去混淆耗时（µs）：（行耗时 − 基线耗时）/ `LOOPS`。假设各行进程启动开销相同、
/// 差分后相消；结果含噪声，小于零属正常，原样显示；基线行由调用方记 `—`。
fn per_decrypt(row_run: Duration, base_run: Duration) -> f64 {
    (row_run.as_secs_f64() - base_run.as_secs_f64()) / LOOPS as f64 * 1e6
}

/// 相对明文基线的增幅百分比（`v` 为某行某列数值，`base` 为基线同列数值，
/// 即 `v/base - 1`；与基线持平显示 `0%`）：
/// 基线为零、任一侧缺失（`n/a`）时无法计算，返回 `None`，调用方回落为纯数字。
fn pct(v: f64, base: f64) -> Option<String> {
    if base == 0.0 {
        return None;
    }
    Some(format!("{:.0}%", v / base * 100.0 - 100.0))
}

/// 单元格渲染：`绝对值（百分比）`；算不出百分比时只写绝对值。
fn cell(abs: String, ratio: Option<String>) -> String {
    match ratio {
        Some(p) => format!("{abs}（{p}）"),
        None => abs,
    }
}

#[cfg(test)]
mod pct_tests {
    use super::*;

    #[test]
    fn typical_ratios() {
        assert_eq!(pct(2.2, 0.1), Some("2100%".to_string()));
        assert_eq!(pct(11.0, 11.0), Some("0%".to_string()));
        assert_eq!(cell("2.2s".to_string(), pct(2.2, 0.1)), "2.2s（2100%）");
    }

    #[test]
    fn zero_base_or_missing_falls_back() {
        assert_eq!(pct(1.0, 0.0), None);
        assert_eq!(cell("n/a".to_string(), None), "n/a");
    }

    #[test]
    fn per_decrypt_values() {
        let v = per_decrypt(Duration::from_micros(81010), Duration::from_micros(10330));
        assert!((v - 35.34).abs() < 0.01, "实际: {v}");
        let neg = per_decrypt(Duration::from_millis(10), Duration::from_millis(11));
        assert!(neg < 0.0, "实际: {neg}");
        assert_eq!(format!("{neg:.2}µs"), "-0.50µs");
    }
}

#[test]
#[ignore]
fn perf_report() {
    let p = payload();

    // 明文基线：static 直接引用。
    let base_code = guest(
        "for &b in SECRET.iter() { sum = sum.wrapping_add(b as u64); }\n        std::hint::black_box(sum);",
    );
    let base_code = format!("static SECRET: &[u8; 128] = b\"{p}\";\n{base_code}");

    let casual_bytes = guest(&format!(
        "for &b in std::hint::black_box(obfstr::obfbytes!(b\"{p}\")).iter() {{ sum = sum.wrapping_add(b as u64); }}\n        std::hint::black_box(sum);"
    ));
    let obf = |m: &str| {
        guest(&format!(
            "let v = obfstr2::{m}!(b\"{p}\");\n        for &b in (&*v).iter() {{ sum = sum.wrapping_add(b as u64); }}"
        ))
    };

    let rows = [
        median_case("明文基线", &base_code, "", REPEATS),
        median_case("CasualX obfbytes!", &casual_bytes, &casual_dep(), REPEATS),
        median_case("obfstr2 b1!", &obf("b1"), &obfstr2_dep(), REPEATS),
        median_case("obfstr2 b2!", &obf("b2"), &obfstr2_dep(), REPEATS),
        median_case("obfstr2 b3!", &obf("b3"), &obfstr2_dep(), REPEATS),
    ];

    eprintln!(
        "\n| 用例 | 每次去混淆耗时 | 编译耗时 | 运行耗时（2000 次解密循环，含启动开销） | expand 字符数 | 产物二进制（未 strip） |"
    );
    eprintln!("| :--- | :--- | :--- | :--- | :--- | :--- |");
    // rows[0] 为明文基线，其余行的括号内数字为相对基线的百分比；每次去混淆耗时列无百分比。
    let base = &rows[0];
    for (i, r) in rows.iter().enumerate() {
        let is_base = i == 0;
        let pct_unless_base = |v: f64, b: f64| {
            if is_base { None } else { pct(v, b) }
        };
        let build_pct = pct_unless_base(r.build.as_secs_f64(), base.build.as_secs_f64());
        let run_pct = pct_unless_base(r.run.as_secs_f64(), base.run.as_secs_f64());
        let expand_pct = match (r.expand_chars, base.expand_chars) {
            (Some(v), Some(b)) if !is_base => pct(v as f64, b as f64),
            _ => None,
        };
        let bin_pct = match (r.bin_bytes, base.bin_bytes) {
            (Some(v), Some(b)) if !is_base => pct(v as f64, b as f64),
            _ => None,
        };
        let expand = r.expand_chars.map_or("n/a".to_string(), |n| n.to_string());
        let bin = r.bin_bytes.map_or("n/a".to_string(), |n| n.to_string());
        eprintln!(
            "| {:<18} | {} | {} | {} | {} | {} |",
            r.name,
            if is_base {
                "—".to_string()
            } else {
                format!("{:.2}µs", per_decrypt(r.run, base.run))
            },
            cell(format!("{:?}", r.build), build_pct),
            cell(format!("{:?}", r.run), run_pct),
            cell(expand, expand_pct),
            cell(bin, bin_pct),
        );
    }
    eprintln!(
        "\n口径：128B 全 a 载荷，release profile，冷构建（含临时工程依赖编译，行间差值才是宏边际成本），每用例跑 3 次取中位数，同机横向参考；运行耗时为 2000 次解密循环（含启动开销与 Drop 擦除），循环体内均有 black_box 防外提；每次去混淆耗时 =（行耗时 − 基线耗时）/ 2000，基线行记 —，负值属噪声原样显示；括号内为相对明文基线的增幅百分比；数字只展示不断言（多态 + 机器抖动）。"
    );
}
