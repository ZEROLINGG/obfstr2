//! 性能对比测试（报告-only）：冷/热构建耗时 + 运行耗时 + 产物体积 + expand 字符数。

use lib_unknown::dyntest::DnyRun;
use std::time::Duration;

const PAYLOAD_LEN: usize = 1024;
const LOOPS: u32 = 100;
const REPEATS: usize = 3;
const TIMEOUT_SECS: u64 = 300;

const EXPECTED_SUM: u64 = PAYLOAD_LEN as u64 * b'a' as u64 * LOOPS as u64;

fn timeout() -> Option<Duration> {
    Some(Duration::from_secs(TIMEOUT_SECS))
}

fn payload() -> String {
    "a".repeat(PAYLOAD_LEN)
}

fn obfstr2_dep() -> String {
    format!("obfstr2 = {{ path = {:?} }}", env!("CARGO_MANIFEST_DIR"))
}

fn casual_dep() -> String {
    "obfstr = \"0.4\"".to_string()
}

fn guest(body: &str) -> String {
    format!(
        r#"fn main() {{
    let mut sum: u64 = 0;
    for _ in 0..std::hint::black_box({LOOPS}){{
        {body}
    }}
    println!("{{sum}}");
}}"#
    )
}

/// 五个用例的 (名称, 代码, 依赖) 定义，冷/热两阶段共用，避免漂移。
fn case_defs(p: &str) -> [(&'static str, String, String); 5] {
    let base_code = format!(
        "static SECRET: &[u8; {PAYLOAD_LEN}] = b\"{p}\";\n{}",
        guest(
            "for &b in SECRET.iter() { sum = sum.wrapping_add(b as u64); }\n        std::hint::black_box(sum);"
        )
    );

    // 注意：CasualX 与 obfstr2 都对返回值整体 black_box，避免测试口径不对称。
    let casual_bytes = guest(&format!(
        "for &b in std::hint::black_box(obfstr::obfbytes!(b\"{p}\")).iter() {{ sum = sum.wrapping_add(b as u64); }}\n        std::hint::black_box(sum);"
    ));

    let obf = |m: &str| {
        guest(&format!(
            "let v = std::hint::black_box(obfstr2::{m}!(b\"{p}\"));\n        for &b in (&*v).iter() {{ sum = sum.wrapping_add(b as u64); }}"
        ))
    };

    [
        ("明文基线", base_code, String::new()),
        ("CasualX obfbytes!", casual_bytes, casual_dep()),
        ("obfstr2 b1!", obf("b1"), obfstr2_dep()),
        ("obfstr2 b2!", obf("b2"), obfstr2_dep()),
        ("obfstr2 b3!", obf("b3"), obfstr2_dep()),
    ]
}

/// 冷构建阶段单次采样：build/run/bin/expand 全量测量。
struct Sample {
    build: Duration,
    run: Duration,
    expand_chars: Option<usize>,
    bin_bytes: Option<u64>,
}

fn measure_full(runner: &mut DnyRun, name: &str) -> Sample {
    let ret = runner.run(timeout());
    assert!(ret.ok, "[{name}] 构建或运行失败:\n{ret}");
    let got: u64 = ret
        .stdout
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("[{name}] 校验和不是数字，实际 stdout:\n{}", ret.stdout));
    assert_eq!(got, EXPECTED_SUM, "[{name}] 解密校验和错误");

    let bin_bytes = std::fs::metadata(runner.bin_path()).map(|m| m.len()).ok();
    let expand_res = runner.cargo(&["expand"], timeout());
    let expand_chars = expand_res.ok.then_some(expand_res.stdout.len());

    Sample {
        build: ret.build_duration,
        run: ret.run_duration,
        expand_chars,
        bin_bytes,
    }
}

fn median_duration(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn median_opt<T: Ord + Copy>(mut v: Vec<T>) -> Option<T> {
    v.sort();
    v.get(v.len() / 2).copied()
}

/// 冷构建：每次都新建临时工程（含三方依赖从零编译）。
fn cold_sample(name: &str, code: &str, deps: &str, n: usize) -> Sample {
    let mut builds = Vec::with_capacity(n);
    let mut runs = Vec::with_capacity(n);
    let mut expands = Vec::with_capacity(n);
    let mut bins = Vec::with_capacity(n);

    for _ in 0..n {
        let mut runner = DnyRun::new(code, deps);
        runner.release(true);
        let s = measure_full(&mut runner, name);
        builds.push(s.build);
        runs.push(s.run);
        expands.extend(s.expand_chars);
        bins.extend(s.bin_bytes);
    }

    Sample {
        build: median_duration(builds),
        run: median_duration(runs),
        expand_chars: median_opt(expands),
        bin_bytes: median_opt(bins),
    }
}

/// 热构建：共享已预热 runner，只重写 main.rs 并 build，不 run/不 expand（省时间，且产物与冷构建等价）。
fn hot_incremental_build(runner: &mut DnyRun, name: &str, code: &str, n: usize) -> Duration {
    let mut builds = Vec::with_capacity(n);
    for _ in 0..n {
        runner.reset_main_code(code);
        let ret = runner.build(timeout());
        assert!(ret.ok, "[{name}] 增量构建失败:\n{ret}");
        builds.push(ret.build_duration);
    }
    median_duration(builds)
}

struct Row {
    name: String,
    incr_build: Duration,
    cold_build: Duration,
    run: Duration,
    expand_chars: Option<usize>,
    bin_bytes: Option<u64>,
}

fn per_decrypt(row_run: Duration, base_run: Duration) -> f64 {
    (row_run.as_secs_f64() - base_run.as_secs_f64()) / LOOPS as f64 * 1e6
}

fn pct(v: f64, base: f64) -> Option<String> {
    if base == 0.0 {
        return None;
    }
    Some(format!("{:.0}%", v / base * 100.0 - 100.0))
}

fn cell(abs: String, ratio: Option<String>) -> String {
    match ratio {
        Some(p) => format!("{abs}（{p}）"),
        None => abs,
    }
}

fn render_report(rows: &[Row]) {
    eprintln!(
        "\n| 用例 | 每次去混淆耗时 | 运行耗时（{LOOPS} 次解密循环，含启动开销） | 增量构建耗时 | 冷构建耗时 | 产物二进制（未 strip） | expand 字符数 |"
    );
    eprintln!("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |");

    let base = &rows[0];
    for (i, r) in rows.iter().enumerate() {
        let is_base = i == 0;
        let p = |v: f64, b: f64| if is_base { None } else { pct(v, b) };
        let po = |v: Option<u64>, b: Option<u64>| {
            if is_base {
                None
            } else {
                match (v, b) {
                    (Some(v), Some(b)) => pct(v as f64, b as f64),
                    _ => None,
                }
            }
        };

        let run_pct = p(r.run.as_secs_f64(), base.run.as_secs_f64());
        let incr_pct = p(r.incr_build.as_secs_f64(), base.incr_build.as_secs_f64());
        let cold_pct = p(r.cold_build.as_secs_f64(), base.cold_build.as_secs_f64());
        let bin_pct = po(r.bin_bytes, base.bin_bytes);
        let expand_pct = po(
            r.expand_chars.map(|v| v as u64),
            base.expand_chars.map(|v| v as u64),
        );

        let bin = r.bin_bytes.map_or("n/a".to_string(), |n| n.to_string());
        let expand = r.expand_chars.map_or("n/a".to_string(), |n| n.to_string());

        eprintln!(
            "| {:<18} | {} | {} | {} | {} | {} | {} |",
            r.name,
            if is_base {
                "—".to_string()
            } else {
                format!("{:.2}µs", per_decrypt(r.run, base.run))
            },
            cell(format!("{:?}", r.run), run_pct),
            cell(format!("{:?}", r.incr_build), incr_pct),
            cell(format!("{:?}", r.cold_build), cold_pct),
            cell(bin, bin_pct),
            cell(expand, expand_pct),
        );
    }

    eprintln!(
        "\n口径：{PAYLOAD_LEN}B 全 a 载荷，release profile；冷构建=独立临时工程从零编译（含三方依赖），\
每用例跑 {REPEATS} 次取中位数；增量构建=预热合并依赖（`obfstr` + `obfstr2`）后仅复写 `main.rs` \
触发的增量编译耗时，同样取 {REPEATS} 次中位数；运行耗时/产物体积/expand 字符数取自冷构建阶段样本\
（与构建路径无关，热构建阶段不重复测量以节省时间）；运行耗时为 {LOOPS} 次解密循环（含启动开销与 \
Drop 擦除），循环体内均有 black_box 防外提；每次去混淆耗时 =（行运行耗时 − 基线运行耗时）/ {LOOPS}，\
基线行记 —，负值属噪声原样显示；括号内为相对明文基线的增幅百分比；数字只展示不断言（多态 + 机器抖动）。"
    );
}

#[test]
#[ignore]
fn perf_report_release() {
    let p = payload();
    let cases = case_defs(&p);

    // 阶段一：冷构建（独立工程，含三方依赖从零编译）+ 运行 + 体积 + expand
    let cold: Vec<Sample> = cases
        .iter()
        .map(|(name, code, deps)| cold_sample(name, code, deps, REPEATS))
        .collect();

    // 阶段二：热构建（共享 runner 预热依赖后，仅测增量 build 耗时）
    let combined_deps = format!("{}\n{}", casual_dep(), obfstr2_dep());
    let mut runner = DnyRun::new("fn main() {}", &combined_deps);
    runner.release(true);
    let warm = runner.build(timeout());
    assert!(warm.ok, "热构建依赖预热失败:\n{warm}");

    let incr: Vec<Duration> = cases
        .iter()
        .map(|(name, code, _)| hot_incremental_build(&mut runner, name, code, REPEATS))
        .collect();

    // 合并两阶段结果为最终行
    let rows: Vec<Row> = cases
        .iter()
        .zip(cold)
        .zip(incr)
        .map(|(((name, _, _), c), i)| Row {
            name: name.to_string(),
            incr_build: i,
            cold_build: c.build,
            run: c.run,
            expand_chars: c.expand_chars,
            bin_bytes: c.bin_bytes,
        })
        .collect();

    render_report(&rows);
}
