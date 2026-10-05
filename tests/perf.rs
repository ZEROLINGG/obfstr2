//! 性能对比测试（报告-only）：明文基线 vs CasualX vs `b1/b2/b3` 的四维数据。
//!
//! - 编译耗时 / 运行耗时：`dyntest` 原生能力（`DnyResult::build_duration` / `run_duration`）；
//! - 展开大小：`DnyRun::cargo(&["expand"])` 输出字符数（需执行机安装 `cargo-expand`，缺失记 `n/a`）；
//! - 产物体积：`DnyRun::bin_path()` + `fs::metadata` 的未 strip 二进制大小；
//! - 只断言构建成功与解密校验和正确，**不对任何数字断言**（冷构建 + 多态 + 机器抖动，必 flaky）；
//! - 结果以 `eprintln!` 打印 Markdown 表，需 `--nocapture` 查看，方便贴进 README；
//! - 默认忽略，手动跑：`cargo test --test perf -- --ignored --nocapture`
//!   （6 个 release 冷构建，`b3` 最重，本机约数分钟；另需联网拉取 `obfstr`）；
//! - 每个用例独立 `DnyRun`（目录唯一），无共享状态、无 `clear_dny_project`（并行 hang 教训见 `nostd.rs` 头注）；
//! - 本文件内单测串行执行，避免多个 `cargo build` 并发抢锁。
//!
//! 口径：128B 全 `a` 载荷（与 `nostd.rs` 收敛值对齐），release profile，guest 内循环 200 次解密求校验和
//! （`run_duration` 含进程启动开销，单次解密会被启动噪声淹没，必须循环放大）；同机横向参考，跨机器不可比。

use lib_unknown::dyntest::DnyRun;
use std::time::Duration;

/// 128 个 `a`：`128 * b'a' * 200 == 2483200`，各 guest 的期望校验和。
const PAYLOAD_LEN: usize = 128;
const LOOPS: u32 = 200;
const EXPECTED_SUM: u64 = PAYLOAD_LEN as u64 * b'a' as u64 * LOOPS as u64;

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
        "for &b in obfstr::obfbytes!(b\"{p}\").iter() {{ sum = sum.wrapping_add(b as u64); }}"
    ));
    let obf = |m: &str| {
        guest(&format!(
            "let v = obfstr2::{m}!(b\"{p}\");\n        for &b in (&*v).iter() {{ sum = sum.wrapping_add(b as u64); }}"
        ))
    };

    let rows = [
        case("明文基线", &base_code, ""),
        case("CasualX obfbytes!", &casual_bytes, &casual_dep()),
        case("obfstr2 b1!", &obf("b1"), &obfstr2_dep()),
        case("obfstr2 b2!", &obf("b2"), &obfstr2_dep()),
        case("obfstr2 b3!", &obf("b3"), &obfstr2_dep()),
    ];

    eprintln!(
        "\n| 用例 | 编译耗时 | 运行耗时（200 次解密循环，含启动开销） | expand 字符数 | 产物二进制（未 strip） |"
    );
    eprintln!("| :--- | :--- | :--- | :--- | :--- |");
    for r in &rows {
        let expand = r.expand_chars.map_or("n/a".to_string(), |n| n.to_string());
        let bin = r.bin_bytes.map_or("n/a".to_string(), |n| n.to_string());
        eprintln!(
            "| {:<18} | {:?} | {:?} | {expand} | {bin} |",
            r.name, r.build, r.run
        );
    }
    eprintln!(
        "\n口径：128B 全 a 载荷，release profile，冷构建（含临时工程依赖编译），同机横向参考；数字只展示不断言（多态 + 机器抖动）。"
    );
}
