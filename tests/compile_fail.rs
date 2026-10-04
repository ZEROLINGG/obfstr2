//! 非法输入测试：越界元素 / 缺失文件 / 非字面量 / 未闭合括号均报编译错误。
//!
//! 由原 `obfstr2-macros/src/lib.rs::tests` 迁移而来。每个用例独立
//! `dny_run`（目录唯一），无共享 `RUNNER`、无 `clear_dny_project`。
//! 未引入 `trybuild`：其快照 rudiment 在离线环境不可用，且此处仅需断言
//! `stderr` 关键信息，`dny_run` 足够。
use lib_unknown::dyntest::dny_run;

fn obfstr2_dep() -> String {
    format!("obfstr2 = {{ path = {:?} }}", env!("CARGO_MANIFEST_DIR"))
}

fn assert_compile_fail(code: &str, needle: &str, tag: &str) {
    let ret = dny_run(code, &obfstr2_dep(), None, false);
    assert!(!ret.ok, "[{tag}] 非法输入应当编译失败");
    assert!(
        ret.stderr.contains(needle),
        "[{tag}] 错误信息应包含 {needle:?}，实际 stderr:\n{}",
        ret.stderr
    );
}

#[test]
fn bytes_array_out_of_range_rejected() {
    assert_compile_fail(
        r#"fn main() { let _b = obfstr2::b2!([0x61, 300]); }"#,
        "0..=255",
        "b2-range",
    );
}

#[test]
fn bytes_array_non_literal_rejected() {
    assert_compile_fail(
        r#"fn main() { let x = 1u8; let _b = obfstr2::b2!([x]); }"#,
        "整数字面量",
        "b2-lit",
    );
}

#[test]
fn missing_file_rejected() {
    assert_compile_fail(
        r#"fn main() { let _b = obfstr2::f2!("不存在的文件.bin"); }"#,
        "无法读取文件",
        "f2-missing",
    );
}

#[test]
fn s_fmt_non_literal_rejected() {
    assert_compile_fail(
        r#"fn main() { let f = "x"; print!("{}", obfstr2::s_fmt!(f)) }"#,
        "必须是字符串字面量",
        "s_fmt-lit",
    );
}

#[test]
fn s_fmt_unclosed_brace_rejected() {
    assert_compile_fail(
        r#"fn main() { print!("{}", obfstr2::s_fmt!("a{b")) }"#,
        "未闭合",
        "s_fmt-brace",
    );
}
