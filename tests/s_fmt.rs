//! `s_fmt!` 与标准 `format!` 的等价性测试（进程内断言）。
use obfstr2::s_fmt;

#[test]
fn plain_text() {
    assert_eq!(s_fmt!("hello world"), "hello world");
}

#[test]
fn escaped_braces() {
    assert_eq!(s_fmt!("{{a}} b"), "{a} b");
}

#[test]
fn positional_and_named_args() {
    assert_eq!(
        s_fmt!("{0} {name}", 1, name = "x"),
        format!("{0} {name}", 1, name = "x")
    );
}

#[test]
fn format_spec_width_precision() {
    assert_eq!(
        s_fmt!("{x:>8.2}", x = 1.23456789_f64),
        format!("{x:>8.2}", x = 1.23456789_f64)
    );
}

#[test]
fn debug_pretty_spec_multiline() {
    let v = vec![1, 2, 3];
    assert_eq!(s_fmt!("{v:#?}", v = v.clone()), format!("{v:#?}", v = v));
}

#[test]
fn mixed_text_and_placeholder_unicode() {
    assert_eq!(
        s_fmt!("你好，{name}！今天是{day}号", name = "张三", day = 5),
        format!("你好，{name}！今天是{day}号", name = "张三", day = 5),
    );
}

#[test]
fn trailing_comma_in_args() {
    assert_eq!(s_fmt!("{}", 42,), format!("{}", 42,));
}

#[test]
fn empty_and_braces_only() {
    assert_eq!(s_fmt!(""), String::new());
    assert_eq!(s_fmt!("{{}}"), "{}");
}
