//! `obfstr2` 的过程宏实现 crate：字符串 / 字节 / 文件编译期混淆入口。
//!
//! 对外暴露 `s1~3!`、`b1~3!`、`f1~3!` 九个宏（低延迟 / 均衡 / 高强度三档）；
//! 具体行为见各宏文档，通过 `obfstr2` 根 crate 转发（`pub use macros_obfstr::*`）。
mod bytes;
mod str;

use proc_macro::TokenStream;

fn expand_str(input: TokenStream, build: fn(String) -> proc_macro2::TokenStream) -> TokenStream {
    match syn::parse::<syn::LitStr>(input) {
        Ok(lit) => build(lit.value()).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_bytes(input: TokenStream, build: fn(Vec<u8>) -> proc_macro2::TokenStream) -> TokenStream {
    // 1. b"..." 字节串形式
    if let Ok(lit) = syn::parse::<syn::LitByteStr>(input.clone()) {
        return build(lit.value()).into();
    }
    // 2. [0x41, 66, ...] 字节数组形式（元素必须为 0..=255 的整数字面量）
    match syn::parse::<syn::ExprArray>(input) {
        Ok(arr) => {
            let mut bytes = Vec::with_capacity(arr.elems.len());
            for elem in &arr.elems {
                match elem {
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(n),
                        ..
                    }) => match n.base10_parse::<u8>() {
                        Ok(b) => bytes.push(b),
                        Err(_) => {
                            return syn::Error::new_spanned(n, "字节数组元素必须在 0..=255 范围内")
                                .to_compile_error()
                                .into();
                        }
                    },
                    other => {
                        return syn::Error::new_spanned(
                            other,
                            "字节数组只接受 0..=255 的整数字面量",
                        )
                        .to_compile_error()
                        .into();
                    }
                }
            }
            build(bytes).into()
        }
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_file(input: TokenStream, build: fn(Vec<u8>) -> proc_macro2::TokenStream) -> TokenStream {
    let path_lit = match syn::parse::<syn::LitStr>(input) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    // 路径相对于被编译 crate 的 CARGO_MANIFEST_DIR 解析（与 include_bytes! 一致）
    let rel = path_lit.value();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let full = std::path::Path::new(&manifest_dir).join(&rel);
    let data = match std::fs::read(&full) {
        Ok(d) => d,
        Err(e) => {
            return syn::Error::new(
                path_lit.span(),
                format!("无法读取文件 {}: {e}", full.display()),
            )
            .to_compile_error()
            .into();
        }
    };
    build(data).into()
}

/// 字符串混淆宏（低延迟档，对应 `s1`）。
///
/// 只接受字符串字面量 `"..."`，展开为求值即得原文的表达式（类型为
/// `StackStr<N>`，请使用类型推断，不要写死类型标注）。
/// # Examples
///
/// ```rust,ignore
/// // 过程宏无法在定义 crate 内 doctest（需外部调用方展开）；
/// // 覆盖见 `tests::test_s2_macro` 的 dyntest 端到端用例（s1 同理）。
/// use obfstr2::s1;
/// let s = s1!("hello");
/// ```
#[proc_macro]
pub fn s1(input: TokenStream) -> TokenStream {
    expand_str(input, crate::str::s1)
}

/// 字符串混淆宏（均衡档，对应 `s2`）。
///
/// 只接受字符串字面量 `"..."`。返回的具体字符串类型（`StackStr` /
/// `HeapStr`）同一宏名下可能随编译变化，请使用类型推断。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_s2_macro`。
/// use obfstr2::s2;
/// let s = s2!("hello");
/// ```
#[proc_macro]
pub fn s2(input: TokenStream) -> TokenStream {
    expand_str(input, crate::str::s2)
}

/// 字符串混淆宏（高强度档，对应 `s3`）。
///
/// 只接受字符串字面量 `"..."`，展开类型规则同 [`s2`](s2())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_s2_macro`（s3 同理）。
/// use obfstr2::s3;
/// let s = s3!("hello");
/// ```
#[proc_macro]
pub fn s3(input: TokenStream) -> TokenStream {
    expand_str(input, crate::str::s3)
}

/// 字节串混淆宏（低延迟档，对应 `b1`）。
///
/// 接受字节串字面量 `b"..."` 或字节数组 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量），展开为求值即得原文的字节容器表达式
/// （`StackBytes<N>` / `HeapBytes<N>`，可解引用为 `[u8]`）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_b2_macro`（b1 同理）。
/// use obfstr2::b1;
/// let b = b1!(b"abc");
/// ```
#[proc_macro]
pub fn b1(input: TokenStream) -> TokenStream {
    expand_bytes(input, crate::bytes::b1)
}

/// 字节串混淆宏（均衡档，对应 `b2`）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_b2_macro`。
/// use obfstr2::b2;
/// let b = b2!([0x61, 98, 99]);
/// ```
#[proc_macro]
pub fn b2(input: TokenStream) -> TokenStream {
    expand_bytes(input, crate::bytes::b2)
}

/// 字节串混淆宏（高强度档，对应 `b3`）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_b2_macro`（b3 同理）。
/// use obfstr2::b3;
/// let b = b3!(b"abc");
/// ```
#[proc_macro]
pub fn b3(input: TokenStream) -> TokenStream {
    expand_bytes(input, crate::bytes::b3)
}

/// 文件混淆宏（低延迟档，对应 `b1`）。
///
/// 接受文件路径字面量（如 `"assets/secret.bin"`，相对于被编译 crate 的
/// `CARGO_MANIFEST_DIR` 解析），编译期读入文件内容并混淆，展开为求值即得
/// 文件原文的字节容器表达式（`StackBytes<N>` / `HeapBytes<N>`）。
/// 需自行保证文件存在；文件缺失或不可读时报编译错误。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_f2_macro`（f1 同理）。
/// use obfstr2::f1;
/// let b = f1!("assets/secret.bin");
/// ```
#[proc_macro]
pub fn f1(input: TokenStream) -> TokenStream {
    expand_file(input, crate::bytes::b1)
}

/// 文件混淆宏（均衡档，对应 `b2`）。
///
/// 输入与展开规则同 [`f1`](f1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_f2_macro`。
/// use obfstr2::f2;
/// let b = f2!("assets/secret.bin");
/// ```
#[proc_macro]
pub fn f2(input: TokenStream) -> TokenStream {
    expand_file(input, crate::bytes::b2)
}

/// 文件混淆宏（高强度档，对应 `b3`）。
///
/// 输入与展开规则同 [`f1`](f1())。
/// # Examples
///
/// ```rust,ignore
/// // 同 s1：不可 doctest，覆盖见 `tests::test_f2_macro`（f3 同理）。
/// use obfstr2::f3;
/// let b = f3!("assets/secret.bin");
/// ```
#[proc_macro]
pub fn f3(input: TokenStream) -> TokenStream {
    expand_file(input, crate::bytes::b3)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use lib_unknown::dyntest::dny_run;

    fn run_case(code: &str, expected: &str, tag: &str) {
        let deps = r#"obfstr2 = { path = "../../../../../obfstr2" }"#;
        let ret = dny_run(code, deps, None, false);
        println!("{ret}");
        assert!(ret.stderr.is_empty(), "[{tag}] 编译失败");
        assert_eq!(ret.stdout, expected, "[{tag}] 解码数据错误");
    }

    #[test]
    fn test_s2_macro() {
        run_case(
            r#"fn main() { print!("{}", obfstr2::s2!("hello")) }"#,
            "hello",
            "s2",
        );
    }

    #[test]
    fn test_b2_macro() {
        run_case(
            r#"fn main() { let b = obfstr2::b2!(b"abc"); for x in &*b { print!("{}", *x as char) } }"#,
            "abc",
            "b2",
        );
    }

    #[test]
    fn test_b2_array_macro() {
        // 十六进制/十进制混写 + 边界值 0/255
        run_case(
            r#"fn main() { let b = obfstr2::b2!([0x61, 98, 0, 255]); for x in &*b { print!("{} ", *x) } }"#,
            "97 98 0 255 ",
            "b2-array",
        );
    }

    #[test]
    fn test_f2_macro() {
        // 生成的临时工程必含 src/main.rs：解码后与 include_bytes! 逐字节比对
        run_case(
            r#"fn main() { let b = obfstr2::f2!("src/main.rs"); assert_eq!(&*b, include_bytes!("main.rs")); print!("OK") }"#,
            "OK",
            "f2",
        );
    }

    #[test]
    fn test_f_missing_rejected() {
        let deps = r#"obfstr2 = { path = "../../../../../obfstr2" }"#;
        let ret = dny_run(
            r#"fn main() { let _b = obfstr2::f2!("不存在的文件.bin"); }"#,
            deps,
            None,
            false,
        );
        assert!(!ret.ok, "缺失文件应当编译失败");
        assert!(
            ret.stderr.contains("无法读取文件"),
            "错误信息应提示无法读取文件，实际 stderr:\n{}",
            ret.stderr
        );
    }
    #[test]
    fn test_b_array_rejects_out_of_range() {
        let deps = r#"obfstr2 = { path = "../../../../../obfstr2" }"#;
        let ret = dny_run(
            r#"fn main() { let _b = obfstr2::b2!([0x61, 300]); }"#,
            deps,
            None,
            false,
        );
        assert!(!ret.ok, "越界元素应当编译失败");
        assert!(
            ret.stderr.contains("0..=255"),
            "错误信息应提示取值范围，实际 stderr:\n{}",
            ret.stderr
        );
    }
}
