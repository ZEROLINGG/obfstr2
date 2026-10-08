//! C 字符串档位入口：`cs1` / `cs2` / `cs3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留 C 字符串解析、NUL 语义与档位参数。
//!
//! 设计：字面量载荷（不含 `\0`，编译期拒绝任何内部 NUL）追加结尾 `\0` 后
//! 喂入 `build_obfuscated_bytes`（经 `b1`/`b2`/`b3` 档位入口），运行时解密为
//! 字节容器后再经 `StackCStr` / `HeapCStr::try_from(&mut [u8])` 还原
//! （首 NUL 截断 + 解密源擦除，调用方已处于 `unsafe` 块内、长度恒为载荷+1，
//! 故直接用 `unwrap_unchecked` 保持零运行时校验，与 `str.rs` 同策略）。
//! `N` 含结尾 `\0`（`N >= 1`，空串即 `N = 1`）；返回自有容器，`Drop` 自动清零。
//! 非 UTF-8 载荷请用 `b"..."` 形态（`CStr` 只校验 NUL 语义，不校验 UTF-8）。

use crate::bytes::{b1, b2, b3};
use lib_unknown::rand::random;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

/// 解析 `csN!` 输入：只接受 `"..."` / `c"..."` / `b"..."` 字面量，拒绝表达式/路径/函数调用。
///
/// 返回不含结尾 `\0` 的载荷字节；载荷中任何位置出现 NUL 即报错并给出下标
/// （宏会追加唯一的结尾 NUL，故任何输入 NUL 都是内部 NUL）。
pub(crate) fn parse_cstr(input: TokenStream2) -> syn::Result<Vec<u8>> {
    let expr: syn::Expr = syn::parse2(input)?;
    let (payload, span) = match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(lit),
            ..
        }) => (lit.value().into_bytes(), lit.span()),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::CStr(lit),
            ..
        }) => (lit.value().as_bytes().to_vec(), lit.span()),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::ByteStr(lit),
            ..
        }) => (lit.value(), lit.span()),
        other => {
            return Err(syn::Error::new_spanned(
                &other,
                "csN! 只接受字符串/C 字符串/字节串字面量（如 \"hi\"、c\"hi\"、b\"hi\"），不支持表达式",
            ));
        }
    };
    if let Some(pos) = payload.iter().position(|&b| b == 0) {
        return Err(syn::Error::new(
            span,
            format!("C 字符串载荷不能包含内部 NUL（载荷下标 {pos}）"),
        ));
    }
    Ok(payload)
}

/// 载荷追加结尾 `\0`（调用方已保证载荷无内部 NUL，追加后恰为合法 C 串字节）。
fn with_nul(mut payload: Vec<u8>) -> Vec<u8> {
    payload.push(0);
    payload
}

pub fn cs1(payload: Vec<u8>) -> TokenStream2 {
    // 容量 N 含结尾 `\0`；纯栈、无堆（nostd 可用），与 b1/s1 同策略。
    let size = payload.len() + 1;
    let ts = b1(with_nul(payload));

    quote! {
        {
            let mut bytes = #ts;
            unsafe { ::obfstr2::types::cstr::StackCStr::<#size>::try_from(bytes.as_mut_slice()).unwrap_unchecked() }
        }
    }
}

pub fn cs2(payload: Vec<u8>) -> TokenStream2 {
    let size = payload.len() + 1;
    let ts = b2(with_nul(payload));

    let main_type_path = if cfg!(feature = "alloc") && random() {
        quote!(::obfstr2::types::cstr::HeapCStr)
    } else {
        quote!(::obfstr2::types::cstr::StackCStr)
    };

    quote! {
        {
            let mut bytes = #ts;
            unsafe { #main_type_path::<#size>::try_from(bytes.as_mut_slice()).unwrap_unchecked() }
        }
    }
}

pub fn cs3(payload: Vec<u8>) -> TokenStream2 {
    let size = payload.len() + 1;
    let ts = b3(with_nul(payload));

    let main_type_path = if cfg!(feature = "alloc") {
        quote!(::obfstr2::types::cstr::HeapCStr)
    } else {
        quote!(::obfstr2::types::cstr::StackCStr)
    };

    quote! {
        {
            let mut bytes = #ts;
            unsafe { #main_type_path::<#size>::try_from(bytes.as_mut_slice()).unwrap_unchecked() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(s: &str) -> TokenStream2 {
        match s.parse() {
            Ok(t) => t,
            Err(e) => panic!("测试输入 {s:?} 不是合法 TokenStream: {e}"),
        }
    }

    fn parse(s: &str) -> Vec<u8> {
        match parse_cstr(token(s)) {
            Ok(p) => p,
            Err(e) => panic!("解析 {s:?} 失败: {e}"),
        }
    }

    fn parse_err(s: &str) -> String {
        match parse_cstr(token(s)) {
            Ok(_) => panic!("{s:?} 应当解析失败"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn three_literal_forms_agree() {
        assert_eq!(parse(r#""hi""#), b"hi");
        assert_eq!(parse(r#"c"hi""#), b"hi");
        assert_eq!(parse(r#"b"hi""#), b"hi");
        assert_eq!(parse(r#""""#), b"");
        assert_eq!(parse(r#"c"""#), b"");
        assert_eq!(parse(r#"b"""#), b"");
        // Unicode 与转义由各自字面量语义展开
        assert_eq!(parse(r#""你好""#), "你好".as_bytes());
        assert_eq!(parse(r#"c"a\nb""#), b"a\nb");
    }

    #[test]
    fn non_utf8_byte_str_accepted() {
        // CStr 不校验 UTF-8：b"..." 可表达任意非 NUL 字节
        assert_eq!(parse(r#"b"\xff\xfe""#), vec![0xFF, 0xFE]);
    }

    #[test]
    fn interior_nul_rejected_with_position() {
        let e = parse_err(r#""a\0b""#);
        assert!(e.contains("内部 NUL") && e.contains("下标 1"), "实际: {e}");
        let e = parse_err(r#"b"hi\0""#);
        assert!(e.contains("内部 NUL"), "实际: {e}");
        let e = parse_err(r#"b"\0""#);
        assert!(e.contains("下标 0"), "实际: {e}");
    }

    #[test]
    fn non_literal_rejected() {
        let e = parse_err("concat!(\"a\", \"b\")");
        assert!(e.contains("只接受字符串"), "实际: {e}");
        let e = parse_err("42");
        assert!(e.contains("只接受字符串"), "实际: {e}");
    }

    #[test]
    fn polymorphic_two_expansions_differ() {
        let a = cs2(b"poly".to_vec()).to_string();
        let b = cs2(b"poly".to_vec()).to_string();
        assert_ne!(a, b, "两次展开应多态不同");
    }

    #[test]
    fn tiers_accept_empty_and_single_byte() {
        for f in [cs1, cs2, cs3] {
            // 空载荷 → 仅结尾 NUL 的单字节内核（N = 1）
            assert!(!f(Vec::new()).is_empty());
            assert!(!f(vec![0x61]).is_empty());
        }
    }
}
