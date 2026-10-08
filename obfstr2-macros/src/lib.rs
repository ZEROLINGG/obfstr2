//! `obfstr2` 的内部过程宏实现 crate，无运行时，不可 doctest。
//!
//! 对外暴露 `s1~3!`、`b1~3!`、`f1~3!`、`i1~3!`、`fl1~3!`、`cs1~3!`（低延迟 / 均衡 / 高强度三档）与 `s_fmt!` 的过程宏本体；
//! 用户文档见 `obfstr2` 根 crate 的同名重导出，请直接依赖 `obfstr2`。
mod bytes;
mod combine;
mod core;
mod crypto;
mod cstr;
mod float;
mod int;
mod storage;
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

fn expand_int(
    input: TokenStream,
    build: fn(int::ParsedInt) -> proc_macro2::TokenStream,
) -> TokenStream {
    match int::parse_int(input.into()) {
        Ok(parsed) => build(parsed).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_float(
    input: TokenStream,
    build: fn(float::ParsedFloat) -> proc_macro2::TokenStream,
) -> TokenStream {
    match float::parse_float(input.into()) {
        Ok(parsed) => build(parsed).into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_cstr(input: TokenStream, build: fn(Vec<u8>) -> proc_macro2::TokenStream) -> TokenStream {
    match cstr::parse_cstr(input.into()) {
        Ok(payload) => build(payload).into(),
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

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn s1(input: TokenStream) -> TokenStream {
    expand_str(input, str::s1)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn s2(input: TokenStream) -> TokenStream {
    expand_str(input, str::s2)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn s3(input: TokenStream) -> TokenStream {
    expand_str(input, str::s3)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn b1(input: TokenStream) -> TokenStream {
    expand_bytes(input, bytes::b1)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn b2(input: TokenStream) -> TokenStream {
    expand_bytes(input, bytes::b2)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn b3(input: TokenStream) -> TokenStream {
    expand_bytes(input, bytes::b3)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn f1(input: TokenStream) -> TokenStream {
    expand_file(input, bytes::b1)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn f2(input: TokenStream) -> TokenStream {
    expand_file(input, bytes::b2)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn f3(input: TokenStream) -> TokenStream {
    expand_file(input, bytes::b3)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/s_fmt.rs`。
#[proc_macro]
pub fn s_fmt(input: TokenStream) -> TokenStream {
    combine::sfmt(input.into()).into()
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn i1(input: TokenStream) -> TokenStream {
    expand_int(input, int::i1)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn i2(input: TokenStream) -> TokenStream {
    expand_int(input, int::i2)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn i3(input: TokenStream) -> TokenStream {
    expand_int(input, int::i3)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn fl1(input: TokenStream) -> TokenStream {
    expand_float(input, float::fl1)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn fl2(input: TokenStream) -> TokenStream {
    expand_float(input, float::fl2)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn fl3(input: TokenStream) -> TokenStream {
    expand_float(input, float::fl3)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn cs1(input: TokenStream) -> TokenStream {
    expand_cstr(input, cstr::cs1)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn cs2(input: TokenStream) -> TokenStream {
    expand_cstr(input, cstr::cs2)
}

#[doc = include_str!("internal_macro.md")]
/// 覆盖见根 crate `tests/smoke.rs`。
#[proc_macro]
pub fn cs3(input: TokenStream) -> TokenStream {
    expand_cstr(input, cstr::cs3)
}
