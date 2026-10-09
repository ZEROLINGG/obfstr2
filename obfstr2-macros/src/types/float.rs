//! 浮点档位入口：`fl1` / `fl2` / `fl3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留浮点编码（解码表达式）与档位入口；解析见 `crate::parse`。
//!
//! 设计：浮点 `to_bits().to_le_bytes() -> Vec<u8>` 喂入 `build_obfuscated_bytes`，
//! 运行时解密为字节容器后再 `from_le_bytes` + `from_bits` 还原为裸浮点值。
//! 返回裸值（可直接算术/比较），不提供 `Drop` 自动清零（与 `StackStr` 差异见文档）。
//! 仅接受有限常规值：`inf`/`NaN` 一律拒绝（前者请用 `INFINITY` 常量，后者无字面量写法）；
//! `-0.0` 按位保留符号位。

use super::want_heap;
use crate::core::{TIER_BALANCED, TIER_HIGH, TIER_LOW, build_obfuscated_bytes};
use crate::parse::{FloatTy, ParsedFloat};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

/// 解码表达式：字节容器 `->` 裸浮点。调用方已处于 `unsafe` 块内
/// （长度恒为 4/8，展开期已验证），直接用 `unwrap_unchecked`（与 `int.rs` 同策略）。
fn decode_expr(ty: FloatTy) -> TokenStream2 {
    match ty {
        FloatTy::F32 => quote!(::core::primitive::f32::from_bits(
            ::core::primitive::u32::from_le_bytes(
                ::core::convert::TryInto::try_into(__float_bytes.as_slice()).unwrap_unchecked()
            )
        )),
        FloatTy::F64 => quote!(::core::primitive::f64::from_bits(
            ::core::primitive::u64::from_le_bytes(
                ::core::convert::TryInto::try_into(__float_bytes.as_slice()).unwrap_unchecked()
            )
        )),
    }
}

fn build_float(parsed: ParsedFloat, inner: TokenStream2) -> TokenStream2 {
    let decode = decode_expr(parsed.ty);
    quote! {
        {
            let mut __float_bytes = #inner;
            unsafe { #decode }
        }
    }
}

pub fn fl1(parsed: ParsedFloat) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        TIER_LOW,
        false, // nostd可用
        true,
    );
    build_float(parsed, inner)
}

pub fn fl2(parsed: ParsedFloat) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        TIER_BALANCED,
        cfg!(feature = "alloc"),
        want_heap(),
    );
    build_float(parsed, inner)
}

pub fn fl3(parsed: ParsedFloat) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        TIER_HIGH,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc"),
    );
    build_float(parsed, inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_float;

    fn token(s: &str) -> TokenStream2 {
        match s.parse() {
            Ok(t) => t,
            Err(e) => panic!("测试输入 {s:?} 不是合法 TokenStream: {e}"),
        }
    }

    fn parse(s: &str) -> ParsedFloat {
        match parse_float(token(s)) {
            Ok(p) => p,
            Err(e) => panic!("解析 {s:?} 失败: {e}"),
        }
    }

    fn parse_err(s: &str) -> String {
        match parse_float(token(s)) {
            Ok(_) => panic!("{s:?} 应当解析失败"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn suffix_and_default_ty() {
        assert_eq!(parse("1.0f32").ty, FloatTy::F32);
        assert_eq!(parse("1.0f64").ty, FloatTy::F64);
        assert_eq!(parse("1.0").ty, FloatTy::F64);
        assert_eq!(parse("-1.0").ty, FloatTy::F64);
        assert_eq!(parse("5f32").ty, FloatTy::F32);
        assert_eq!(parse("1e10").ty, FloatTy::F64);
        assert_eq!(parse("1_000.5f32").ty, FloatTy::F32);
    }

    #[test]
    fn bits_roundtrip_encoding() {
        assert_eq!(
            parse("1.5f32").bytes,
            1.5f32.to_bits().to_le_bytes().to_vec()
        );
        assert_eq!(
            parse("-0.0").bytes,
            (-0.0f64).to_bits().to_le_bytes().to_vec()
        );
        assert_eq!(
            parse("-0.0f32").bytes,
            (-0.0f32).to_bits().to_le_bytes().to_vec()
        );
        // -0.0 与 0.0 位必须不同（符号位保留）
        assert_ne!(
            parse("-0.0f32").bytes,
            parse("0.0f32").bytes,
            "-0.0 符号位必须保留"
        );
    }

    #[test]
    fn boundary_values_accepted() {
        parse("340282346638528859811704183484516925440.0f32"); // f32::MAX
        parse("-340282346638528859811704183484516925440.0f32");
        parse("1.7976931348623157e308"); // f64::MAX
        parse("5e-324"); // 最小 f64 次正规数
        parse("1e-45f32"); // 次正规区
        parse("1.17549435e-38f32"); // f32::MIN_POSITIVE（最小正规格数）
    }

    #[test]
    fn overflow_to_inf_rejected() {
        let e = parse_err("1e999f32");
        assert!(e.contains("无穷"), "实际: {e}");
        let e = parse_err("1e999");
        assert!(e.contains("无穷"), "实际: {e}");
    }

    #[test]
    fn non_literal_rejected() {
        let e = parse_err("f64::MAX");
        assert!(e.contains("只接受浮点字面量"), "实际: {e}");
        let e = parse_err("1.0 + 2.0");
        assert!(e.contains("只接受浮点字面量"), "实际: {e}");
        let e = parse_err("f64::INFINITY");
        assert!(e.contains("只接受浮点字面量"), "实际: {e}");
        let e = parse_err("1.0f16");
        assert!(e.contains("后缀"), "实际: {e}");
    }

    #[test]
    fn polymorphic_two_expansions_differ() {
        let a = fl2(parse("3.15")).to_string();
        let b = fl2(parse("3.15")).to_string();
        assert_ne!(a, b, "两次展开应多态不同");
    }

    #[test]
    fn tiers_accept_edge_values() {
        for f in [fl1, fl2, fl3] {
            assert!(!f(parse("0.0f32")).is_empty());
            assert!(!f(parse("-0.0")).is_empty());
            assert!(!f(parse("1.7976931348623157e308")).is_empty());
        }
    }
}
