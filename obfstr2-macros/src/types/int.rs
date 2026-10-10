//! 整数档位入口：`i1` / `i2` / `i3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留整数编码（解码表达式）与档位入口；解析见 `crate::parse`。
//!
//! 设计：整数 `to_le_bytes() -> Vec<u8>` 喂入 `build_obfuscated_bytes`，
//! 运行时解密为字节容器后再 `from_le_bytes` 还原为裸整数值。
//! 返回裸值（可直接算术/比较），不提供 `Drop` 自动清零（与 `StackStr` 差异见文档）。

use super::want_heap;
use crate::core::{TIER_BALANCED, TIER_HIGH, TIER_LOW, build_obfuscated_bytes};
use crate::parse::{IntTy, ParsedInt};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

/// 解码表达式：字节容器 `->` 裸整数。`usize/isize` 经 `u64/i64` 中转（64 位语义）。
///
/// 调用方已处于 `unsafe` 块内（长度恒为 1/2/4/8/16，展开期已验证），
/// 故直接用 `unwrap_unchecked` 保持零运行时校验（与 `str.rs` 同策略）。
/// 小端解码单臂生成：除 `usize` / `isize` 需经 `u64` / `i64` 中转（64 位语义）外，其余类型直解。
macro_rules! decode_le {
    ($ty:ty) => {
        quote!(::core::primitive::$ty::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        ))
    };
    ($ty:ty as $cast:ty) => {
        quote!(
            (::core::primitive::$ty::from_le_bytes(
                ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
            ) as $cast)
        )
    };
}

fn decode_expr(ty: IntTy) -> TokenStream2 {
    match ty {
        IntTy::U8 => decode_le!(u8),
        IntTy::I8 => decode_le!(i8),
        IntTy::U16 => decode_le!(u16),
        IntTy::I16 => decode_le!(i16),
        IntTy::U32 => decode_le!(u32),
        IntTy::I32 => decode_le!(i32),
        IntTy::U64 => decode_le!(u64),
        IntTy::I64 => decode_le!(i64),
        IntTy::U128 => decode_le!(u128),
        IntTy::I128 => decode_le!(i128),
        IntTy::Usize => decode_le!(u64 as usize),
        IntTy::Isize => decode_le!(i64 as isize),
    }
}

fn build_int(parsed: ParsedInt, inner: TokenStream2) -> TokenStream2 {
    let decode = decode_expr(parsed.ty);
    quote! {
        {
            let mut __int_bytes = #inner;
            unsafe { #decode }
        }
    }
}

pub fn i1(parsed: ParsedInt) -> Result<TokenStream2, String> {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        TIER_LOW,
        false, // nostd可用
        true,
    )?;
    Ok(build_int(parsed, inner))
}

pub fn i2(parsed: ParsedInt) -> Result<TokenStream2, String> {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        TIER_BALANCED,
        cfg!(feature = "alloc"),
        want_heap(),
    )?;
    Ok(build_int(parsed, inner))
}

pub fn i3(parsed: ParsedInt) -> Result<TokenStream2, String> {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        TIER_HIGH,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc"),
    )?;
    Ok(build_int(parsed, inner))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::parse::parse_int;

    fn token(s: &str) -> TokenStream2 {
        match s.parse() {
            Ok(t) => t,
            Err(e) => panic!("测试输入 {s:?} 不是合法 TokenStream: {e}"),
        }
    }

    fn parse(s: &str) -> ParsedInt {
        match parse_int(token(s)) {
            Ok(p) => p,
            Err(e) => panic!("解析 {s:?} 失败: {e}"),
        }
    }

    fn parse_err(s: &str) -> String {
        match parse_int(token(s)) {
            Ok(_) => panic!("{s:?} 应当解析失败"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn suffix_and_default_ty() {
        assert_eq!(parse("42u8").ty, IntTy::U8);
        assert_eq!(parse("42").ty, IntTy::I32);
        assert_eq!(parse("-1").ty, IntTy::I32);
        assert_eq!(parse("0xFFu16").ty, IntTy::U16);
        assert_eq!(parse("1_000u32").ty, IntTy::U32);
        assert_eq!(parse("1usize").ty, IntTy::Usize);
        assert_eq!(parse("-1isize").ty, IntTy::Isize);
    }

    #[test]
    fn le_bytes_roundtrip_encoding() {
        assert_eq!(parse("0x0102u16").bytes, 0x0102u16.to_le_bytes().to_vec());
        assert_eq!(parse("-1i8").bytes, (-1i8).to_le_bytes().to_vec());
        assert_eq!(
            parse("170141183460469231731687303715884105727i128").bytes,
            i128::MAX.to_le_bytes().to_vec()
        );
    }

    #[test]
    fn boundary_min_max_accepted() {
        parse("255u8");
        parse("127i8");
        parse("-128i8");
        parse("2147483647");
        parse("-2147483648");
        parse("340282366920938463463374607431768211455u128");
        parse("-170141183460469231731687303715884105728i128");
    }

    #[test]
    fn out_of_range_rejected() {
        let e = parse_err("256u8");
        assert!(e.contains("超出 u8 范围"), "实际: {e}");
        let e = parse_err("-1u8");
        assert!(e.contains("负数不能用于无符号"), "实际: {e}");
        let e = parse_err("128i8");
        assert!(e.contains("超出 i8 范围"), "实际: {e}");
        let e = parse_err("-129i8");
        assert!(e.contains("超出 i8 范围"), "实际: {e}");
    }

    #[test]
    fn non_literal_rejected() {
        let e = parse_err("u64::MAX");
        assert!(e.contains("只接受整数字面量"), "实际: {e}");
        let e = parse_err("1 + 2");
        assert!(e.contains("只接受整数字面量"), "实际: {e}");
        let e = parse_err("1f32");
        assert!(
            e.contains("只接受整数字面量") || e.contains("不支持的整数后缀"),
            "实际: {e}"
        );
    }

    #[test]
    fn polymorphic_two_expansions_differ() {
        let p = || parse("42u32");
        // ParsedInt 不可 Clone（bytes Vec 可 clone 但 parse 每次重新来，保证输入一致）
        let a = i2(parse("42u32")).expect("i2").to_string();
        let b = i2(parse("42u32")).expect("i2").to_string();
        assert_ne!(a, b, "两次展开应多态不同");
        let _ = p;
    }

    #[test]
    fn tiers_accept_edge_values() {
        for f in [i1, i2, i3] {
            assert!(!f(parse("0u8")).expect("tier").is_empty());
            assert!(!f(parse("-128i8")).expect("tier").is_empty());
            assert!(
                !f(parse("18446744073709551615u64"))
                    .expect("tier")
                    .is_empty()
            );
        }
    }
}
