//! 整数档位入口：`i1` / `i2` / `i3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留整数解析、编码与档位参数。
//!
//! 设计：整数 `to_le_bytes() -> Vec<u8>` 喂入 `build_obfuscated_bytes`，
//! 运行时解密为字节容器后再 `from_le_bytes` 还原为裸整数值。
//! 返回裸值（可直接算术/比较），不提供 `Drop` 自动清零（与 `StackStr` 差异见文档）。

use crate::core::build_obfuscated_bytes;
use lib_unknown::rand::random;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

/// 解析后的整数：小端字节 + 目标类型标记。
pub(crate) struct ParsedInt {
    bytes: Vec<u8>,
    /// 解码表达式的整数类型，如 `u32`；`usize`/`isize` 需经 `u64`/`i64` 中转。
    ty: IntTy,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum IntTy {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
    Usize,
    Isize,
}

impl IntTy {
    fn from_suffix(suffix: &str) -> Option<Self> {
        match suffix {
            "u8" => Some(Self::U8),
            "i8" => Some(Self::I8),
            "u16" => Some(Self::U16),
            "i16" => Some(Self::I16),
            "u32" => Some(Self::U32),
            "i32" => Some(Self::I32),
            "u64" => Some(Self::U64),
            "i64" => Some(Self::I64),
            "u128" => Some(Self::U128),
            "i128" => Some(Self::I128),
            "usize" => Some(Self::Usize),
            "isize" => Some(Self::Isize),
            "" => Some(Self::I32),
            _ => None,
        }
    }

    fn display(&self) -> &'static str {
        match self {
            Self::U8 => "u8",
            Self::I8 => "i8",
            Self::U16 => "u16",
            Self::I16 => "i16",
            Self::U32 => "u32",
            Self::I32 => "i32",
            Self::U64 => "u64",
            Self::I64 => "i64",
            Self::U128 => "u128",
            Self::I128 => "i128",
            Self::Usize => "usize",
            Self::Isize => "isize",
        }
    }

    fn is_signed(&self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::Isize
        )
    }
}

/// 解析 `iN!` 输入：只接受整数面量（可选前导 `-`），拒绝表达式/路径/函数调用。
pub(crate) fn parse_int(input: TokenStream2) -> syn::Result<ParsedInt> {
    let expr: syn::Expr = syn::parse2(input)?;
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(n),
            ..
        }) => parse_positive(&n),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => match *u.expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(n),
                ..
            }) => parse_negative(&n),
            other => Err(syn::Error::new_spanned(
                &other,
                "iN! 只接受整数字面量（如 42u8、-1、0xFFu16），不支持表达式",
            )),
        },
        other => Err(syn::Error::new_spanned(
            &other,
            "iN! 只接受整数字面量（如 42u8、-1、0xFFu16），不支持表达式",
        )),
    }
}

fn unsupported_suffix_err(n: &syn::LitInt) -> syn::Error {
    syn::Error::new_spanned(
        n,
        format!(
            "不支持的整数后缀 {:?}，可用：u8/i8/u16/i16/u32/i32/u64/i64/u128/i128/usize/isize（空后缀视为 i32）",
            n.suffix()
        ),
    )
}

fn range_err(n: &syn::LitInt, ty: IntTy) -> syn::Error {
    syn::Error::new_spanned(n, format!("整数字面量超出 {} 范围", ty.display()))
}

/// 正数字面量：`base10_parse` 天然处理 `0x/0o/0b`/下划线并做范围校验。
fn parse_positive(n: &syn::LitInt) -> syn::Result<ParsedInt> {
    let ty = IntTy::from_suffix(n.suffix()).ok_or_else(|| unsupported_suffix_err(n))?;
    // usize 按 u64 语义编码（见模块文档与 README 限制说明）。
    let bytes = match ty {
        IntTy::U8 => {
            let v: u8 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::I8 => {
            let v: i8 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::U16 => {
            let v: u16 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::I16 => {
            let v: i16 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::U32 => {
            let v: u32 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::I32 => {
            let v: i32 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::U64 => {
            let v: u64 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::I64 => {
            let v: i64 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::U128 => {
            let v: u128 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::I128 => {
            let v: i128 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::Usize => {
            let v: u64 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
        IntTy::Isize => {
            let v: i64 = n.base10_parse().map_err(|_| range_err(n, ty))?;
            v.to_le_bytes().to_vec()
        }
    };
    Ok(ParsedInt { bytes, ty })
}

/// 负数字面量：先按 `i128` 解析绝对值再取负，避免 `-(-MIN)` 这类边界溢出误拒。
fn parse_negative(n: &syn::LitInt) -> syn::Result<ParsedInt> {
    let ty = IntTy::from_suffix(n.suffix()).ok_or_else(|| unsupported_suffix_err(n))?;
    if !ty.is_signed() && ty != IntTy::I32 {
        // ty 不可能是无后缀之外的无符号之外的东西；无符号一律拒绝。
        // （无后缀视为 i32，属于有符号，走下面流程。）
        if !ty.is_signed() {
            return Err(syn::Error::new_spanned(
                n,
                format!("负数不能用于无符号整数类型 {}", ty.display()),
            ));
        }
    }
    // 绝对值按 `u128` 解析，兼容 `-i128::MIN`（其绝对值超出 `i128::MAX`）。
    let mag: u128 = n.base10_parse().map_err(|_| range_err(n, ty))?;
    // 各有符号类型的绝对值上限 = MAX + 1（允许 MIN）。
    macro_rules! neg_checked {
        ($max:expr, $min:expr, $ty:ty) => {{
            let limit = ($max as u128) + 1;
            if mag > limit {
                return Err(range_err(n, ty));
            }
            if mag == limit {
                <$ty>::MIN.to_le_bytes().to_vec()
            } else {
                (-(mag as i128) as $ty).to_le_bytes().to_vec()
            }
        }};
    }
    let bytes = match ty {
        IntTy::I8 => neg_checked!(i8::MAX, i8::MIN, i8),
        IntTy::I16 => neg_checked!(i16::MAX, i16::MIN, i16),
        IntTy::I32 => neg_checked!(i32::MAX, i32::MIN, i32),
        IntTy::I64 => neg_checked!(i64::MAX, i64::MIN, i64),
        IntTy::I128 => {
            const LIMIT: u128 = (i128::MAX as u128) + 1;
            if mag > LIMIT {
                return Err(range_err(n, ty));
            }
            if mag == LIMIT {
                i128::MIN.to_le_bytes().to_vec()
            } else {
                (-(mag as i128)).to_le_bytes().to_vec()
            }
        }
        IntTy::Isize => neg_checked!(i64::MAX, i64::MIN, i64),
        _ => {
            return Err(syn::Error::new_spanned(
                n,
                format!("负数不能用于无符号整数类型 {}", ty.display()),
            ));
        }
    };
    Ok(ParsedInt { bytes, ty })
}

/// 解码表达式：字节容器 `->` 裸整数。`usize/isize` 经 `u64/i64` 中转（64 位语义）。
///
/// 调用方已处于 `unsafe` 块内（长度恒为 1/2/4/8/16，展开期已验证），
/// 故直接用 `unwrap_unchecked` 保持零运行时校验（与 `str.rs` 同策略）。
fn decode_expr(ty: IntTy) -> TokenStream2 {
    match ty {
        IntTy::U8 => quote!(::core::primitive::u8::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::I8 => quote!(::core::primitive::i8::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::U16 => quote!(::core::primitive::u16::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::I16 => quote!(::core::primitive::i16::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::U32 => quote!(::core::primitive::u32::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::I32 => quote!(::core::primitive::i32::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::U64 => quote!(::core::primitive::u64::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::I64 => quote!(::core::primitive::i64::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::U128 => quote!(::core::primitive::u128::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::I128 => quote!(::core::primitive::i128::from_le_bytes(
            ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
        )),
        IntTy::Usize => quote!(
            (::core::primitive::u64::from_le_bytes(
                ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
            ) as usize)
        ),
        IntTy::Isize => quote!(
            (::core::primitive::i64::from_le_bytes(
                ::core::convert::TryInto::try_into(__int_bytes.as_slice()).unwrap_unchecked()
            ) as isize)
        ),
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

pub fn i1(parsed: ParsedInt) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        30,
        0,
        1,
        false, // nostd可用
        true,
    );
    build_int(parsed, inner)
}

pub fn i2(parsed: ParsedInt) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        100,
        50,
        2,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc") && random(),
    );
    build_int(parsed, inner)
}

pub fn i3(parsed: ParsedInt) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        100,
        95,
        4,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc"),
    );
    build_int(parsed, inner)
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
        let a = i2(parse("42u32")).to_string();
        let b = i2(parse("42u32")).to_string();
        assert_ne!(a, b, "两次展开应多态不同");
        let _ = p;
    }

    #[test]
    fn tiers_accept_edge_values() {
        for f in [i1, i2, i3] {
            assert!(!f(parse("0u8")).is_empty());
            assert!(!f(parse("-128i8")).is_empty());
            assert!(!f(parse("18446744073709551615u64")).is_empty());
        }
    }
}
