//! 浮点档位入口：`fl1` / `fl2` / `fl3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留浮点解析、编码与档位参数。
//!
//! 设计：浮点 `to_bits().to_le_bytes() -> Vec<u8>` 喂入 `build_obfuscated_bytes`，
//! 运行时解密为字节容器后再 `from_le_bytes` + `from_bits` 还原为裸浮点值。
//! 返回裸值（可直接算术/比较），不提供 `Drop` 自动清零（与 `StackStr` 差异见文档）。
//! 仅接受有限常规值：`inf`/`NaN` 一律拒绝（前者请用 `INFINITY` 常量，后者无字面量写法）；
//! `-0.0` 按位保留符号位。

use crate::core::build_obfuscated_bytes;
use lib_unknown::rand::random;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

/// 解析后的浮点：小端字节 + 目标类型标记。
pub(crate) struct ParsedFloat {
    bytes: Vec<u8>,
    ty: FloatTy,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FloatTy {
    F32,
    F64,
}

impl FloatTy {
    fn from_suffix(suffix: &str) -> Option<Self> {
        match suffix {
            "f32" => Some(Self::F32),
            "f64" => Some(Self::F64),
            "" => Some(Self::F64),
            _ => None,
        }
    }

    fn display(&self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }
}

/// 解析 `flN!` 输入：只接受浮点字面量（可选前导 `-`），拒绝表达式/路径/常量。
pub(crate) fn parse_float(input: TokenStream2) -> syn::Result<ParsedFloat> {
    let expr: syn::Expr = syn::parse2(input)?;
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Float(n),
            ..
        }) => parse_positive(&n),
        // `5f32` 形态：整数 token + 浮点后缀，syn 可能判为 Lit::Int，引导至浮点处理。
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(n),
            ..
        }) if n.suffix() == "f32" || n.suffix() == "f64" => parse_int_token_as_float(&n),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => match *u.expr {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Float(n),
                ..
            }) => parse_negative(&n),
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(n),
                ..
            }) if n.suffix() == "f32" || n.suffix() == "f64" => {
                parse_negative_int_token_as_float(&n)
            }
            other => Err(syn::Error::new_spanned(
                &other,
                "flN! 只接受浮点字面量（如 3.14f32、-1.0、1e10，空后缀视为 f64），不支持表达式",
            )),
        },
        other => Err(syn::Error::new_spanned(
            &other,
            "flN! 只接受浮点字面量（如 3.14f32、-1.0、1e10，空后缀视为 f64），不支持表达式",
        )),
    }
}

fn unsupported_suffix_err(span: proc_macro2::Span, suffix: &str) -> syn::Error {
    syn::Error::new(
        span,
        format!("不支持的浮点后缀 {suffix:?}，可用：f32/f64（空后缀视为 f64）"),
    )
}

fn non_finite_err(span: proc_macro2::Span, ty: FloatTy) -> syn::Error {
    syn::Error::new(
        span,
        format!(
            "浮点字面量已上溢为无穷（{}），请直接使用 INFINITY 常量而非宏",
            ty.display()
        ),
    )
}

fn nan_err(span: proc_macro2::Span) -> syn::Error {
    syn::Error::new(span, "NaN 不能作为混淆输入（无字面量写法且语义不稳定）")
}

/// 正浮点字面量：`base10_parse` 处理下划线/指数/后缀，之后做有限性检查。
fn parse_positive(n: &syn::LitFloat) -> syn::Result<ParsedFloat> {
    let ty = FloatTy::from_suffix(n.suffix())
        .ok_or_else(|| unsupported_suffix_err(n.span(), n.suffix()))?;
    match ty {
        FloatTy::F32 => {
            let v: f32 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            if v.is_nan() {
                return Err(nan_err(n.span()));
            }
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
        FloatTy::F64 => {
            let v: f64 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            if v.is_nan() {
                return Err(nan_err(n.span()));
            }
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
    }
}

/// 负浮点字面量：正值解析后取负再 `to_bits`，保留 `-0.0` 符号位。
fn parse_negative(n: &syn::LitFloat) -> syn::Result<ParsedFloat> {
    let ty = FloatTy::from_suffix(n.suffix())
        .ok_or_else(|| unsupported_suffix_err(n.span(), n.suffix()))?;
    match ty {
        FloatTy::F32 => {
            let mag: f32 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            if mag.is_nan() {
                return Err(nan_err(n.span()));
            }
            let v = -mag;
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
        FloatTy::F64 => {
            let mag: f64 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            if mag.is_nan() {
                return Err(nan_err(n.span()));
            }
            let v = -mag;
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
    }
}

/// `5f32` 防御分支：整数 token + 浮点后缀时按浮点解析。
fn parse_int_token_as_float(n: &syn::LitInt) -> syn::Result<ParsedFloat> {
    let ty = FloatTy::from_suffix(n.suffix())
        .ok_or_else(|| unsupported_suffix_err(n.span(), n.suffix()))?;
    // 整数形态无小数点/指数，按对应浮点重解析其十进制数字。
    let digits = n.base10_digits();
    match ty {
        FloatTy::F32 => {
            let v: f32 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
        FloatTy::F64 => {
            let v: f64 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
    }
}

/// `5f32` 取负分支：直接解析绝对值再取负编码，避免正浮点→字节→浮点的往返转换。
fn parse_negative_int_token_as_float(n: &syn::LitInt) -> syn::Result<ParsedFloat> {
    let ty = FloatTy::from_suffix(n.suffix())
        .ok_or_else(|| unsupported_suffix_err(n.span(), n.suffix()))?;
    let digits = n.base10_digits();
    match ty {
        FloatTy::F32 => {
            let mag: f32 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            let v = -mag;
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
        FloatTy::F64 => {
            let mag: f64 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            let v = -mag;
            if !v.is_finite() {
                return Err(non_finite_err(n.span(), ty));
            }
            Ok(ParsedFloat {
                bytes: v.to_bits().to_le_bytes().to_vec(),
                ty,
            })
        }
    }
}

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
        30,
        0,
        1,
        false, // nostd可用
        true,
    );
    build_float(parsed, inner)
}

pub fn fl2(parsed: ParsedFloat) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        100,
        50,
        2,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc") && random(),
    );
    build_float(parsed, inner)
}

pub fn fl3(parsed: ParsedFloat) -> TokenStream2 {
    let inner = build_obfuscated_bytes(
        parsed.bytes.clone(),
        100,
        95,
        4,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc"),
    );
    build_float(parsed, inner)
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
