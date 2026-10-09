//! 输入解析层：各宏字面量输入 → 载荷字节 / 编码结构。
//!
//! 档位适配见 `crate::types`，混淆编排见 `crate::core`。
//! 本文件只保留输入校验（字面量形态、后缀、范围、NUL、文件存在性），不做加密与发射。

use proc_macro2::TokenStream as TokenStream2;

/// 负号拆分：`42u8` → `(字面量, false)`，`-42u8` → `(字面量, true)`。
///
/// 调用方按自身字面量类型做二次匹配（`int` 要 `Lit::Int`，`float` 要 `Lit::Float`，
/// 另有整数 token 兼容分支）；`what` 为各宏的“只接受……”前缀，错误文案与原内联版本逐字一致。
pub(crate) fn split_neg(expr: syn::Expr, what: &str) -> syn::Result<(syn::Lit, bool)> {
    match expr {
        syn::Expr::Lit(syn::ExprLit { lit, .. }) => Ok((lit, false)),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => match *u.expr {
            syn::Expr::Lit(syn::ExprLit { lit, .. }) => Ok((lit, true)),
            other => Err(syn::Error::new_spanned(
                &other,
                format!("{what}，不支持表达式"),
            )),
        },
        other => Err(syn::Error::new_spanned(
            &other,
            format!("{what}，不支持表达式"),
        )),
    }
}

/// 解析后的整数：小端字节 + 目标类型标记。
pub(crate) struct ParsedInt {
    pub(crate) bytes: Vec<u8>,
    /// 解码表达式的整数类型，如 `u32`；`usize`/`isize` 需经 `u64`/`i64` 中转。
    pub(crate) ty: IntTy,
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

/// 解析 `iN!` 输入：只接受整数字面量（可选前导 `-`），拒绝表达式/路径/函数调用。
pub(crate) fn parse_int(input: TokenStream2) -> syn::Result<ParsedInt> {
    let expr: syn::Expr = syn::parse2(input)?;
    match split_neg(expr, "iN! 只接受整数字面量（如 42u8、-1、0xFFu16)")? {
        (syn::Lit::Int(n), false) => parse_int_positive(&n),
        (syn::Lit::Int(n), true) => parse_int_negative(&n),
        (lit, _) => Err(syn::Error::new_spanned(
            &lit,
            "iN! 只接受整数字面量（如 42u8、-1、0xFFu16），不支持表达式",
        )),
    }
}

fn int_suffix_err(n: &syn::LitInt) -> syn::Error {
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

/// 正数字面量单臂生成：`$parse` 为实际解析类型（`usize` 按 `u64`、`isize` 按 `i64` 解析，
/// 见模块文档与 README 限制说明）。泛型函数无法表述各整数类型的 `to_le_bytes`（无公共 trait，
/// 为此引入新依赖得不偿失），故用局内宏。
macro_rules! parse_pos {
    ($n:expr, $ty:expr, $parse:ty) => {{
        let v: $parse = $n.base10_parse().map_err(|_| range_err($n, $ty))?;
        v.to_le_bytes().to_vec()
    }};
}

/// 正数字面量：`base10_parse` 天然处理 `0x/0o/0b`/下划线并做范围校验。
fn parse_int_positive(n: &syn::LitInt) -> syn::Result<ParsedInt> {
    let ty = IntTy::from_suffix(n.suffix()).ok_or_else(|| int_suffix_err(n))?;
    let bytes = match ty {
        IntTy::U8 => parse_pos!(n, ty, u8),
        IntTy::I8 => parse_pos!(n, ty, i8),
        IntTy::U16 => parse_pos!(n, ty, u16),
        IntTy::I16 => parse_pos!(n, ty, i16),
        IntTy::U32 => parse_pos!(n, ty, u32),
        IntTy::I32 => parse_pos!(n, ty, i32),
        IntTy::U64 => parse_pos!(n, ty, u64),
        IntTy::I64 => parse_pos!(n, ty, i64),
        IntTy::U128 => parse_pos!(n, ty, u128),
        IntTy::I128 => parse_pos!(n, ty, i128),
        IntTy::Usize => parse_pos!(n, ty, u64),
        IntTy::Isize => parse_pos!(n, ty, i64),
    };
    Ok(ParsedInt { bytes, ty })
}

/// 负数字面量：先按 `i128` 解析绝对值再取负，避免 `-(-MIN)` 这类边界溢出误拒。
fn parse_int_negative(n: &syn::LitInt) -> syn::Result<ParsedInt> {
    let ty = IntTy::from_suffix(n.suffix()).ok_or_else(|| int_suffix_err(n))?;
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

/// 解析后的浮点：小端字节 + 目标类型标记。
pub(crate) struct ParsedFloat {
    pub(crate) bytes: Vec<u8>,
    pub(crate) ty: FloatTy,
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
    match split_neg(
        expr,
        "flN! 只接受浮点字面量（如 3.14f32、-1.0、1e10，空后缀视为 f64)",
    )? {
        (syn::Lit::Float(n), false) => parse_float_positive(&n),
        // `5f32` 形态：整数 token + 浮点后缀，syn 可能判为 Lit::Int，引导至浮点处理。
        (syn::Lit::Int(n), false) if n.suffix() == "f32" || n.suffix() == "f64" => {
            parse_float_from_int_token(&n)
        }
        (syn::Lit::Float(n), true) => parse_float_negative(&n),
        (syn::Lit::Int(n), true) if n.suffix() == "f32" || n.suffix() == "f64" => {
            parse_float_from_neg_int_token(&n)
        }
        (lit, _) => Err(syn::Error::new_spanned(
            &lit,
            "flN! 只接受浮点字面量（如 3.14f32、-1.0、1e10，空后缀视为 f64），不支持表达式",
        )),
    }
}

fn float_suffix_err(span: proc_macro2::Span, suffix: &str) -> syn::Error {
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

/// 有限性检查 + `to_bits` 小端编码的公共尾段（`f32` / `f64` 均有 `is_finite` / `to_bits`，
/// 宏展开后按具体类型解析；`nan` 式额外拒绝 NaN，供字面量形态使用，整数 token 形态不可能读出 NaN）。
macro_rules! finish_float {
    ($v:expr, $span:expr, $ty:expr) => {{
        let v = $v;
        if !v.is_finite() {
            return Err(non_finite_err($span, $ty));
        }
        Ok(ParsedFloat {
            bytes: v.to_bits().to_le_bytes().to_vec(),
            ty: $ty,
        })
    }};
    ($v:expr, $span:expr, $ty:expr, nan) => {{
        let v = $v;
        if v.is_nan() {
            return Err(nan_err($span));
        }
        if !v.is_finite() {
            return Err(non_finite_err($span, $ty));
        }
        Ok(ParsedFloat {
            bytes: v.to_bits().to_le_bytes().to_vec(),
            ty: $ty,
        })
    }};
}

/// 正浮点字面量：`base10_parse` 处理下划线/指数/后缀，之后做有限性检查。
fn parse_float_positive(n: &syn::LitFloat) -> syn::Result<ParsedFloat> {
    let ty =
        FloatTy::from_suffix(n.suffix()).ok_or_else(|| float_suffix_err(n.span(), n.suffix()))?;
    match ty {
        FloatTy::F32 => {
            let v: f32 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(v, n.span(), ty, nan)
        }
        FloatTy::F64 => {
            let v: f64 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(v, n.span(), ty, nan)
        }
    }
}

/// 负浮点字面量：正值解析后取负再 `to_bits`，保留 `-0.0` 符号位。
fn parse_float_negative(n: &syn::LitFloat) -> syn::Result<ParsedFloat> {
    let ty =
        FloatTy::from_suffix(n.suffix()).ok_or_else(|| float_suffix_err(n.span(), n.suffix()))?;
    match ty {
        FloatTy::F32 => {
            let mag: f32 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(-mag, n.span(), ty, nan)
        }
        FloatTy::F64 => {
            let mag: f64 = n
                .base10_parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(-mag, n.span(), ty, nan)
        }
    }
}

/// `5f32` 防御分支：整数 token + 浮点后缀时按浮点解析。
fn parse_float_from_int_token(n: &syn::LitInt) -> syn::Result<ParsedFloat> {
    let ty =
        FloatTy::from_suffix(n.suffix()).ok_or_else(|| float_suffix_err(n.span(), n.suffix()))?;
    // 整数形态无小数点/指数，按对应浮点重解析其十进制数字。
    let digits = n.base10_digits();
    match ty {
        FloatTy::F32 => {
            let v: f32 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(v, n.span(), ty)
        }
        FloatTy::F64 => {
            let v: f64 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(v, n.span(), ty)
        }
    }
}

/// `5f32` 取负分支：直接解析绝对值再取负编码，避免正浮点→字节→浮点的往返转换。
fn parse_float_from_neg_int_token(n: &syn::LitInt) -> syn::Result<ParsedFloat> {
    let ty =
        FloatTy::from_suffix(n.suffix()).ok_or_else(|| float_suffix_err(n.span(), n.suffix()))?;
    let digits = n.base10_digits();
    match ty {
        FloatTy::F32 => {
            let mag: f32 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(-mag, n.span(), ty)
        }
        FloatTy::F64 => {
            let mag: f64 = digits
                .parse()
                .map_err(|e| syn::Error::new(n.span(), format!("浮点字面量解析失败：{e}")))?;
            finish_float!(-mag, n.span(), ty)
        }
    }
}

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

/// 解析 `sN!` 输入：只接受字符串字面量 `"..."`。
pub(crate) fn parse_str(input: TokenStream2) -> syn::Result<String> {
    syn::parse2::<syn::LitStr>(input).map(|lit| lit.value())
}

/// 解析 `bN!` 输入：`b"..."` 字节串或 `[0x41, 66, ...]` 数组（元素须为 0..=255 的整数字面量）。
pub(crate) fn parse_bytes(input: TokenStream2) -> syn::Result<Vec<u8>> {
    // 1. b"..." 字节串形式
    if let Ok(lit) = syn::parse2::<syn::LitByteStr>(input.clone()) {
        return Ok(lit.value());
    }
    // 2. [0x41, 66, ...] 字节数组形式
    let arr: syn::ExprArray = syn::parse2(input)?;
    let mut bytes = Vec::with_capacity(arr.elems.len());
    for elem in &arr.elems {
        match elem {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(n),
                ..
            }) => match n.base10_parse::<u8>() {
                Ok(b) => bytes.push(b),
                Err(_) => {
                    return Err(syn::Error::new_spanned(
                        n,
                        "字节数组元素必须在 0..=255 范围内",
                    ));
                }
            },
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "字节数组只接受 0..=255 的整数字面量",
                ));
            }
        }
    }
    Ok(bytes)
}

/// 解析 `fN!` 输入：路径字面量相对被编译 crate 的 `CARGO_MANIFEST_DIR` 读入文件
/// （与 `include_bytes!` 一致）；文件缺失或不可读时报错。
pub(crate) fn parse_file(input: TokenStream2) -> syn::Result<Vec<u8>> {
    let path_lit: syn::LitStr = syn::parse2(input)?;
    let rel = path_lit.value();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let full = std::path::Path::new(&manifest_dir).join(&rel);
    std::fs::read(&full).map_err(|e| {
        syn::Error::new(
            path_lit.span(),
            format!("无法读取文件 {}: {e}", full.display()),
        )
    })
}
