#![doc = include_str!("../README.md")]
#![no_std]
pub use lib_unknown::crypto;
pub use lib_unknown::types;

/// 内部过程宏实现库的重导出。
#[doc(hidden)]
pub extern crate obfstr2_macros;

/// 字符串混淆宏（低延迟档）。
///
/// 只接受字符串字面量 `"..."`，展开为求值即得原文的表达式（类型为
/// `StackStr<N>`，请使用类型推断，不要写死类型标注）。
///
/// # Examples
///
/// ```rust
/// use obfstr2::s1;
///
/// let s = s1!("hello");
/// assert_eq!(&*s, "hello");
/// ```
#[macro_export]
macro_rules! s1 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::s1!($($tt)*)
    };
}

/// 字符串混淆宏（均衡档）。
///
/// 只接受字符串字面量 `"..."`。返回的具体字符串类型（`StackStr` /
/// `HeapStr`）同一宏名下可能随编译变化，请使用类型推断。
///
/// # Examples
///
/// ```rust
/// use obfstr2::s2;
///
/// let s = s2!("hello");
/// assert_eq!(&*s, "hello");
/// ```
#[macro_export]
macro_rules! s2 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::s2!($($tt)*)
    };
}

/// 字符串混淆宏（高强度档）。
///
/// 只接受字符串字面量 `"..."`，展开类型规则同 [`s2`](s2!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::s3;
///
/// let s = s3!("hello");
/// assert_eq!(&*s, "hello");
/// ```
#[macro_export]
macro_rules! s3 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::s3!($($tt)*)
    };
}

/// 字节串混淆宏（低延迟档）。
///
/// 接受字节串字面量 `b"..."` 或字节数组 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量），展开为求值即得原文的字节容器表达式
/// （`StackBytes<N>` / `HeapBytes<N>`，可解引用为 `[u8]`）。
///
/// # Examples
///
/// ```rust
/// use obfstr2::b1;
///
/// let a = b1!(b"abc");
/// let b = b1!([0x61, 98, 99]);
/// assert_eq!(&*a, &*b);
/// assert_eq!(&*a, b"abc");
/// ```
#[macro_export]
macro_rules! b1 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::b1!($($tt)*)
    };
}

/// 字节串混淆宏（均衡档）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
///
/// # Examples
///
/// ```rust
/// use obfstr2::b2;
///
/// let a = b2!(b"abc");
/// let b = b2!([0x61, 98, 99]);
/// assert_eq!(&*a, &*b);
/// assert_eq!(&*a, b"abc");
/// ```
#[macro_export]
macro_rules! b2 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::b2!($($tt)*)
    };
}

/// 字节串混淆宏（高强度档）。
///
/// 接受 `b"..."` 或 `[0x41, 66, ...]`（元素须为 0..=255 的整数字面量）。
///
/// # Examples
///
/// ```rust
/// use obfstr2::b3;
///
/// let a = b3!(b"abc");
/// let b = b3!([0x61, 98, 99]);
/// assert_eq!(&*a, &*b);
/// assert_eq!(&*a, b"abc");
/// ```
#[macro_export]
macro_rules! b3 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::b3!($($tt)*)
    };
}

/// 文件混淆宏（低延迟档）。
///
/// 接受文件路径字面量（如 `"assets/fixture.bin"`，相对于被编译 crate 的
/// `CARGO_MANIFEST_DIR` 解析），编译期读入文件内容并混淆，展开为求值即得
/// 文件原文的字节容器表达式（`StackBytes<N>` / `HeapBytes<N>`）。
/// 需自行保证文件存在；文件缺失或不可读时报编译错误。
///
/// # Examples
///
/// ```rust
/// use obfstr2::f1;
///
/// let b = f1!("assets/fixture.bin");
/// assert_eq!(&*b, b"secret");
/// ```
#[macro_export]
macro_rules! f1 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::f1!($($tt)*)
    };
}

/// 文件混淆宏（均衡档）。
///
/// 输入与展开规则同 [`f1`](f1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::f2;
///
/// let b = f2!("assets/fixture.bin");
/// assert_eq!(&*b, b"secret");
/// ```
#[macro_export]
macro_rules! f2 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::f2!($($tt)*)
    };
}

/// 文件混淆宏（高强度档）。
///
/// 输入与展开规则同 [`f1`](f1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::f3;
///
/// let b = f3!("assets/fixture.bin");
/// assert_eq!(&*b, b"secret");
/// ```
#[macro_export]
macro_rules! f3 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::f3!($($tt)*)
    };
}

/// 格式化字符串混淆宏（1 档）。
///
/// 首参须为字符串字面量：其中的字面量片段逐个混淆后注入 `format!` 调用，
/// 占位符与后续参数原样保留。返回 `String`，需要调用方有 `std` / `alloc`。
///
/// # Examples
///
/// ```rust
/// use obfstr2::s_fmt;
///
/// let name = "world";
/// let s = s_fmt!("hello, {}!", name);
/// assert_eq!(s, "hello, world!");
/// let t = s_fmt!("hi, {name}!", name = name);
/// assert_eq!(t, "hi, world!");
/// ```
#[macro_export]
macro_rules! s_fmt {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::s_fmt!($($tt)*)
    };
}

/// 整数混淆宏（低延迟档）。
///
/// 只接受整数字面量（如 `42u8`、`-1`、`0xFFu16`，空后缀视为 `i32`），
/// 展开为求值即得原文的裸整数表达式，可直接算术、比较、`let` 绑定传递。
/// 注意：返回裸值，无 `Drop` 自动清零（与 `StackStr` 不同）。
///
/// # Examples
///
/// ```rust
/// use obfstr2::i1;
///
/// assert_eq!(i1!(42u8), 42u8);
/// assert_eq!(i1!(-1), -1i32);
/// assert_eq!(i1!(0xFFu16), 0xFFu16);
/// ```
#[macro_export]
macro_rules! i1 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::i1!($($tt)*)
    };
}

/// 整数混淆宏（均衡档）。
///
/// 输入与展开规则同 [`i1`](i1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::i2;
///
/// assert_eq!(i2!(-1), -1i32);
/// assert_eq!(i2!(1_000u32), 1_000u32);
/// assert_eq!(i2!(123usize), 123usize);
/// ```
#[macro_export]
macro_rules! i2 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::i2!($($tt)*)
    };
}

/// 整数混淆宏（高强度档）。
///
/// 输入与展开规则同 [`i1`](i1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::i3;
///
/// assert_eq!(i3!(0xFFu16), 0xFFu16);
/// assert_eq!(i3!(255u8), 255u8);
/// assert_eq!(i3!(-7i16), -7i16);
/// ```
#[macro_export]
macro_rules! i3 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::i3!($($tt)*)
    };
}

/// 浮点混淆宏（低延迟档）。
///
/// 只接受浮点字面量（如 `3.14f32`、`-1.0`、`1e10`，空后缀视为 `f64`），
/// 展开为求值即得原文的裸浮点表达式，可直接算术、比较、`let` 绑定传递。
/// 仅接受有限常规值：`inf` / `NaN` 一律拒绝；`-0.0` 按位保留符号位。
/// 注意：返回裸值，无 `Drop` 自动清零（与 `StackStr` 不同）。
///
/// # Examples
///
/// ```rust
/// use obfstr2::fl1;
///
/// assert_eq!(fl1!(1.5f32).to_bits(), 1.5f32.to_bits());
/// assert_eq!(fl1!(-0.0f32).to_bits(), (-0.0f32).to_bits());
/// ```
#[macro_export]
macro_rules! fl1 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::fl1!($($tt)*)
    };
}

/// 浮点混淆宏（均衡档）。
///
/// 输入与展开规则同 [`fl1`](fl1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::fl2;
///
/// assert_eq!(fl2!(3.15).to_bits(), 3.15f64.to_bits());
/// assert_eq!(fl2!(1e10).to_bits(), 1e10f64.to_bits());
/// assert_eq!(fl2!(5f32).to_bits(), 5f32.to_bits());
/// ```
#[macro_export]
macro_rules! fl2 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::fl2!($($tt)*)
    };
}

/// 浮点混淆宏（高强度档）。
///
/// 输入与展开规则同 [`fl1`](fl1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::fl3;
///
/// assert_eq!(fl3!(-0.0).to_bits(), (-0.0f64).to_bits());
/// assert_eq!(fl3!(2.5f64).to_bits(), 2.5f64.to_bits());
/// ```
#[macro_export]
macro_rules! fl3 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::fl3!($($tt)*)
    };
}

/// C 字符串混淆宏（低延迟档）。
///
/// 接受字符串字面量 `"..."`、C 字符串字面量 `c"..."` 或字节串字面量
/// `b"..."`（后者可表达非 UTF-8 载荷；三者语义等价，`b"..."` 不校验 UTF-8）。
/// 载荷不能包含内部 NUL（宏会追加唯一的结尾 `\0`）。
/// 展开为求值即得原文的 C 字符串容器表达式（`StackCStr<N>`，`N` 含结尾 `\0`，
/// 请使用类型推断），可解引用为 `core::ffi::CStr`、`as_ptr()` 直投系统调用，
/// `Drop` 时自动清零。
///
/// # Examples
///
/// ```rust
/// use obfstr2::cs1;
///
/// let a = cs1!("/bin/sh");
/// let b = cs1!(c"/bin/sh");
/// let c = cs1!(b"/bin/sh");
/// assert_eq!(&*a, c"/bin/sh");
/// assert_eq!(&*b, c"/bin/sh");
/// assert_eq!(&*c, c"/bin/sh");
/// ```
#[macro_export]
macro_rules! cs1 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::cs1!($($tt)*)
    };
}

/// C 字符串混淆宏（均衡档）。
///
/// 输入与展开规则同 [`cs1`](cs1!())；返回的具体容器类型（`StackCStr` /
/// `HeapCStr`）同一宏名下可能随编译变化，请使用类型推断。
///
/// # Examples
///
/// ```rust
/// use obfstr2::cs2;
///
/// let a = cs2!("/bin/sh");
/// let b = cs2!(c"/bin/sh");
/// let c = cs2!(b"/bin/sh");
/// assert_eq!(&*a, c"/bin/sh");
/// assert_eq!(&*b, c"/bin/sh");
/// assert_eq!(&*c, c"/bin/sh");
/// ```
#[macro_export]
macro_rules! cs2 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::cs2!($($tt)*)
    };
}

/// C 字符串混淆宏（高强度档）。
///
/// 输入与展开规则同 [`cs1`](cs1!())。
///
/// # Examples
///
/// ```rust
/// use obfstr2::cs3;
///
/// let a = cs3!("/bin/sh");
/// let b = cs3!(c"/bin/sh");
/// let c = cs3!(b"/bin/sh");
/// assert_eq!(&*a, c"/bin/sh");
/// assert_eq!(&*b, c"/bin/sh");
/// assert_eq!(&*c, c"/bin/sh");
/// ```
#[macro_export]
macro_rules! cs3 {
    ($($tt:tt)*) => {
        ::obfstr2::obfstr2_macros::cs3!($($tt)*)
    };
}
