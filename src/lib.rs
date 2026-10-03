//! 编译期字符串 / 字节 / 文件混淆库（`no_std` 兼容）。
//!
//! 混淆宏（`s1~3!`、`b1~3!`、`f1~3!`）由 [`macros_obfstr`] 提供并在此转发；
//! 运行时安全内存类型与密码原语分别来自 `lib-unknown` 的 `types` 与 `crypto` 模块。
#![allow(unused)]
#![no_std]
pub use lib_unknown::crypto;
pub use lib_unknown::types;

pub use macros_obfstr::*;
