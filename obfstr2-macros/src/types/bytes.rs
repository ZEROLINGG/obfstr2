//! 字节档位入口：`b1` / `b2` / `b3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留档位参数与测试。

use crate::core::{TIER_BALANCED, TIER_HIGH, TIER_LOW, build_obfuscated_bytes};
use lib_unknown::rand::random;
use proc_macro2::TokenStream as TokenStream2;

/// 均衡档的堆栈二选一：`str.rs` / `cstr.rs` 的主容器策略复用此处，保持档位语义一致。
pub(crate) fn want_heap() -> bool {
    cfg!(feature = "alloc") && random()
}

pub fn b1(input: Vec<u8>) -> TokenStream2 {
    build_obfuscated_bytes(
        input, TIER_LOW, false, // nostd可用
        true,
    )
}

pub fn b2(input: Vec<u8>) -> TokenStream2 {
    build_obfuscated_bytes(input, TIER_BALANCED, cfg!(feature = "alloc"), want_heap())
}

pub fn b3(input: Vec<u8>) -> TokenStream2 {
    // 高强度档主容器随 `alloc` 走堆（与 `s3` / `cs3` / `i3` / `fl3` 对齐）；
    // 关闭 `alloc` 时 `allow_heap` 为假，仍纯栈，`no_std` 可用。
    build_obfuscated_bytes(input, TIER_HIGH, cfg!(feature = "alloc"), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn polymorphic_two_expansions_differ() {
        // 多态核心：同一输入两次展开的 Token 流应不同（随机分块/原语/存储/标识符）。
        let a = b2(vec![42u8; 32]).to_string();
        let b = b2(vec![42u8; 32]).to_string();
        assert_ne!(a, b, "两次展开应多态不同");
    }

    #[test]
    fn tiers_accept_empty_and_single_byte() {
        for f in [b1, b2, b3] {
            assert!(!f(Vec::new()).is_empty());
            assert!(!f(vec![0u8]).is_empty());
        }
    }
}
