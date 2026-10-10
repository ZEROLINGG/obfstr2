//! 多态密文存储策略注册表（`Storage` + `STORAGE_STRATEGIES`）。
//!

use lib_unknown::rand::random;
use proc_macro2::{
    Ident as Ident2, Literal as Literal2, Span as Span2, TokenStream as TokenStream2,
};
use quote::{format_ident, quote};
use std::sync::LazyLock;

#[derive(Clone)]
pub(crate) struct Storage {
    // 返回： 完整的变量声明与数据填充 AST
    pub(crate) ast: fn(&proc_macro2::Ident, &TokenStream2, usize, &[u8]) -> TokenStream2,
    // 判断当前 chunk 长度是否适合此策略
    pub(crate) support: fn(usize) -> bool,
    // 抗分析能力（如伪装度，打断静态扫描的能力） 0~100
    #[allow(dead_code)]
    pub(crate) security: u8,
    // 运行时恢复数据的性能开销 0~100
    pub(crate) latency: u8,
}

/// 十六进制字符串存储（MAC/UUID/IPv6）的运行时解码片段。
fn hex_str_decode(
    ident: &Ident2,
    type_path: &TokenStream2,
    size: usize,
    const_name: &Ident2,
    sep: u8,
) -> TokenStream2 {
    quote! {
        let mut #ident = #type_path::new();
        let mut _written = 0;
        for &s in #const_name {
            let mut hi = None;
            for &b in s.as_bytes() {
                if _written >= #size { break; }
                if b == #sep { continue; }
                let val = match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => 0,
                };
                if let Some(h) = hi {
                    unsafe { #ident.extend_from_slice(&[(h << 4) | val]).unwrap_unchecked(); }
                    _written += 1;
                    hi = None;
                } else {
                    hi = Some(val);
                }
            }
        }
    }
}

/// 整型数组存储策略生成：`u64` / `u128` 双策略仅位宽、字面量后缀与延迟不同，
/// 共用分块填充与按需截断恢复逻辑。
macro_rules! int_array_storage {
    ($tag:ident, $ty:ty, $suffixed:ident, $width:expr) => {
        Storage {
            ast: |ident, type_path, size, data| {
                let mut ints = Vec::new();
                for chunk in data.chunks($width) {
                    let mut buf = [0u8; $width];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    ints.push(Literal2::$suffixed(<$ty>::from_le_bytes(buf)));
                }
                let const_name = Ident2::new(
                    &format!("__STATIC_{}_{}", stringify!($tag), random::<u32>()),
                    Span2::call_site(),
                );
                quote! {
                    static #const_name: &[$ty] = &[#(#ints),*];
                    let mut #ident = #type_path::new();
                    let mut _current_len = 0;
                    for &val in #const_name {
                        let b = val.to_le_bytes();
                        let remaining = #size - _current_len;
                        let copy_len = if remaining > $width { $width } else { remaining };
                        unsafe { #ident.extend_from_slice(&b[..copy_len]).unwrap_unchecked(); }
                        _current_len += copy_len;
                    }
                }
            },
            support: |size| (128..=1024).contains(&size),
            security: 20,
            latency: 20,
        }
    };
}

pub(crate) static STORAGE_STRATEGIES: LazyLock<Vec<Storage>> = LazyLock::new(|| {
    vec![
        Storage {
            ast: |ident, type_path, _size, data| {
                let enc_literal = Literal2::byte_string(data);
                let enc_ident = format_ident!("__STATIC_B_{}", random::<u32>());
                quote! {
                    static #enc_ident: &[u8] = #enc_literal;
                    let mut #ident = #type_path::new();
                    unsafe { #ident.extend_from_slice(#enc_ident).unwrap_unchecked(); }
                }
            },
            support: |_| true,
            security: 10,
            latency: 0,
        },
        int_array_storage!(U64, u64, u64_suffixed, 8),
        int_array_storage!(U128, u128, u128_suffixed, 16),
        // MAC 地址隐写存储策略
        Storage {
            ast: |ident, type_path, size, data| {
                let mut macs = Vec::new();
                // MAC 地址每块 6 字节
                for chunk in data.chunks(6) {
                    let mut buf = [0u8; 6];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    let mac_str = format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
                    );
                    macs.push(mac_str);
                }
                let const_name = format_ident!("__STATIC_MAC_{}", random::<u32>());
                let decode = hex_str_decode(ident, type_path, size, &const_name, b':');
                quote! {
                    static #const_name: &[&str] = &[#(#macs),*];
                    #decode
                }
            },
            support: |size| (6..=967).contains(&size),
            security: 45,
            latency: 15,
        },
        // UUID 隐写存储策略
        Storage {
            ast: |ident, type_path, size, data| {
                let mut uuids = Vec::new();
                // UUID 每块 16 字节
                for chunk in data.chunks(16) {
                    let mut buf = [0u8; 16];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    let uuid_str = format!(
                        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        buf[0],
                        buf[1],
                        buf[2],
                        buf[3],
                        buf[4],
                        buf[5],
                        buf[6],
                        buf[7],
                        buf[8],
                        buf[9],
                        buf[10],
                        buf[11],
                        buf[12],
                        buf[13],
                        buf[14],
                        buf[15]
                    );
                    uuids.push(uuid_str);
                }
                let const_name = format_ident!("__STATIC_UUID_{}", random::<u32>());
                let decode = hex_str_decode(ident, type_path, size, &const_name, b'-');
                quote! {
                    static #const_name: &[&str] = &[#(#uuids),*];
                    #decode
                }
            },
            support: |size| (16..=1024).contains(&size),
            security: 48,
            latency: 18,
        },
        // IPv6 隐写存储策略
        Storage {
            ast: |ident, type_path, size, data| {
                let mut ipv6s = Vec::new();
                // IPv6 每块 16 字节
                for chunk in data.chunks(16) {
                    let mut buf = [0u8; 16];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    let ipv6_str = format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        buf[0],
                        buf[1],
                        buf[2],
                        buf[3],
                        buf[4],
                        buf[5],
                        buf[6],
                        buf[7],
                        buf[8],
                        buf[9],
                        buf[10],
                        buf[11],
                        buf[12],
                        buf[13],
                        buf[14],
                        buf[15]
                    );
                    ipv6s.push(ipv6_str);
                }
                let const_name = format_ident!("__STATIC_IPV6_{}", random::<u32>());
                let decode = hex_str_decode(ident, type_path, size, &const_name, b':');
                quote! {
                    static #const_name: &[&str] = &[#(#ipv6s),*];
                    #decode
                }
            },
            support: |size| (16..=1024).contains(&size),
            security: 48,
            latency: 18,
        },
    ]
});
