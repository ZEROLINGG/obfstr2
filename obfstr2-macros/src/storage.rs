#![allow(unused)]
//! 多态密文存储策略注册表（`Storage` + `STORAGE_STRATEGIES`）。
//!

use lib_unknown::rand::random;
use proc_macro2::{Ident as Ident2, Literal as Literal2, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use std::sync::LazyLock;

#[derive(Clone)]
pub(crate) struct Storage {
    // 接受参数： (变量名(Ident), 类型路径(TokenStream2), 密文真实长度(usize), 密文数据(&[u8]))
    // 返回： 完整的变量声明与数据填充 AST
    pub(crate) ast: fn(&proc_macro2::Ident, &TokenStream2, usize, &[u8]) -> TokenStream2,
    // 判断当前 chunk 长度是否适合此策略
    pub(crate) support: fn(usize) -> bool,
    // 抗分析能力（如伪装度，打断静态扫描的能力） 0~100
    pub(crate) security: u8,
    // 运行时恢复数据的性能开销 0~100
    pub(crate) latency: u8,
}

/// 十六进制字符串存储（MAC/UUID/IPv6）的运行时解码片段。
///
/// 三者此前各有一套近乎逐行重复的 `for &b in s.as_bytes()` 解析循环，
/// 此处按分隔符（`b':'` / `b'-'`）参数化为公共 helper。
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
            latency: 2,
        },
        Storage {
            ast: |ident, type_path, size, data| {
                let bytes = data.iter().map(|&b| Literal2::u8_suffixed(b));
                quote! {
                    let mut #ident = #type_path::new();
                    let temp_arr: [u8; #size] = [#(#bytes),*];
                    unsafe { #ident.extend_from_slice(&temp_arr).unwrap_unchecked(); }
                }
            },
            support: |size| size <= 256,
            security: 10,
            latency: 5,
        },
        Storage {
            ast: |ident, type_path, size, data| {
                let mut u64s = Vec::new();
                for chunk in data.chunks(8) {
                    let mut buf = [0u8; 8];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    u64s.push(Literal2::u64_suffixed(u64::from_le_bytes(buf)));
                }
                let const_name = format_ident!("__STATIC_U64_{}", random::<u32>());
                quote! {
                    static #const_name: &[u64] = &[#(#u64s),*];
                    let mut #ident = #type_path::new();
                    let mut _current_len = 0;
                    for &val in #const_name {
                        let b = val.to_le_bytes();
                        let remaining = #size - _current_len;
                        let copy_len = if remaining > 8 { 8 } else { remaining };
                        unsafe { #ident.extend_from_slice(&b[..copy_len]).unwrap_unchecked(); }
                        _current_len += copy_len;
                    }
                }
            },
            support: |size| (128..=1024).contains(&size),
            security: 20,
            latency: 8,
        },
        Storage {
            ast: |ident, type_path, size, data| {
                let mut u128s = Vec::new();
                for chunk in data.chunks(16) {
                    let mut buf = [0u8; 16];
                    buf[..chunk.len()].copy_from_slice(chunk);
                    u128s.push(Literal2::u128_suffixed(u128::from_le_bytes(buf)));
                }
                let const_name = format_ident!("__STATIC_U128_{}", random::<u32>());
                quote! {
                    static #const_name: &[u128] = &[#(#u128s),*];
                    let mut #ident = #type_path::new();
                    let mut _current_len = 0;
                    for &val in #const_name {
                        let b = val.to_le_bytes();
                        let remaining = #size - _current_len;
                        let copy_len = if remaining > 16 { 16 } else { remaining };
                        unsafe { #ident.extend_from_slice(&b[..copy_len]).unwrap_unchecked(); }
                        _current_len += copy_len;
                    }
                }
            },
            support: |size| (128..=1024).contains(&size),
            security: 20,
            latency: 10,
        },
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
            security: 45, // 较高的静态分析打扰度（IDA/Ghidra 提取字符串会误以为是网络配置）
            latency: 15,  // 需要简单的字符串解析开销
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
            security: 60, // 极高的伪装度，极为像系统的组件 GUID/UUID
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
            security: 65, // 反汇编分析者容易将其归类为网络硬编码地址
            latency: 18,
        },
    ]
});
