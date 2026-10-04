#![allow(unused)]
//! 多态加解密原语注册表（`Crypto` + `PRIMITIVES`）。
//!

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use std::sync::LazyLock;

#[derive(Clone)]
pub(crate) struct Crypto {
    // 正向加密：参数 (数据切片, 密钥, IV)
    pub(crate) enc: fn(&mut [u8], u64, u8),
    // 逆向解密：参数 (变量标识符, 密钥, IV) -> 返回 AST TokenStream
    pub(crate) dec: fn(&proc_macro2::Ident, u64, u8) -> TokenStream2,
    // 判断当前长度的 chunk 能否运用该操作
    pub(crate) support: fn(usize) -> bool,
    // 抗逆向安全性 0～100 (抵抗静态分析、符号执行的难度)
    pub(crate) security: u8,
    // 运行时性能开销 0～100 (初始化盒子的耗时、单字节处理的时钟周期)
    pub(crate) latency: u8,
}

pub(crate) static PRIMITIVES: LazyLock<Vec<Crypto>> = LazyLock::new(|| {
    vec![
        // CBC 模式异或链
        Crypto {
            enc: |chunk, key, iv| {
                let mut l = iv;
                for c in chunk.iter_mut() {
                    *c ^= key.rotate_left(l as u32) as u8;
                    l = *c;
                }
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        let mut l = #iv;
                        for c in #ident.iter_mut() {
                            let next_l = *c;
                            *c ^= (#key as u64).rotate_left(l as u32) as u8;
                            l = next_l;
                        }
                    }
                }
            },
            support: |_len| true,
            security: 12,
            latency: 5,
        },
        // 包装加减法与位置密钥
        Crypto {
            enc: |chunk, key, iv| {
                for (i, c) in chunk.iter_mut().enumerate() {
                    let k = (key ^ iv as u64).rotate_right(i as u32) as u8;
                    *c = c.wrapping_add(k);
                }
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        for (i, c) in #ident.iter_mut().enumerate() {
                            let k = (#key as u64 ^ #iv as u64).rotate_right(i as u32) as u8;
                            *c = c.wrapping_sub(k);
                        }
                    }
                }
            },
            support: |_len| true,
            security: 15,
            latency: 5,
        },
        // 乘法逆元混淆
        Crypto {
            enc: |chunk, key, _iv| {
                for (i, c) in chunk.iter_mut().enumerate() {
                    let k = (key.rotate_right(i as u32) as u8) | 1;
                    *c = c.wrapping_mul(lib_unknown::crypto::base::inv_mul8(k));
                }
            },
            dec: |ident, key, _iv| {
                quote! {
                    {
                        for (i, c) in #ident.iter_mut().enumerate() {
                            let k = ((#key as u64).rotate_right(i as u32) as u8) | 1;
                            *c = c.wrapping_mul(k);
                        }
                    }
                }
            },
            support: |_len| true,
            security: 15,
            latency: 5,
        },
        // 动态位移混淆 + 位置流异或
        Crypto {
            enc: |chunk, key, _iv| {
                for (i, c) in chunk.iter_mut().enumerate() {
                    let rot = (key.rotate_right(i as u32) % 8) as u32;
                    *c = c.rotate_left(rot) ^ (key >> ((i * 8) % 64)) as u8;
                }
            },
            dec: |ident, key, _iv| {
                quote! {
                    {
                        for (i, c) in #ident.iter_mut().enumerate() {
                            let rot = ((#key as u64).rotate_right(i as u32) % 8) as u32;
                            *c ^= ((#key as u64) >> ((i * 8) % 64)) as u8;
                            *c = c.rotate_right(rot);
                        }
                    }
                }
            },
            support: |_len| true,
            security: 16,
            latency: 5,
        },
        // 纯流密码 mse_no_ps (无 P盒/S盒)
        Crypto {
            enc: |chunk, key, iv| {
                lib_unknown::crypto::base::mse_no_ps(chunk, key, iv);
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        ::obfstr2::crypto::base::imse_no_ps(#ident.as_mut_slice(), #key, #iv);
                    }
                }
            },
            support: |_len| true,
            security: 35,
            latency: 15,
        },
        // 流密码 mse_no_s (带自修改P盒，无S盒)
        Crypto {
            enc: |chunk, key, iv| {
                lib_unknown::crypto::base::mse_no_s(chunk, key, iv);
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        ::obfstr2::crypto::base::imse_no_s(#ident.as_mut_slice(), #key, #iv);
                    }
                }
            },
            support: |_len| true,
            security: 55,
            latency: 35,
        },
        // 全量流密码 mse (自修改动态 P盒 + S盒)
        Crypto {
            enc: |chunk, key, iv| {
                lib_unknown::crypto::base::mse(chunk, key, iv);
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        ::obfstr2::crypto::base::imse(#ident.as_mut_slice(), #key, #iv);
                    }
                }
            },
            support: |_len| true,
            security: 80,
            latency: 80,
        },
        // 静态 S-Box 非线性替换
        Crypto {
            enc: |chunk, _key, _iv| {
                for c in chunk.iter_mut() {
                    *c =
                        lib_unknown::crypto::base::s8(*c, &lib_unknown::crypto::base::SBOX_BASE[0]);
                }
            },
            dec: |ident, _key, _iv| {
                quote! {
                    {
                        for c in #ident.iter_mut() {
                            *c = ::obfstr2::crypto::base::s8(*c, &::obfstr2::crypto::base::SBOX_BASE[1]);
                        }
                    }
                }
            },
            support: |_len| true,
            security: 16,
            latency: 3,
        },
        // 动态比特洗牌 P-Box
        Crypto {
            enc: |chunk, key, _iv| {
                let p = lib_unknown::crypto::base::gen_p(key);
                for c in chunk.iter_mut() {
                    *c = lib_unknown::crypto::base::p8(*c, &p);
                }
            },
            dec: |ident, key, _iv| {
                quote! {
                    {
                        let p = ::obfstr2::crypto::base::gen_p(#key as u64);
                        let p_inv = unsafe { ::obfstr2::crypto::base::inv_p(&p).unwrap_unchecked() };
                        for c in #ident.iter_mut() {
                            *c = ::obfstr2::crypto::base::p8(*c, &p_inv);
                        }
                    }
                }
            },
            support: |_len| true,
            security: 30,
            latency: 20,
        },
        // 动态密码本 S-Box
        Crypto {
            enc: |chunk, key, _iv| {
                let s = lib_unknown::crypto::base::gen_s(key);
                for c in chunk.iter_mut() {
                    *c = lib_unknown::crypto::base::s8(*c, &s);
                }
            },
            dec: |ident, key, _iv| {
                quote! {
                    {
                        let s = ::obfstr2::crypto::base::gen_s(#key as u64);
                        let s_inv = unsafe { ::obfstr2::crypto::base::inv_s(&s).unwrap_unchecked() };
                        for c in #ident.iter_mut() {
                            *c = ::obfstr2::crypto::base::s8(*c, &s_inv);
                        }
                    }
                }
            },
            support: |_len| true,
            security: 65,
            latency: 70,
        },
        // 单字节多轮流加密 (3轮 r8，无盒)
        Crypto {
            enc: |chunk, key, iv| {
                for (i, c) in chunk.iter_mut().enumerate() {
                    let mut val = *c;
                    let mut round_key = lib_unknown::crypto::base::mix64(
                        key ^ (iv as u64) ^ (i as u64).rotate_left(7),
                    );

                    for round in 0..3 {
                        val = lib_unknown::crypto::base::r8(
                            val,
                            iv,
                            round,
                            round_key as u128,
                            None,
                            None,
                        );
                        round_key = lib_unknown::crypto::base::mix64_next(round_key);
                    }
                    *c = val;
                }
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        for (i, c) in #ident.iter_mut().enumerate() {
                            let mut val = *c;
                            let mut k0 = ::obfstr2::crypto::base::mix64(#key as u64 ^ (#iv as u64) ^ (i as u64).rotate_left(7));
                            let mut k1 = ::obfstr2::crypto::base::mix64_next(k0);
                            let mut k2 = ::obfstr2::crypto::base::mix64_next(k1);

                            val = ::obfstr2::crypto::base::ir8(val, #iv, 2, k2 as u128, None, None);
                            val = ::obfstr2::crypto::base::ir8(val, #iv, 1, k1 as u128, None, None);
                            val = ::obfstr2::crypto::base::ir8(val, #iv, 0, k0 as u128, None, None);
                            *c = val;
                        }
                    }
                }
            },
            support: |_len| true,
            security: 40,
            latency: 30,
        },
        // 3-5 轮动态 P-Box
        Crypto {
            enc: |chunk, key, iv| {
                let rounds = ((key >> 8) as usize % 3) + 3; // 3-5轮
                for round in 0..rounds {
                    let mut prev = iv ^ (round as u8);
                    let seed =
                        lib_unknown::crypto::base::mix64(key.rotate_right((round * 11) as u32));
                    let mut p = lib_unknown::crypto::base::gen_p(seed);
                    let round_key = (key as u128) ^ ((round as u128) << 64);

                    for (i, c) in chunk.iter_mut().enumerate() {
                        let ct = lib_unknown::crypto::base::r8(
                            *c,
                            prev,
                            i,
                            round_key,
                            Some(&mut p),
                            None,
                        );
                        prev = ct;
                        *c = ct;
                    }
                }
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        let rounds = (((#key >> 8) as usize) % 3) + 3;
                        for round in (0..rounds).rev() {
                            let mut prev = (#iv as u8) ^ (round as u8);
                            let seed = ::obfstr2::crypto::base::mix64((#key as u64).rotate_right((round * 11) as u32));
                            let p_box = ::obfstr2::crypto::base::gen_p(seed);
                            let mut p_inv = unsafe { ::obfstr2::crypto::base::inv_p(&p_box).unwrap_unchecked() };
                            let round_key = (#key as u128) ^ ((round as u128) << 64);
                            for (i, c) in #ident.iter_mut().enumerate() {
                                let pt = ::obfstr2::crypto::base::ir8(*c, prev, i, round_key, Some(&mut p_inv), None);
                                prev = *c;
                                *c = pt;
                            }
                        }
                    }
                }
            },
            support: |_len| true,
            security: 60,
            latency: 60,
        },
        // 全功能多轮 r8（3轮，P+S双盒）
        Crypto {
            enc: |chunk, key, iv| {
                let rounds = 3;
                for round in 0..rounds {
                    let mut prev = iv.rotate_left(round as u32);
                    let seed_base =
                        lib_unknown::crypto::base::mix64_next(key.wrapping_add(round as u64));
                    let mut p = lib_unknown::crypto::base::gen_p(seed_base);
                    let mut s = lib_unknown::crypto::base::gen_s(lib_unknown::crypto::base::mix64(
                        seed_base,
                    ));
                    let round_key = (key as u128) ^ ((round as u128) << 80);

                    for (i, c) in chunk.iter_mut().enumerate() {
                        let ct = lib_unknown::crypto::base::r8(
                            *c,
                            prev,
                            i,
                            round_key,
                            Some(&mut p),
                            Some(&mut s),
                        );
                        prev = ct;
                        *c = ct;
                    }
                }
            },
            dec: |ident, key, iv| {
                quote! {
                    {
                        let rounds = 3;
                        for round in (0..rounds).rev() {
                            let mut prev = (#iv as u8).rotate_left(round as u32);
                            let seed_base = ::obfstr2::crypto::base::mix64_next((#key as u64).wrapping_add(round as u64));
                            let p_box = ::obfstr2::crypto::base::gen_p(seed_base);
                            let s_box = ::obfstr2::crypto::base::gen_s(::obfstr2::crypto::base::mix64(seed_base));
                            let mut p_inv = unsafe { ::obfstr2::crypto::base::inv_p(&p_box).unwrap_unchecked() };
                            let mut s_inv = unsafe { ::obfstr2::crypto::base::inv_s(&s_box).unwrap_unchecked() };
                            let round_key = (#key as u128) ^ ((round as u128) << 80);

                            for (i, c) in #ident.iter_mut().enumerate() {
                                let pt = ::obfstr2::crypto::base::ir8(*c, prev, i, round_key, Some(&mut p_inv), Some(&mut s_inv));
                                prev = *c;
                                *c = pt;
                            }
                        }
                    }
                }
            },
            support: |_len| true,
            security: 85,
            latency: 90,
        },
    ]
});
