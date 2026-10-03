#![allow(unused)]
// obfstr2/macros/src/bytes.rs
use lib_unknown::rand::{random, random_range, shuffle};
use proc_macro2::{Literal as Literal2, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use std::sync::LazyLock;

#[derive(Clone)]
struct Crypto {
    // 正向加密：参数 (数据切片, 密钥, IV)
    enc: fn(&mut [u8], u64, u8),
    // 逆向解密：参数 (变量标识符, 密钥, IV) -> 返回 AST TokenStream
    dec: fn(&proc_macro2::Ident, u64, u8) -> TokenStream2,
    // 判断当前长度的 chunk 能否运用该操作
    support: fn(usize) -> bool,
    // 抗逆向安全性 0～100 (抵抗静态分析、符号执行的难度)
    security: u8,
    // 运行时性能开销 0～100 (初始化盒子的耗时、单字节处理的时钟周期)
    latency: u8,
}

static PRIMITIVES: LazyLock<Vec<Crypto>> = LazyLock::new(|| {
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
        // 全功能多轮 r8（2轮，P+S双盒）
        Crypto {
            enc: |chunk, key, iv| {
                let rounds = 2;
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
                        let rounds = 2;
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

#[derive(Clone)]
struct Storage {
    // 接受参数： (变量名(Ident), 类型路径(TokenStream2), 密文真实长度(usize), 密文数据(&[u8]))
    // 返回： 完整的变量声明与数据填充 AST
    ast: fn(&proc_macro2::Ident, &TokenStream2, usize, &[u8]) -> TokenStream2,
    // 判断当前 chunk 长度是否适合此策略
    support: fn(usize) -> bool,
    // 抗分析能力（如伪装度，打断静态扫描的能力） 0~100
    security: u8,
    // 运行时恢复数据的性能开销 0~100
    latency: u8,
}

static STORAGE_STRATEGIES: LazyLock<Vec<Storage>> = LazyLock::new(|| {
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
            security: 80,
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
            support: |_| true,
            security: 50,
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
            support: |size| size >= 8,
            security: 60,
            latency: 10,
        },
    ]
});

fn build_obfuscated_bytes(
    mut input: Vec<u8>,
    max_latency: u8,
    min_combined_security: u8,
    magnification: u8,
    allow_heap: bool,
    stack_main_bytes: bool,
) -> TokenStream2 {
    let size = input.len();
    let id: u64 = random();
    // let key: u64 = random();

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut i = 1;

    // 随机分块
    while !input.is_empty() {
        let take_size = random_range({ 2usize * i }..{ 8 * i }).min(input.len());
        chunks.push(input.drain(..take_size).collect());
        i += 1;
    }

    let mut ts = TokenStream2::new();

    let bytes = format_ident!("__bytes_{id}");
    let ghost_state = format_ident!("__ghost_state_{id}");

    let use_heap_main = allow_heap && !stack_main_bytes;
    let main_type_path = if use_heap_main {
        quote!(::obfstr2::types::bytes::HeapBytes)
    } else {
        quote!(::obfstr2::types::bytes::StackBytes)
    };

    ts.extend(quote! {
        let mut #bytes = #main_type_path::<#size>::new();
        let mut #ghost_state: u8 = 0_u8;
    });

    for (i, mut chunk) in (1..).zip(chunks) {
        let iv: u8 = random();
        let key: u64 = random();

        let bytes_chunk = format_ident!("__bytes_chunk_{id}_{i}");
        let chunk_size = chunk.len();

        let use_heap_chunk = allow_heap && random::<bool>();
        let chunk_type_path = if use_heap_chunk {
            quote!(::obfstr2::types::bytes::HeapBytes)
        } else {
            quote!(::obfstr2::types::bytes::StackBytes)
        };

        let mut available_primitives: Vec<Crypto> = PRIMITIVES
            .iter()
            .filter(|op| (op.support)(chunk_size) && op.latency <= max_latency)
            .cloned()
            .collect();

        let op_count = random_range(1..3_u8).wrapping_mul(magnification.max(1)) as usize;
        let mut ops = Vec::new();

        let mut combined_vulnerability = 1.0_f64;
        let mut current_combined_security = 0_u8;

        if !available_primitives.is_empty() {
            while ops.len() < op_count || current_combined_security < min_combined_security {
                shuffle(&mut available_primitives);
                let chosen = available_primitives[0].clone();

                let vulnerability = (100.0 - chosen.security as f64) / 100.0;
                combined_vulnerability *= vulnerability;
                current_combined_security = (100.0 * (1.0 - combined_vulnerability)) as u8;

                ops.push(chosen);
                if ops.len() > 16 {
                    break;
                }
            }
        }

        // 执行加密并叠加
        for op in &ops {
            (op.enc)(&mut chunk, key, iv);
        }

        let mut dec_call = TokenStream2::new();
        for op in ops.iter().rev() {
            let dec_ts = (op.dec)(&bytes_chunk, key, iv);
            dec_call.extend(dec_ts);
        }

        let available_storages: Vec<Storage> = STORAGE_STRATEGIES
            .iter()
            .filter(|s| (s.support)(chunk_size) && s.latency <= max_latency)
            .cloned()
            .collect();

        let storage_strategy =
            available_storages[random_range(0..available_storages.len())].clone();

        match random_range(0..3) {
            0 => {
                let dec_fn = format_ident!("__dec_fn_{id}_{i}");
                let chunk_type_expr = quote!(#chunk_type_path::<N>);
                let storage_ast =
                    (storage_strategy.ast)(&bytes_chunk, &chunk_type_expr, chunk_size, &chunk);

                ts.extend(quote! {
                    {
                        #[cold]
                        #[inline(never)]
                        fn #dec_fn<const N: usize>(x: u8) -> #chunk_type_expr {
                            if core::hint::black_box(x) ^ core::hint::black_box(#iv) == 0 {
                                #storage_ast
                                #dec_call
                                core::hint::black_box(#bytes_chunk)
                            } else {
                                #chunk_type_expr::new()
                            }
                        }
                        unsafe { #bytes.extend_from_slice(#dec_fn::<#chunk_size>(#iv).as_slice()).unwrap_unchecked(); }
                    }
                });
            }
            1 => {
                let dec_fn = format_ident!("__dec_fn_{id}_{i}");
                let chunk_type_expr = quote!(#chunk_type_path::<N>);
                let storage_ast =
                    (storage_strategy.ast)(&bytes_chunk, &chunk_type_expr, chunk_size, &chunk);

                ts.extend(quote! {
                    {
                        #[cold]
                        #[inline(never)]
                        fn #dec_fn<const N: usize>(x: u8, d: &mut #main_type_path<#size>) {
                            if core::hint::black_box(x) ^ core::hint::black_box(#iv) == 0 {
                                #storage_ast
                                #dec_call
                                unsafe { d.extend_from_slice(#bytes_chunk.as_slice()).unwrap_unchecked(); }
                            } else {
                                let #bytes_chunk = #chunk_type_expr::new();
                                unsafe { d.extend_from_slice(#bytes_chunk.as_slice()).unwrap_unchecked(); }
                            }
                        }
                        core::hint::black_box(#dec_fn::<#chunk_size>(#iv, &mut #bytes));
                    }
                });
            }
            _ => {
                let chunk_type_expr = quote!(#chunk_type_path::<#chunk_size>);
                let storage_ast =
                    (storage_strategy.ast)(&bytes_chunk, &chunk_type_expr, chunk_size, &chunk);

                ts.extend(quote! {
                    {
                        #storage_ast
                        #dec_call
                        unsafe { #bytes.extend_from_slice(#bytes_chunk.as_slice()).unwrap_unchecked(); }
                        drop(#bytes_chunk);
                    }
                });
            }
        }

        ts.extend(quote! {
            if let Some(&_last_byte) = #bytes.as_slice().last() {
                #ghost_state = #ghost_state.wrapping_add(_last_byte);
            }
        });

        if random_range(0..10) == 0 {
            let fake_iv: u8 = random();
            let fake_key: u64 = random();
            let fake_chunk_size = random_range(4..16_usize);
            let mut fake_chunk: Vec<u8> = (0..fake_chunk_size).map(|_| random::<u8>()).collect();
            let fake_bytes_chunk = format_ident!("__chunk_f_{id}_{i}");

            let mut fake_ops_pool: Vec<Crypto> = PRIMITIVES
                .iter()
                .filter(|op| (op.support)(fake_chunk_size) && op.latency <= max_latency)
                .cloned()
                .collect();

            shuffle(&mut fake_ops_pool);
            let fake_ops_count = random_range(1..3_usize).min(fake_ops_pool.len());
            let fake_ops: Vec<Crypto> = fake_ops_pool.into_iter().take(fake_ops_count).collect();

            for op in &fake_ops {
                (op.enc)(&mut fake_chunk, fake_key, fake_iv);
            }

            let mut fake_dec_call = TokenStream2::new();
            for op in fake_ops.iter().rev() {
                let dec_ts = (op.dec)(&fake_bytes_chunk, fake_key, fake_iv);
                fake_dec_call.extend(dec_ts);
            }

            let fake_storage_strategy =
                available_storages[random_range(0..available_storages.len())].clone();
            let fake_chunk_type_expr = quote!(#chunk_type_path::<#fake_chunk_size>);
            let fake_storage_ast = (fake_storage_strategy.ast)(
                &fake_bytes_chunk,
                &fake_chunk_type_expr,
                fake_chunk_size,
                &fake_chunk,
            );

            let junk_core = quote! {
                #fake_storage_ast
                #fake_dec_call
                #ghost_state ^= ::obfstr2::crypto::base::mix64(#fake_bytes_chunk[#fake_chunk_size / 2] as u64) as u8;
                ::core::hint::black_box(#fake_bytes_chunk);
            };

            let junk_ast = match random_range(0..4) {
                0 => quote! {
                    if (::core::hint::black_box(#fake_key as u64) % 2) == (#fake_key as u64 % 2) {
                        #junk_core
                    }
                },
                1 => quote! {
                    let mut _fake_iter = 0;
                    while _fake_iter < 1 {
                        #junk_core
                        _fake_iter += ::core::hint::black_box(1);
                    }
                },
                2 => quote! {
                    if #ghost_state > ::core::hint::black_box(1) {
                        #junk_core
                    } else {
                        #junk_core
                    }
                },
                _ => quote! {
                    { #junk_core }
                },
            };

            ts.extend(junk_ast);
        }
    }

    quote! {
        {
            #ts
            ::core::hint::black_box(#ghost_state);
            #bytes
        }
    }
}

pub fn b1(input: Vec<u8>) -> TokenStream2 {
    build_obfuscated_bytes(
        input, 30, 0, 1, false, // nostd可用
        true,
    )
}

pub fn b2(input: Vec<u8>) -> TokenStream2 {
    build_obfuscated_bytes(
        input,
        100,
        50,
        2,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc") && random(),
    )
}

pub fn b3(input: Vec<u8>) -> TokenStream2 {
    build_obfuscated_bytes(
        input,
        100,
        95,
        4,
        cfg!(feature = "alloc"),
        cfg!(feature = "alloc"),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use lib_unknown::dyntest::{DnyRun, clear_dny_project, dny_run};
    #[test]
    fn test1() {
        let input = vec![9_u8; 1024];
        let ts = b1(input);
        println!("{}", ts);
    }

    // debug
    fn run_test(f: fn(Vec<u8>) -> TokenStream2, tag: &str) {
        let x = random_range(20..127) as u8;
        let input = vec![x; 1024];
        let ts = f(input);

        let code = format!(
            "fn main() {{ let x = {}; for x in &*x {{ print!(\"{{}}\", *x as char) }} }}",
            ts
        );

        println!("[{tag}] size: {}\n{:.128}...", code.len(), code);
        let deps = "obfstr2 = { path = \"../../../../../obfstr2\"} ".to_string();
        let ret = dny_run(code.as_str(), deps.as_str(), None, false);
        println!("{ret}");

        assert!(ret.stderr.is_empty());

        assert_eq!(ret.stdout.len(), 1024);

        let target_char = x as char;
        assert!(
            ret.stdout.chars().all(|c| c == target_char),
            "解码数据错误！"
        );
    }

    #[test]
    fn test_b1() {
        // [b1] size: 39632
        // fn main() { let x = { let mut __bytes_15280672320692049431 = :: obfstr :: types :: bytes :: HeapBytes :: < 1024usize > :: new ()...
        // === [Result: SUCCESS] ===
        // > Build: 3.438274697s | Run: 730.881µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH ... [单行超长截断] ... HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
        // ==========================
        run_test(b1, "b1");
    }
    #[test]
    fn test_b2() {
        // [b2] size: 49958
        // fn main() { let x = { let mut __bytes_11790621254148289636 = :: obfstr :: types :: bytes :: StackBytes :: < 1024usize > :: new (...
        // === [Result: SUCCESS] ===
        // > Build: 3.272137787s | Run: 2.6597ms
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd ... [单行超长截断] ... dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
        // ==========================
        run_test(b2, "b2");
    }
    #[test]
    fn test_b3() {
        // [b3] size: 76198
        // fn main() { let x = { let mut __bytes_12085379065007848602 = :: obfstr :: types :: bytes :: StackBytes :: < 1024usize > :: new (...
        // === [Result: SUCCESS] ===
        // > Build: 5.201673531s | Run: 4.18119ms
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ... [单行超长截断] ... ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // ==========================
        run_test(b3, "b3");
    }
    #[test]
    fn test_casual_x_obfstr() {
        // [https://crates.io/crates/obfstr] size: 1104
        // fn main() { print!("{}", std::str::from_utf8(obfstr::obfbytes!(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...
        // === [Result: SUCCESS] ===
        // > Build: 1.287872124s | Run: 669.795µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ... [单行超长截断] ... aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        // ==========================
        let input = String::from_utf8(vec![97; 1024]).unwrap();
        let code = format!(
            "fn main() {{ print!(\"{{}}\", std::str::from_utf8(obfstr::obfbytes!(b\"{input}\")).unwrap()) }}",
        );
        let deps = r#"obfstr = "0.4.6""#;
        println!(
            "[https://crates.io/crates/obfstr] size: {}\n{:.128}...",
            code.len(),
            code
        );

        let ret = dny_run(code.as_str(), deps, None, false);
        println!("{ret}");

        assert!(ret.stderr.is_empty());
        assert!(ret.stdout.chars().all(|c| c == 'a'));
        assert!(!ret.stdout.is_empty());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn test_nostd(call: &str, assert: (char, usize), tag: &str, source: &str) {
        let template = r#"
#![no_std]
#![no_main]
#![allow(binary_asm_labels)]
#![allow(unused)]
#![allow(unsafe_code)]
#![cfg(not(test))]

use core::arch::asm;
use core::{panic};

#[panic_handler]
fn panic(_: &panic::PanicInfo) -> ! {
    sys_exit(101)
}

pub mod constants {
    pub const WRITE: usize = 1;
    pub const EXIT: usize  = 60;
}

#[inline(always)]
pub unsafe fn syscall1(n: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
        "syscall",
        in("rax") n,
        in("rdi") a1,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;

    unsafe {
        asm!(
        "syscall",
        in("rax") n,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack)
        );
    }
    ret
}

#[inline(always)]
pub fn sys_exit(status: usize) -> ! {
    unsafe { syscall1(constants::EXIT, status); }
    loop {}
}

#[inline(always)]
pub fn sys_write(fd: usize, buf: &[u8]) -> isize {
    unsafe { syscall3(constants::WRITE, fd, buf.as_ptr() as usize, buf.len()) }
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "xor rbp, rbp",
        "and rsp, -16",
        "call {f}",
        "mov rdi, rax",
        "call {exit}",
        f = sym main,
        exit = sym sys_exit,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}


fn main() -> usize {
    let bytes = [[bytes]];
    sys_write(1, &*bytes);
    0
}

"#;
        let input = String::from_utf8(vec![97; 1024]).unwrap();
        let code = template.replace("[[bytes]]", call);
        let deps = source;
        println!("[{tag}] Code size: {}\n{:.128}...", code.len(), code);

        let mut runner = DnyRun::new(&code, deps);
        runner.release(true);
        runner.cargo_config(
            r#"
[build]
target = "x86_64-unknown-none"

[target.x86_64-unknown-none]
rustflags = [
    "-C", "panic=abort",
    "-C", "opt-level=z",
    "-C", "relocation-model=static",
    "-C", "link-arg=--gc-sections",
]
"#,
        );
        let ret = runner.run(None);
        println!("{ret}");

        assert!(ret.stderr.is_empty());
        assert_eq!(ret.stdout.len(), assert.1, "输出长度不符合预期");
        assert!(
            ret.stdout.chars().all(|c| c == assert.0),
            "解码数据错误，不全为预期的字符!"
        );
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_b1_nostd() {
        // [b1_nostd] Code size: 41227
        //
        // #![no_std]
        // #![no_main]
        // #![allow(binary_asm_labels)]
        // #![allow(unused)]
        // #![allow(unsafe_code)]
        // #![cfg(not(test))]
        //
        // use core::arch...
        // === [Result: SUCCESS] ===
        // > Build: 2.921353266s | Run: 198.72µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ... [单行超长截断] ... aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        // ==========================
        let input = vec![97_u8; 1024]; // 97 对应 'a'
        let ts = b1(input);

        test_nostd(
            &ts.to_string(),
            ('a', 1024),
            "b1_nostd",
            "obfstr2 = { path = \"../../../../../obfstr2\" , default-features = false }",
        );
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_b2_nostd() {
        // [b2_nostd] Code size: 52218
        //
        // #![no_std]
        // #![no_main]
        // #![allow(binary_asm_labels)]
        // #![allow(unused)]
        // #![allow(unsafe_code)]
        // #![cfg(not(test))]
        //
        // use core::arch...
        // === [Result: SUCCESS] ===
        // > Build: 2.915866741s | Run: 382.805µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ... [单行超长截断] ... aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        // ==========================

        let input = vec![97_u8; 1024]; // 97 对应 'a'
        let ts = build_obfuscated_bytes(input, 100, 50, 2, false, true);

        test_nostd(
            &ts.to_string(),
            ('a', 1024),
            "b2_nostd",
            "obfstr2 = { path = \"../../../../../obfstr2\" , default-features = false }",
        );
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_b3_nostd() {
        // [b3_nostd] Code size: 75692
        //
        // #![no_std]
        // #![no_main]
        // #![allow(binary_asm_labels)]
        // #![allow(unused)]
        // #![allow(unsafe_code)]
        // #![cfg(not(test))]
        //
        // use core::arch...
        // === [Result: SUCCESS] ===
        // > Build: 3.292512812s | Run: 667.549µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ... [单行超长截断] ... aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        // ==========================
        let input = vec![97_u8; 1024]; // 97 对应 'a'
        let ts = build_obfuscated_bytes(input, 100, 95, 4, false, true);

        test_nostd(
            &ts.to_string(),
            ('a', 1024),
            "b3_nostd",
            "obfstr2 = { path = \"../../../../../obfstr2\" , default-features = false }",
        );
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn test_casual_x_obfstr_nostd() {
        // [https://github.com/CasualX/obfstr.git] Code size: 2751
        //
        // #![no_std]
        // #![no_main]
        // #![allow(binary_asm_labels)]
        // #![allow(unused)]
        // #![allow(unsafe_code)]
        // #![cfg(not(test))]
        //
        // use core::arch...
        // === [Result: SUCCESS] ===
        // > Build: 1.305794816s | Run: 684.698µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ... [单行超长截断] ... aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        // ==========================

        // __int64 __fastcall RNvCsjHZ874GpTPu_39dyn_test_1789194880555402510_23392582094main(__int64 a1, __int64 a2, __int64 a3)
        // {
        //   __int64 v3; // rdx
        //   unsigned __int64 v4; // rsi
        //   _DWORD *v5; // rdi
        //   __int64 i; // rcx
        //   _QWORD v8[128]; // [rsp+8h] [rbp-800h] BYREF
        //   char buf[1024]; // [rsp+408h] [rbp-400h] BYREF
        //
        //   v8[0] = (char *)&RNvNvCsjHZ874GpTPu_39dyn_test_1789194880555402510_23392582094main15__OBFBYTES_SDATA - 26456;
        //   LODWORD(v8[0]) = -207411036;
        //   v3 = RINvNtCs228yPdDHRh6_6obfstr4xref5innerKy6783d858e948a41_ECsjHZ874GpTPu_39dyn_test_1789194880555402510_2339258209(
        //          a1: (char *)&RNvNvCsjHZ874GpTPu_39dyn_test_1789194880555402510_23392582094main15__OBFBYTES_SDATA - 26456,
        //          a2: 4087556260LL,
        //          a3,
        //          a4: v8);
        //   v4 = 0;
        //   v5 = v8;
        //   for ( i = 256; i != 0; --i )
        //     *v5++ = 0;
        //   while ( v4 <= 0x3FF )
        //   {
        //     v8[v4 / 8] = *(_QWORD *)(v3 + v4) + qword_200158[v4 / 8];
        //     v4 += 8LL;
        //   }
        //   qmemcpy(buf, v8, sizeof(buf));
        //   sys_write(1u, buf, 0x400u);
        //   return 0;
        // }
        // __int64 __fastcall RINvNtCs228yPdDHRh6_6obfstr4xref5innerKy6783d858e948a41_ECsjHZ874GpTPu_39dyn_test_1789194880555402510_2339258209(
        //         __int64 a1,
        //         unsigned int a2)
        // {
        //   int v2; // ecx
        //   int i; // edx
        //
        //   v2 = -2091773722;
        //   for ( i = 0; ; v2 ^= i )
        //   {
        //     switch ( v2 )
        //     {
        //       case -2091773722:
        //         a2 = -a2;
        //         i = 1498102796;
        //         continue;
        //       case -635884310:
        //         a2 += 904870607;
        //         i = -1729995644;
        //         continue;
        //       case 1123774574:
        //         a2 ^= __ROL4__(a2, 6);
        //         i = 885028024;
        //         continue;
        //       case 1948647596:
        //         a2 ^= a2 >> 23;
        //         i = 736261398;
        //         continue;
        //       case 1983579350:
        //         a2 = -a2;
        //         i = 35456122;
        //         continue;
        //       default:
        //         break;
        //     }
        //     if ( v2 == 1606710714 )
        //       break;
        //   }
        //   return (unsigned __int16)a2 + a1;
        // }
        let input = String::from_utf8(vec![97; 1024]).unwrap();

        let ts = format!("obfstr::obfbytes!(b\"{}\")", input);

        test_nostd(
            &ts,
            ('a', 1024),
            "https://github.com/CasualX/obfstr.git",
            "obfstr = \"0.4\"",
        );
    }

    #[test]
    fn clear() {
        clear_dny_project(None);
    }
}
