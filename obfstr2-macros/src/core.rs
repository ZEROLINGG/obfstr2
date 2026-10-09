//! 混淆编排核心：分块 → 加密 → 存储 → 发射（`build_obfuscated_bytes`）。
//!
//! 从 `bytes.rs` 拆分而来：注册表见 `crate::crypto` / `crate::storage`，
//! 本文件只保留流程编排与档位无关的公共 helper。

use crate::crypto::{Crypto, PRIMITIVES};
use crate::storage::{STORAGE_STRATEGIES, Storage};
use lib_unknown::rand::{random, random_range, shuffle};
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};

/// 按 `chunk_size` 与 `max_latency` 过滤出可用的加密原语。
fn available_crypto(chunk_size: usize, max_latency: u8) -> Vec<Crypto> {
    PRIMITIVES
        .iter()
        .filter(|op| (op.support)(chunk_size) && op.latency <= max_latency)
        .cloned()
        .collect()
}

/// 按 `chunk_size` 与 `max_latency` 过滤出可用的存储策略。
fn available_storage(chunk_size: usize, max_latency: u8) -> Vec<Storage> {
    STORAGE_STRATEGIES
        .iter()
        .filter(|s| (s.support)(chunk_size) && s.latency <= max_latency)
        .cloned()
        .collect()
}

/// 选取存储策略：过滤为空时回退到首项（`static &[u8]`，恒可用），避免 1B 小 chunk panic。
fn pick_storage(chunk_size: usize, max_latency: u8) -> Storage {
    let mut pool = available_storage(chunk_size, max_latency);
    if pool.is_empty() {
        return STORAGE_STRATEGIES[0].clone();
    }
    pool.swap_remove(random_range(0..pool.len()))
}

/// 按 `fake_chunk_size` 重过滤的垃圾块存储策略（不复用真 chunk 的池，避免语义错配）。
fn pick_fake_storage(fake_chunk_size: usize, max_latency: u8) -> Storage {
    pick_storage(fake_chunk_size, max_latency)
}

/// 主流程的原语叠加选择：随机 `1~3 × magnification` 个起步，
/// 组合安全度（`1 - Π(1 - security)`）达标即停，上限 16 层。
fn select_stacked_ops(
    chunk_size: usize,
    max_latency: u8,
    min_combined_security: u8,
    magnification: u8,
) -> Vec<Crypto> {
    let mut pool = available_crypto(chunk_size, max_latency);
    if pool.is_empty() {
        return Vec::new();
    }
    let op_count = random_range(1..3_u8).wrapping_mul(magnification.max(1)) as usize;
    let mut ops = Vec::new();
    let mut combined_vulnerability = 1.0_f64;
    let mut current_combined_security = 0_u8;
    while ops.len() < op_count || current_combined_security < min_combined_security {
        shuffle(&mut pool);
        let chosen = pool[0].clone();
        let vulnerability = (100.0 - chosen.security as f64) / 100.0;
        combined_vulnerability *= vulnerability;
        current_combined_security = (100.0 * (1.0 - combined_vulnerability)) as u8;
        ops.push(chosen);
        if ops.len() > 16 {
            break;
        }
    }
    ops
}

/// 垃圾块用的轻量选择：同一过滤入口，随机洗牌后取 1~2 个。
/// 与主流程共用 `available_crypto`，避免过滤逻辑重复。
fn select_junk_ops(chunk_size: usize, max_latency: u8) -> Vec<Crypto> {
    let mut pool = available_crypto(chunk_size, max_latency);
    shuffle(&mut pool);
    let n = random_range(1..3_usize).min(pool.len());
    pool.into_iter().take(n).collect()
}

/// 强度档位公共参数（延迟上限 / 组合安全度下限 / 原语叠加倍率）。
///
/// `allow_heap` / `stack_main_bytes` 与档位正交（`no_std` 可用性与主容器策略），保留在调用点，不进表。
#[derive(Clone, Copy)]
pub(crate) struct TierParams {
    pub(crate) max_latency: u8,
    pub(crate) min_security: u8,
    pub(crate) magnification: u8,
    /// 垃圾块填充概率（0~100，百分比；按 chunk 掷骰；超出 100 视为恒插）。
    pub(crate) junk_pct: u8,
}

/// 低延迟档（`s1` / `b1` / `i1` / `fl1` / `cs1`）：纯栈，`no_std` 可用。
pub(crate) const TIER_LOW: TierParams = TierParams {
    max_latency: 30,
    min_security: 0,
    magnification: 1,
    junk_pct: 5,
};

/// 均衡档（`s2` / `b2` / `i2` / `fl2` / `cs2`）：堆栈随机。
pub(crate) const TIER_BALANCED: TierParams = TierParams {
    max_latency: 100,
    min_security: 50,
    magnification: 2,
    junk_pct: 20,
};

/// 高强度档（`s3` / `b3` / `i3` / `fl3` / `cs3`）：`alloc` 下主容器走堆。
pub(crate) const TIER_HIGH: TierParams = TierParams {
    max_latency: 100,
    min_security: 95,
    magnification: 4,
    junk_pct: 40,
};

pub(crate) fn build_obfuscated_bytes(
    mut input: Vec<u8>,
    tier: TierParams,
    allow_heap: bool,
    stack_main_bytes: bool,
) -> TokenStream2 {
    let size = input.len();
    let id: u64 = random();

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

        let ops = select_stacked_ops(
            chunk_size,
            tier.max_latency,
            tier.min_security,
            tier.magnification,
        );

        // 执行加密并叠加
        for op in &ops {
            (op.enc)(&mut chunk, key, iv);
        }

        let mut dec_call = TokenStream2::new();
        for op in ops.iter().rev() {
            let dec_ts = (op.dec)(&bytes_chunk, key, iv);
            dec_call.extend(dec_ts);
        }

        let storage_strategy = pick_storage(chunk_size, tier.max_latency);

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

        if random_range(0..100_u8) < tier.junk_pct {
            let fake_iv: u8 = random();
            let fake_key: u64 = random();
            let fake_chunk_size = random_range(4..16_usize);
            let mut fake_chunk: Vec<u8> = (0..fake_chunk_size).map(|_| random::<u8>()).collect();
            let fake_bytes_chunk = format_ident!("__chunk_f_{id}_{i}");

            let fake_ops = select_junk_ops(fake_chunk_size, tier.max_latency);

            for op in &fake_ops {
                (op.enc)(&mut fake_chunk, fake_key, fake_iv);
            }

            let mut fake_dec_call = TokenStream2::new();
            for op in fake_ops.iter().rev() {
                let dec_ts = (op.dec)(&fake_bytes_chunk, fake_key, fake_iv);
                fake_dec_call.extend(dec_ts);
            }

            let fake_storage_strategy = pick_fake_storage(fake_chunk_size, tier.max_latency);
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
