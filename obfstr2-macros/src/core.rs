//! 混淆编排核心：分块 → 加密 → 存储 → 发射（`build_obfuscated_bytes`）。
//!
//! 新内核：`LayerCtx` 自报告长度；`dec` 为 SSA 式
//! `(AST, Ident_out)`，框架只做 fold 串联；失败显式 `Result` 上抛。

use crate::crypto::{Crypto, LayerCtx, PRIMITIVES};
use crate::storage::{STORAGE_STRATEGIES, Storage};
use lib_unknown::rand::{random, random_range, shuffle};
use proc_macro2::{Ident as Ident2, TokenStream as TokenStream2};
use quote::{format_ident, quote};

pub(crate) const STACK_BUDGET: usize = 1024;

fn available_crypto(chunk_size: usize, max_latency: u8) -> Vec<Crypto> {
    PRIMITIVES
        .iter()
        .filter(|op| (op.support)(chunk_size) && op.latency <= max_latency)
        .cloned()
        .collect()
}

fn available_storage(chunk_size: usize, max_latency: u8) -> Vec<Storage> {
    STORAGE_STRATEGIES
        .iter()
        .filter(|s| (s.support)(chunk_size) && s.latency <= max_latency)
        .cloned()
        .collect()
}

/// 单层快照：`enc` 执行后立即冻结关键字段，供逆序 `dec` 使用。
pub(crate) struct LayerRecord {
    pub(crate) crypto: Crypto,
    pub(crate) key: u64,
    pub(crate) iv: u8,
    pub(crate) pt_len: usize,
    pub(crate) ct_len: usize,
}

/// 逆序解密 fold：`(AST, Ident_out) = dec(ctx, Ident_in)` 串联。
fn build_dec2(
    layers: &[LayerRecord],
    family: &TokenStream2,
    entry: Ident2,
    tag_prefix: &str,
) -> (TokenStream2, Ident2) {
    layers.iter().rev().enumerate().fold(
        (TokenStream2::new(), entry),
        |(mut ts, ident), (rev_pos, layer)| {
            let enc_idx = layers.len() - 1 - rev_pos;
            let ctx = LayerCtx {
                type_path: family.clone(),
                key: layer.key,
                iv: layer.iv,
                in_size: layer.pt_len,
                out_size: layer.ct_len,
                ident_tag: format!("{tag_prefix}_{enc_idx}"),
            };
            let (frag, next_ident) = (layer.crypto.dec)(&ctx, ident);
            ts.extend(frag);
            (ts, next_ident)
        },
    )
}

/// 强度档位公共参数（延迟上限 / 组合安全度下限 / 原语叠加倍率）。
///
/// `allow_heap` / `stack_main_bytes` 与档位正交（`no_std` 可用性与主容器策略），保留在调用点，不进表。
#[derive(Clone, Copy)]
pub(crate) struct TierParams {
    pub(crate) max_latency: u8,
    pub(crate) min_security: u8,
    pub(crate) magnification: u8,
    /// 垃圾块填充概率（本阶段重构暂不使用）。
    #[allow(dead_code)]
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
) -> Result<TokenStream2, String> {
    let size = input.len();
    let id: u64 = random();

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut i = 1;

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

    for (i, chunk) in (1..).zip(chunks) {
        let bytes_chunk = format_ident!("__bytes_chunk_{id}_{i}");
        let pt_len = chunk.len();

        let mut data = chunk;
        let op_count = random_range(1..3_u8).wrapping_mul(tier.magnification.max(1)) as usize;
        let mut layers: Vec<LayerRecord> = Vec::new();
        let mut combined_vulnerability = 1.0_f64;
        let mut current_combined_security = 0_u8;
        while layers.len() < op_count || current_combined_security < tier.min_security {
            let mut pool = available_crypto(data.len(), tier.max_latency);
            if pool.is_empty() {
                break;
            }
            shuffle(&mut pool);
            let Some(crypto) = pool.pop() else { break };
            let in_len = data.len();
            let (key, iv) = (random::<u64>(), random::<u8>());
            // enc 期间 type_path/ident_tag 无意义（enc 从不读它们），填空即可；
            // dec 时由 build_dec2 重填家族与确定性后缀。
            let mut ctx = LayerCtx {
                type_path: TokenStream2::new(),
                key,
                iv,
                in_size: in_len,
                out_size: in_len,
                ident_tag: String::new(),
            };
            data = (crypto.enc)(&mut ctx, data);
            if ctx.out_size != data.len() {
                return Err(format!(
                    "chunk#{i} 层#{} 原语自报告长度 {}B 与实际输出 {}B 不一致",
                    layers.len(),
                    ctx.out_size,
                    data.len()
                ));
            }
            let out_len = data.len();
            let vulnerability = (100.0 - crypto.security as f64) / 100.0;
            combined_vulnerability *= vulnerability;
            current_combined_security = (100.0 * (1.0 - combined_vulnerability)) as u8;
            layers.push(LayerRecord {
                crypto,
                key,
                iv,
                pt_len: in_len,
                ct_len: out_len,
            });
        }
        let ciphertext = data;
        let ct_len = ciphertext.len();
        // 本 chunk 所需中间容器的峰值（各层输入/输出；空轨迹时回退明文长）。
        let peak = layers
            .iter()
            .flat_map(|l| [l.pt_len, l.ct_len])
            .max()
            .unwrap_or(pt_len)
            .max(pt_len)
            .max(1);

        let use_heap_chunk = if peak > STACK_BUDGET {
            if allow_heap {
                true
            } else {
                return Err(format!(
                    "chunk#{i} 需要 {peak}B 中间容器，超过纯栈上限 {STACK_BUDGET}B 且无堆可用"
                ));
            }
        } else if peak <= 32 {
            false
        } else {
            allow_heap && random::<bool>()
        };
        let chunk_type_path = if use_heap_chunk {
            quote!(::obfstr2::types::bytes::HeapBytes)
        } else {
            quote!(::obfstr2::types::bytes::StackBytes)
        };
        let pool = available_storage(ct_len, tier.max_latency);
        if pool.is_empty() {
            return Err(format!(
                "chunk#{i} 密文 {ct_len}B 在延迟上限 {} 下无可用存储策略",
                tier.max_latency
            ));
        }
        let mut pool = pool;
        let storage_strategy = pool.swap_remove(random_range(0..pool.len()));

        // 空轨迹（首轮即无可用原语）无解密可做，强制内联直写，跳过 dec_fn 包装。
        let mode = if layers.is_empty() {
            2
        } else {
            random_range(0..3)
        };
        match mode {
            0 => {
                let dec_fn = format_ident!("__dec_fn_{id}_{i}");
                let storage_expr = quote!(#chunk_type_path::<#ct_len>);
                let ret_expr = quote!(#chunk_type_path::<#pt_len>);
                let storage_ast =
                    (storage_strategy.ast)(&bytes_chunk, &storage_expr, ct_len, &ciphertext);
                let (dec_ts, final_ident) = build_dec2(
                    &layers,
                    &chunk_type_path,
                    bytes_chunk.clone(),
                    &format!("{id}_{i}"),
                );
                let first_iv = layers.first().map(|l| l.iv).unwrap_or(0u8);

                ts.extend(quote! {
                    {
                        #[cold]
                        #[inline(never)]
                        fn #dec_fn(x: u8) -> #ret_expr {
                            // 调用方恒传 first_iv，恒走真分支；else 仅为反静态分析的死分支（空 extend 是 no-op）。
                            if core::hint::black_box(x) ^ core::hint::black_box(#first_iv) == 0 {
                                #storage_ast
                                #dec_ts
                                core::hint::black_box(#final_ident)
                            } else {
                                #ret_expr::new()
                            }
                        }
                        unsafe { #bytes.extend_from_slice(#dec_fn(#first_iv).as_slice()).unwrap_unchecked(); }
                    }
                });
            }
            1 => {
                let dec_fn = format_ident!("__dec_fn_{id}_{i}");
                let storage_expr = quote!(#chunk_type_path::<#ct_len>);
                let ret_expr = quote!(#chunk_type_path::<#pt_len>);
                let storage_ast =
                    (storage_strategy.ast)(&bytes_chunk, &storage_expr, ct_len, &ciphertext);
                let (dec_ts, final_ident) = build_dec2(
                    &layers,
                    &chunk_type_path,
                    bytes_chunk.clone(),
                    &format!("{id}_{i}"),
                );
                let first_iv = layers.first().map(|l| l.iv).unwrap_or(0u8);

                ts.extend(quote! {
                    {
                        #[cold]
                        #[inline(never)]
                        fn #dec_fn(x: u8, d: &mut #main_type_path<#size>) {
                            // 调用方恒传 first_iv，恒走真分支；else 仅为反静态分析的死分支（空 extend 是 no-op）。
                            if core::hint::black_box(x) ^ core::hint::black_box(#first_iv) == 0 {
                                #storage_ast
                                #dec_ts
                                unsafe { d.extend_from_slice(#final_ident.as_slice()).unwrap_unchecked(); }
                            } else {
                                let #bytes_chunk = #ret_expr::new();
                                unsafe { d.extend_from_slice(#bytes_chunk.as_slice()).unwrap_unchecked(); }
                            }
                        }
                        core::hint::black_box(#dec_fn(#first_iv, &mut #bytes));
                    }
                });
            }
            _ => {
                let storage_expr = quote!(#chunk_type_path::<#ct_len>);
                let storage_ast =
                    (storage_strategy.ast)(&bytes_chunk, &storage_expr, ct_len, &ciphertext);
                let (dec_ts, final_ident) = build_dec2(
                    &layers,
                    &chunk_type_path,
                    bytes_chunk.clone(),
                    &format!("{id}_{i}"),
                );

                ts.extend(quote! {
                    {
                        #storage_ast
                        #dec_ts
                        unsafe { #bytes.extend_from_slice(#final_ident.as_slice()).unwrap_unchecked(); }
                        drop(#final_ident);
                    }
                });
            }
        }

        // ghost 最小使用：防 DCE 的单调累加，不含 junk 干扰。
        ts.extend(quote! {
            if let Some(&_last_byte) = #bytes.as_slice().last() {
                #ghost_state = #ghost_state.wrapping_add(_last_byte);
            }
        });
    }

    Ok(quote! {
        {
            #ts
            ::core::hint::black_box(#ghost_state);
            #bytes
        }
    })
}
