//! 混淆编排核心：分块 → 加密 → 存储 → 发射（`build_obfuscated_bytes`）。
//!
//! 新内核：`LayerCtx` 自报告长度；`dec` 为 SSA 式
//! `(AST, Ident_out)`，框架只做 fold 串联；失败显式 `Result` 上抛。

use crate::crypto::CRYPTOS;
use crate::crypto::{Crypto, LayerCtx};
use crate::storage::{STORAGES, Storage};
use lib_unknown::rand::{random, random_range, shuffle};
use proc_macro2::{Ident as Ident2, TokenStream as TokenStream2};
use quote::{format_ident, quote};

pub(crate) const STACK_BUDGET: usize = 1024;

fn available_crypto(chunk_size: usize, max_latency: u8) -> Vec<Crypto> {
    CRYPTOS
        .iter()
        .filter(|op| (op.support)(chunk_size) && op.latency <= max_latency)
        .cloned()
        .collect()
}

fn available_storage(chunk_size: usize, max_latency: u8) -> Vec<Storage> {
    STORAGES
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

/// 加密选层：随机 `1~3 × magnification` 个起步，组合安全度
/// （`1 - Π(1 - security)`）达标即停；真 chunk 与垃圾块共用，保证过滤口径一致。
///
/// 返回 `(密文, 层快照)`；原语自报告长度与实际输出不一致时返回 `Err`。
/// `chunk_tag` 仅用于错误定位（如 `"chunk#3"` / `"junk#3"`）。
fn encrypt_layers(
    data: Vec<u8>,
    tier: TierParams,
    chunk_tag: &str,
) -> Result<(Vec<u8>, Vec<LayerRecord>), String> {
    let mut data = data;
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
        // dec 时由 build_dec_layers 重填家族与确定性后缀。
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
                "{chunk_tag} 层#{} 原语自报告长度 {}B 与实际输出 {}B 不一致",
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
    Ok((data, layers))
}

/// 逆序解密 fold：`(AST, Ident_out) = dec(ctx, Ident_in)` 串联。
///
/// 每层按档位概率抛硬币：包装层发射统一签名
/// `#[cold]#[inline(never)] fn __dec_layer_{tag}(mut enc: Family<CT>) -> Family<PT>`，
/// 等长/变长不分支（变长多余的 `mut` 由 `allow(unused_mut)` 消化）；
/// 外层以 `__v_{tag}` 承接返回值，避免函数名被 `let` 遮蔽。
/// 包装层附带 `black_box(f) as usize` 显式消费函数地址（`allow(function_casts_as_integer)`）。
/// 档位概率的单调 backpressure：`eff = base * (1 + base/100)^inline_count`，封顶 100。
///
/// `inline_count` 为本次宏展开累计内联层数（只增不减，跨 chunk 传递）；
/// 大载荷下内联越多、后续包装概率越高，避免调用方函数体线性膨胀拖慢编译。
/// `base == 0` 恒内联；`inline_count >= 64` 直接封顶（防 `powi` 上溢到 `inf`）。
fn effective_wrap_pct(base: u8, inline_count: u32) -> u8 {
    if base == 0 {
        return 0;
    }
    if inline_count >= 64 {
        return 100;
    }
    (base as f64 * (1.0 + base as f64 / 100.0).powi(inline_count as i32)).min(100.0) as u8
}

fn build_dec_layers(
    layers: &[LayerRecord],
    family: &TokenStream2,
    entry: Ident2,
    tag_prefix: &str,
    wrap_pct: u8,
    inline_count: &mut u32,
) -> (TokenStream2, TokenStream2, Ident2) {
    let mut prelude = TokenStream2::new();
    let mut body = TokenStream2::new();
    let mut cur = entry;
    for (rev_pos, layer) in layers.iter().rev().enumerate() {
        let enc_idx = layers.len() - 1 - rev_pos;
        let tag = format!("{tag_prefix}_{enc_idx}");
        let ct = layer.ct_len;
        let pt = layer.pt_len;
        // 档位控制的非内联概率 + 单调累积：0=全内联，>=100=全包装。
        let wrap = random_range(0..100u8) < effective_wrap_pct(wrap_pct, *inline_count);
        if wrap {
            let dec_fn = format_ident!("__dec_layer_{tag}");
            let val = format_ident!("__v_{tag}");
            let param = format_ident!("enc");
            let ctx = LayerCtx {
                type_path: family.clone(),
                key: layer.key,
                iv: layer.iv,
                in_size: layer.pt_len,
                out_size: layer.ct_len,
                ident_tag: tag.clone(),
            };
            let (frag, next_ident) = (layer.crypto.dec)(&ctx, param);
            let in_ty = quote!(#family<#ct>);
            let out_ty = quote!(#family<#pt>);
            prelude.extend(quote! {
                #[cold]
                #[inline(never)]
                #[allow(unused_mut)]
                fn #dec_fn(mut enc: #in_ty) -> #out_ty {
                    #frag
                    ::core::hint::black_box(#next_ident)
                }
            });
            body.extend(quote! {
                #[allow(function_casts_as_integer)]
                let _ = ::core::hint::black_box(#dec_fn) as usize;
                let mut #val = #dec_fn(#cur);
            });
            cur = val;
        } else {
            let ctx = LayerCtx {
                type_path: family.clone(),
                key: layer.key,
                iv: layer.iv,
                in_size: layer.pt_len,
                out_size: layer.ct_len,
                ident_tag: tag,
            };
            let (frag, next_ident) = (layer.crypto.dec)(&ctx, cur);
            body.extend(frag);
            cur = next_ident;
            *inline_count += 1;
        }
    }
    (prelude, body, cur)
}

/// 强度档位公共参数（延迟上限 / 组合安全度下限 / 原语叠加倍率 / 逐层非内联包装概率）。
#[derive(Clone, Copy)]
pub(crate) struct TierParams {
    pub(crate) max_latency: u8,
    pub(crate) min_security: u8,
    pub(crate) magnification: u8,
    /// 逐层 `#[cold]#[inline(never)]` 包装概率 0..=100（`build_dec_layers` 按层抛硬币）。
    pub(crate) wrap_pct: u8,
    /// 垃圾块填充概率（0~100 百分比；按 chunk 掷骰；超出 100 视为恒插）。
    pub(crate) junk_pct: u8,
}

/// 低延迟档（`s1` / `b1` / `i1` / `fl1` / `cs1`）：纯栈，`no_std` 可用。
pub(crate) const TIER_LOW: TierParams = TierParams {
    max_latency: 20,
    min_security: 0,
    magnification: 1,
    wrap_pct: 15,
    junk_pct: 5,
};

/// 均衡档（`s2` / `b2` / `i2` / `fl2` / `cs2`）：堆栈随机。
pub(crate) const TIER_BALANCED: TierParams = TierParams {
    max_latency: 80,
    min_security: 28,
    magnification: 2,
    wrap_pct: 50,
    junk_pct: 20,
};

/// 高强度档（`s3` / `b3` / `i3` / `fl3` / `cs3`）：`alloc` 下主容器走堆。
pub(crate) const TIER_HIGH: TierParams = TierParams {
    max_latency: 100,
    min_security: 60,
    magnification: 4,
    wrap_pct: 85,
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

    // 单调累积的内联计数：跨 chunk 传递，内联越多后续包装概率越高。
    let mut inline_total: u32 = 0;
    for (i, chunk) in (1..).zip(chunks) {
        let bytes_chunk = format_ident!("__bytes_chunk_{id}_{i}");
        let pt_len = chunk.len();

        let data = chunk;
        let (data, layers) = encrypt_layers(data, tier, &format!("chunk#{i}"))?;
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
        } else if peak <= 16 {
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

        let storage_expr = quote!(#chunk_type_path::<#ct_len>);
        let storage_ast = (storage_strategy.ast)(&bytes_chunk, &storage_expr, ct_len, &ciphertext);
        // 逐层档位概率包装 + 单调 backpressure：内联 frag 与统一签名 fn 混排（空轨迹时 layers 为空，直接直写）。
        let (dec_prelude, dec_body, final_ident) = build_dec_layers(
            &layers,
            &chunk_type_path,
            bytes_chunk.clone(),
            &format!("{id}_{i}"),
            tier.wrap_pct,
            &mut inline_total,
        );

        ts.extend(quote! {
            {
                #storage_ast
                #dec_prelude
                #dec_body
                unsafe { #bytes.extend_from_slice(#final_ident.as_slice()).unwrap_unchecked(); }
                drop(#final_ident);
            }
        });

        // ghost 最小使用：防 DCE 的单调累加；junk 只可读作分支条件，不写入。
        ts.extend(quote! {
            if let Some(&_last_byte) = #bytes.as_slice().last() {
                #ghost_state = #ghost_state.wrapping_add(_last_byte);
            }
        });

        // 垃圾块：与主路径同构（加密选层→存储→解密发射），解出结果只进黑洞，
        // 不并入主容器。假数据长度取真 chunk 明文长的 1/10~全长，容器家族按峰值复用主路径规则；
        // 存储空池 / 超预算无堆时跳过本轮（不报错，避免牵连真 chunk）。
        // ident 用独立 `f` 后缀，内联计数用局部变量，不污染真路径 backpressure。
        if random_range(0..100_u8) < tier.junk_pct {
            let fake_lo = (pt_len / 10).max(1);
            let fake_len = if fake_lo >= pt_len {
                pt_len
            } else {
                random_range(fake_lo..pt_len + 1)
            };
            let fake_data: Vec<u8> = (0..fake_len).map(|_| random::<u8>()).collect();
            let Ok((fake_ciphertext, fake_layers)) =
                encrypt_layers(fake_data, tier, &format!("junk#{i}"))
            else {
                continue;
            };
            let fake_ct_len = fake_ciphertext.len();
            let fake_peak = fake_layers
                .iter()
                .flat_map(|l| [l.pt_len, l.ct_len])
                .max()
                .unwrap_or(fake_len)
                .max(fake_len)
                .max(1);
            let fake_family = if fake_peak > STACK_BUDGET {
                if allow_heap {
                    quote!(::obfstr2::types::bytes::HeapBytes)
                } else {
                    continue;
                }
            } else if fake_peak <= 16 {
                quote!(::obfstr2::types::bytes::StackBytes)
            } else if allow_heap && random::<bool>() {
                quote!(::obfstr2::types::bytes::HeapBytes)
            } else {
                quote!(::obfstr2::types::bytes::StackBytes)
            };
            let fake_pool = available_storage(fake_ct_len, tier.max_latency);
            if fake_pool.is_empty() {
                continue;
            }
            let mut fake_pool = fake_pool;
            let fake_storage_strategy = fake_pool.swap_remove(random_range(0..fake_pool.len()));
            let fake_chunk = format_ident!("__chunk_f_{id}_{i}");
            let fake_storage_expr = quote!(#fake_family::<#fake_ct_len>);
            let fake_storage_ast = (fake_storage_strategy.ast)(
                &fake_chunk,
                &fake_storage_expr,
                fake_ct_len,
                &fake_ciphertext,
            );
            let mut fake_inline: u32 = 0;
            let (fake_prelude, fake_body, fake_final) = build_dec_layers(
                &fake_layers,
                &fake_family,
                fake_chunk.clone(),
                &format!("{id}_{i}f"),
                tier.wrap_pct,
                &mut fake_inline,
            );
            let junk_core = quote! {
                #fake_storage_ast
                #fake_prelude
                #fake_body
                ::core::hint::black_box(#fake_final.as_slice());
                drop(#fake_final);
            };
            let junk_ast = match random_range(0..4_u8) {
                0 => {
                    let fake_key: u64 = random();
                    quote! {
                        if (::core::hint::black_box(#fake_key) % 2) == (#fake_key % 2) {
                            #junk_core
                        }
                    }
                }
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

    Ok(quote! {
        {
            #ts
            ::core::hint::black_box(#ghost_state);
            #bytes
        }
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    #[test]
    fn effective_wrap_pct_starts_at_base() {
        assert_eq!(effective_wrap_pct(15, 0), 15);
        assert_eq!(effective_wrap_pct(50, 0), 50);
        assert_eq!(effective_wrap_pct(85, 0), 85);
        assert_eq!(effective_wrap_pct(0, 999), 0);
    }

    #[test]
    fn effective_wrap_pct_grows_and_caps() {
        // base=50: 50 -> 75 -> 112->100
        assert_eq!(effective_wrap_pct(50, 1), 75);
        assert_eq!(effective_wrap_pct(50, 2), 100);
        // base=85: 一次内联后即封顶
        assert_eq!(effective_wrap_pct(85, 1), 100);
        // 单调不减并封顶
        let mut prev = 0;
        for i in 0..70 {
            let cur = effective_wrap_pct(15, i);
            assert!(cur >= prev, "i={i}: {cur} < {prev}");
            prev = cur;
        }
        assert_eq!(effective_wrap_pct(15, 64), 100);
        assert_eq!(effective_wrap_pct(15, 1000), 100);
    }
}
