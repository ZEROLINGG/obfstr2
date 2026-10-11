//! 多态混淆加解密原语注册表。

use proc_macro2::{Ident as Ident2, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use std::sync::LazyLock;

/// 单层上下文：正反两趟共用同一种结构，`enc` 执行后 `out_size` 即唯一真相。
#[derive(Clone)]
pub(crate) struct LayerCtx {
    /// 容器家族路径（不含泛型，如 `::obfstr2::types::bytes::StackBytes`），
    pub(crate) type_path: TokenStream2,
    pub(crate) key: u64,
    pub(crate) iv: u8,
    /// 本层输入长度（enc 前 / dec 后应恢复到此长度）。
    pub(crate) in_size: usize,
    /// 本层输出长度（enc 后 / dec 前），由 `enc` 自报告写回。
    pub(crate) out_size: usize,
    /// 确定性临时标识后缀（`{macro_id}_{chunk_idx}_{enc_layer_idx}`），
    pub(crate) ident_tag: String,
}

#[derive(Clone)]
pub(crate) struct Crypto {
    /// 正向加密（拥有制）：接管输入容器，返回输出容器，并写回 `ctx.out_size`。
    pub(crate) enc: fn(&mut LayerCtx, Vec<u8>) -> Vec<u8>,
    /// 逆向解密：输入当前 ident，返回 `(解密 AST, 后续应使用的 ident)`。
    pub(crate) dec: fn(&LayerCtx, Ident2) -> (TokenStream2, Ident2),
    // 判断本层输入长度能否运用该操作（按当前 `data.len()` 逐层重估）。
    pub(crate) support: fn(usize) -> bool,
    /// 抗逆向安全性 0～100（抵抗静态分析、符号执行的难度；不是密钥保密时的比特安全）。
    ///
    /// 标尺锚点：裸 XOR = 1，Ascon-128 = 80。本注册表全是 8-bit 单元自制变换，
    /// 不具备跨字节扩散 / 128-bit 状态 / 认证 / 已发表分析四条中的任何一条，
    /// 故没有任何一项超过 25（3 轮 P+S 多轮封顶）；只改长度不改载荷的假层取 1。
    pub(crate) security: u8,
    /// 运行时性能开销 0～100（`dec` 路径实付成本；典型 8–32B 串，含初始化）。
    ///
    /// 标尺锚点：每字节一次 XOR = 1，Ascon-128 = 80。`gen_s` 系（255 次 `mix64`）
    /// 建表开销与长度无关，短串下主导总耗时，故含 `gen_s` 的项可记到 80 之上
    ///（3 轮 P+S 取 100，为全表最高）。
    ///
    /// 取值依据 `tests/perf_crypto.rs` 的实测换算（16B 总耗时相对同 harness
    /// 下 Ascon-128，封顶 100；重档 6 项饱和，内部排序看 fixed 绝对值）。
    /// 注：新增的 `black_box` 保护会带来少量额外运行时开销，各项 `latency`
    /// 数值维持原测定值不变（黑盒对短串场景影响可忽略，详见 perf 测试）。
    pub(crate) latency: u8,
}

pub(crate) static PRIMITIVES: LazyLock<Vec<Crypto>> = LazyLock::new(|| {
    vec![
        // CBC 模式异或链
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                let mut l = iv;
                for c in chunk.iter_mut() {
                    *c ^= key.rotate_left(l as u32) as u8;
                    l = *c;
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let mut l = ::core::hint::black_box(#iv as u8);
                        for c in #in_ident.iter_mut() {
                            let next_l = *c;
                            let v = *c ^ key.rotate_left(l as u32) as u8;
                            *c = ::core::hint::black_box(v);
                            l = ::core::hint::black_box(next_l);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 2,
            latency: 7,
        },
        // 包装加减法与位置密钥
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                for (i, c) in chunk.iter_mut().enumerate() {
                    let k = (key ^ iv as u64).rotate_right(i as u32) as u8;
                    *c = c.wrapping_add(k);
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u64);
                        for (i, c) in #in_ident.iter_mut().enumerate() {
                            let k = ::core::hint::black_box((key ^ iv).rotate_right(i as u32) as u8);
                            let v = c.wrapping_sub(k);
                            *c = ::core::hint::black_box(v);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 2,
            latency: 8,
        },
        // 乘法逆元混淆
        Crypto {
            enc: |ctx, mut chunk| {
                let key = ctx.key;
                for (i, c) in chunk.iter_mut().enumerate() {
                    let k = (key.rotate_right(i as u32) as u8) | 1;
                    *c = c.wrapping_mul(lib_unknown::crypto::base::inv_mul8(k));
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let key = ctx.key;
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        for (i, c) in #in_ident.iter_mut().enumerate() {
                            let k = ::core::hint::black_box((key.rotate_right(i as u32) as u8) | 1);
                            let v = c.wrapping_mul(k);
                            *c = ::core::hint::black_box(v);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 2,
            latency: 10,
        },
        // 动态位移混淆 + 位置流异或
        Crypto {
            enc: |ctx, mut chunk| {
                let key = ctx.key;
                for (i, c) in chunk.iter_mut().enumerate() {
                    let rot = (key.rotate_right(i as u32) % 8) as u32;
                    *c = c.rotate_left(rot) ^ (key >> ((i * 8) % 64)) as u8;
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let key = ctx.key;
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        for (i, c) in #in_ident.iter_mut().enumerate() {
                            let rot = ::core::hint::black_box((key.rotate_right(i as u32) % 8) as u32);
                            let x = ::core::hint::black_box((key >> ((i * 8) % 64)) as u8);
                            *c ^= x;
                            let v = c.rotate_right(rot);
                            *c = ::core::hint::black_box(v);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 3,
            latency: 11,
        },
        // 纯流密码 mse_no_ps (无 P盒/S盒)
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                lib_unknown::crypto::base::mse_no_ps(&mut chunk, key, iv);
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u8);
                        ::obfstr2::crypto::base::imse_no_ps(#in_ident.as_mut_slice(), key, iv);
                        // 调用可能被跨 crate 内联（LTO），逐字节再黑盒一次防止整体折叠。
                        for b in #in_ident.iter_mut() {
                            *b = ::core::hint::black_box(*b);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 10,
            latency: 65,
        },
        // 流密码 mse_no_s (带自修改P盒，无S盒)
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                lib_unknown::crypto::base::mse_no_s(&mut chunk, key, iv);
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u8);
                        ::obfstr2::crypto::base::imse_no_s(#in_ident.as_mut_slice(), key, iv);
                        for b in #in_ident.iter_mut() {
                            *b = ::core::hint::black_box(*b);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 14,
            latency: 100,
        },
        // 全量流密码 mse (自修改动态 P盒 + S盒)
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                lib_unknown::crypto::base::mse(&mut chunk, key, iv);
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u8);
                        ::obfstr2::crypto::base::imse(#in_ident.as_mut_slice(), key, iv);
                        for b in #in_ident.iter_mut() {
                            *b = ::core::hint::black_box(*b);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 22,
            latency: 100,
        },
        // 静态 S-Box 非线性替换
        Crypto {
            enc: |ctx, mut chunk| {
                for c in chunk.iter_mut() {
                    *c =
                        lib_unknown::crypto::base::s8(*c, &lib_unknown::crypto::base::SBOX_BASE[0]);
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |_ctx, in_ident| {
                let ast = quote! {
                    {
                        for c in #in_ident.iter_mut() {
                            let v = ::obfstr2::crypto::base::s8(*c, &::obfstr2::crypto::base::SBOX_BASE[1]);
                            *c = ::core::hint::black_box(v);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 2,
            latency: 6,
        },
        // 动态比特洗牌 P-Box
        Crypto {
            enc: |ctx, mut chunk| {
                let key = ctx.key;
                let p = lib_unknown::crypto::base::gen_p(key);
                for c in chunk.iter_mut() {
                    *c = lib_unknown::crypto::base::p8(*c, &p);
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let key = ctx.key;
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let p = ::core::hint::black_box(::obfstr2::crypto::base::gen_p(key));
                        let p_inv = ::core::hint::black_box(unsafe {
                            ::obfstr2::crypto::base::inv_p(&p).unwrap_unchecked()
                        });
                        for c in #in_ident.iter_mut() {
                            let v = ::obfstr2::crypto::base::p8(*c, &p_inv);
                            *c = ::core::hint::black_box(v);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 5,
            latency: 39,
        },
        // 动态密码本 S-Box
        Crypto {
            enc: |ctx, mut chunk| {
                let key = ctx.key;
                let s = lib_unknown::crypto::base::gen_s(key);
                for c in chunk.iter_mut() {
                    *c = lib_unknown::crypto::base::s8(*c, &s);
                }
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let key = ctx.key;
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let s = ::core::hint::black_box(::obfstr2::crypto::base::gen_s(key));
                        let s_inv = ::core::hint::black_box(unsafe {
                            ::obfstr2::crypto::base::inv_s(&s).unwrap_unchecked()
                        });
                        for c in #in_ident.iter_mut() {
                            let v = ::obfstr2::crypto::base::s8(*c, &s_inv);
                            *c = ::core::hint::black_box(v);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 7,
            latency: 100,
        },
        // 单字节多轮流加密 (3轮 r8，无盒)
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
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
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u8);
                        for (i, c) in #in_ident.iter_mut().enumerate() {
                            let mut val = *c;
                            let k0 = ::core::hint::black_box(::obfstr2::crypto::base::mix64(
                                key ^ (iv as u64) ^ (i as u64).rotate_left(7),
                            ));
                            let k1 = ::core::hint::black_box(::obfstr2::crypto::base::mix64_next(k0));
                            let k2 = ::core::hint::black_box(::obfstr2::crypto::base::mix64_next(k1));

                            val = ::obfstr2::crypto::base::ir8(val, iv, 2, k2 as u128, None, None);
                            val = ::obfstr2::crypto::base::ir8(val, iv, 1, k1 as u128, None, None);
                            val = ::obfstr2::crypto::base::ir8(val, iv, 0, k0 as u128, None, None);
                            *c = ::core::hint::black_box(val);
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 12,
            latency: 100,
        },
        // 3-5 轮动态 P-Box
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                let rounds = ((key >> 8) % 3) as usize + 3; // 避免跨平台 usize 位宽不可移植
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
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u8);
                        let rounds = ((key >> 8) % 3) as usize + 3;
                        for round in (0..rounds).rev() {
                            let mut prev = ::core::hint::black_box(iv ^ (round as u8));
                            let seed = ::core::hint::black_box(::obfstr2::crypto::base::mix64(
                                key.rotate_right((round * 11) as u32),
                            ));
                            let p_box = ::core::hint::black_box(::obfstr2::crypto::base::gen_p(seed));
                            let mut p_inv = ::core::hint::black_box(unsafe {
                                ::obfstr2::crypto::base::inv_p(&p_box).unwrap_unchecked()
                            });
                            let round_key = ::core::hint::black_box(
                                (key as u128) ^ ((round as u128) << 64),
                            );
                            for (i, c) in #in_ident.iter_mut().enumerate() {
                                let pt = ::obfstr2::crypto::base::ir8(
                                    *c,
                                    prev,
                                    i,
                                    round_key,
                                    Some(&mut p_inv),
                                    None,
                                );
                                prev = ::core::hint::black_box(*c);
                                *c = ::core::hint::black_box(pt);
                            }
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 17,
            latency: 100,
        },
        // 全功能多轮 r8（3轮，P+S双盒）
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
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
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let (key, iv) = (ctx.key, ctx.iv);
                let ast = quote! {
                    {
                        let key = ::core::hint::black_box(#key as u64);
                        let iv = ::core::hint::black_box(#iv as u8);
                        let rounds = 3;
                        for round in (0..rounds).rev() {
                            let mut prev = ::core::hint::black_box(iv.rotate_left(round as u32));
                            let seed_base = ::core::hint::black_box(
                                ::obfstr2::crypto::base::mix64_next(key.wrapping_add(round as u64)),
                            );
                            let p_box = ::core::hint::black_box(::obfstr2::crypto::base::gen_p(seed_base));
                            let s_box = ::core::hint::black_box(::obfstr2::crypto::base::gen_s(
                                ::obfstr2::crypto::base::mix64(seed_base),
                            ));
                            let mut p_inv = ::core::hint::black_box(unsafe {
                                ::obfstr2::crypto::base::inv_p(&p_box).unwrap_unchecked()
                            });
                            let mut s_inv = ::core::hint::black_box(unsafe {
                                ::obfstr2::crypto::base::inv_s(&s_box).unwrap_unchecked()
                            });
                            let round_key = ::core::hint::black_box(
                                (key as u128) ^ ((round as u128) << 80),
                            );

                            for (i, c) in #in_ident.iter_mut().enumerate() {
                                let pt = ::obfstr2::crypto::base::ir8(
                                    *c,
                                    prev,
                                    i,
                                    round_key,
                                    Some(&mut p_inv),
                                    Some(&mut s_inv),
                                );
                                prev = ::core::hint::black_box(*c);
                                *c = ::core::hint::black_box(pt);
                            }
                        }
                    }
                };
                (ast, in_ident)
            },
            support: |_len| true,
            security: 25,
            latency: 100,
        },
        // PKCS7 填充到 16 字节边界。
        // `16 - len % 16` 值域恒为 1..=16（`len % 16 == 0` 时补满一块）。
        Crypto {
            enc: |ctx, mut chunk| {
                let pad = 16 - (chunk.len() % 16);
                chunk.extend(std::iter::repeat_n(pad as u8, pad));
                ctx.out_size = chunk.len(); // 长度改变需要同步
                chunk
            },
            dec: |ctx, in_ident| {
                let path = ctx.type_path.clone();
                let pt = ctx.in_size;
                let tag = ctx.ident_tag.clone();
                let out_ident = format_ident!("__tmp_{tag}"); // 长度改变需要更新容器
                let ast = quote! {
                    let mut #out_ident = #path::<#pt>::new();
                    unsafe { #out_ident.extend_from_slice(&#in_ident.as_slice()[..#pt]).unwrap_unchecked(); }
                    drop(#in_ident); // 立即释放擦除
                    // 原来只黑盒了长度，内容仍完全裸露；现对拷贝出的每个字节
                    // （已逼近最终明文）单独黑盒，并对整段切片做一次逃逸保护。
                    for b in #out_ident.as_mut_slice().iter_mut() {
                        *b = ::core::hint::black_box(*b);
                    }
                    ::core::hint::black_box(#out_ident.as_slice());
                    ::core::hint::black_box(#out_ident.as_slice().len());
                };
                (ast, out_ident)
            },
            support: |_len| true,
            security: 1,
            latency: 8,
        },
        // 密钥标签：尾部追加 4B `mix64(key^iv^len)`。
        Crypto {
            enc: |ctx, mut chunk| {
                let (key, iv) = (ctx.key, ctx.iv);
                let tag =
                    lib_unknown::crypto::base::mix64(key ^ (iv as u64) ^ (chunk.len() as u64));
                chunk.extend_from_slice(&tag.to_le_bytes()[..4]);
                ctx.out_size = chunk.len();
                chunk
            },
            dec: |ctx, in_ident| {
                let path = ctx.type_path.clone();
                let pt = ctx.in_size;
                let tag = ctx.ident_tag.clone();
                let out_ident = format_ident!("__tmp_{tag}");
                let ast = quote! {
                    let mut #out_ident = #path::<#pt>::new();
                    unsafe { #out_ident.extend_from_slice(&#in_ident.as_slice()[..#pt]).unwrap_unchecked(); }
                    drop(#in_ident);
                    for b in #out_ident.as_mut_slice().iter_mut() {
                        *b = ::core::hint::black_box(*b);
                    }
                    ::core::hint::black_box(#out_ident.as_slice());
                    ::core::hint::black_box(#out_ident.as_slice().len());
                };
                (ast, out_ident)
            },
            support: |_len| true,
            security: 1,
            latency: 8,
        },
    ]
});