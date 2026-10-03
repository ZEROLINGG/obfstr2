//! `s_fmt!` 的格式串切分与重组逻辑（入口见 crate 根 [`s_fmt`](crate::s_fmt)）。
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token};

pub struct FormatArgs {
    pub fmt_lit: LitStr,
    pub rest: TokenStream2,
}

impl Parse for FormatArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let fmt_lit: LitStr = input
            .parse()
            .map_err(|e| syn::Error::new(e.span(), "s_fmt! 的第一个参数必须是字符串字面量"))?;

        let rest = if input.peek(Token![,]) {
            let _comma: Token![,] = input.parse()?;
            input.parse()?
        } else {
            TokenStream2::new()
        };

        Ok(FormatArgs { fmt_lit, rest })
    }
}

/// 拆分后的格式化字符串块
pub enum Chunk {
    Text(String),
    Placeholder(String),
}

/// 稳健地解析格式化字符串（`{{` / `}}` 为转义，其余 `{...}` 为占位符）
pub fn parse_format_string(s: &str) -> Result<Vec<Chunk>, String> {
    let mut chunks = Vec::new();
    let mut chars = s.chars().peekable();
    let mut text = String::new();

    while let Some(c) = chars.next() {
        if c == '{' {
            if chars.peek() == Some(&'{') {
                chars.next();
                text.push_str("{{");
            } else {
                if !text.is_empty() {
                    chunks.push(Chunk::Text(std::mem::take(&mut text)));
                }
                let mut ph = String::from("{");
                let mut closed = false;
                for pc in chars.by_ref() {
                    ph.push(pc);
                    if pc == '}' {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err("格式串中 '{' 未闭合".into());
                }
                chunks.push(Chunk::Placeholder(ph));
            }
        } else if c == '}' {
            if chars.peek() == Some(&'}') {
                chars.next();
                text.push_str("}}");
            } else {
                return Err("格式串中 '}' 未配对".into());
            }
        } else {
            text.push(c);
        }
    }
    if !text.is_empty() {
        chunks.push(Chunk::Text(text));
    }
    Ok(chunks)
}

/// 用 s2 档混淆格式串中的字面量部分，展开为 `format!` 调用（返回 `String`）。
pub fn sfmt(input: TokenStream2) -> TokenStream2 {
    let args = match syn::parse2::<FormatArgs>(input) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };
    let fmt_str = args.fmt_lit.value();

    let chunks = match parse_format_string(&fmt_str) {
        Ok(c) => c,
        Err(err) => {
            return syn::Error::new(args.fmt_lit.span(), err).to_compile_error();
        }
    };

    let mut new_fmt = String::new();
    let mut obf_injections = Vec::new();
    let mut obf_idx = 0usize;

    for chunk in chunks {
        match chunk {
            Chunk::Text(text) => {
                let unescaped_text = text.replace("{{", "{").replace("}}", "}");
                let arg_name = quote::format_ident!("___fmt_chunk_{}__", obf_idx);
                new_fmt.push_str(&format!("{{{arg_name}}}"));

                let ts = crate::str::s2(unescaped_text);
                obf_injections.push(quote! { #arg_name = #ts });

                obf_idx += 1;
            }
            Chunk::Placeholder(ph) => {
                new_fmt.push_str(&ph);
            }
        }
    }

    let new_fmt_lit = LitStr::new(&new_fmt, args.fmt_lit.span());
    let mut final_args = args.rest;

    let has_trailing_comma = final_args
        .clone()
        .into_iter()
        .last()
        .is_some_and(|tt| matches!(tt, proc_macro2::TokenTree::Punct(p) if p.as_char() == ','));

    if !final_args.is_empty() && !obf_injections.is_empty() && !has_trailing_comma {
        final_args.extend(quote! { , });
    }

    if !obf_injections.is_empty() {
        let inj_tokens = quote! { #(#obf_injections),* };
        final_args.extend(inj_tokens);
    }

    quote! {
        format!(#new_fmt_lit, #final_args)
    }
}
