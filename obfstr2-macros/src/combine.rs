//! `s_fmt!` 的格式串切分与重组逻辑（入口见 crate 根 [`s_fmt`](crate::s_fmt)）。
use lib_unknown::rand::random;
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
#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Chunk {
    Text(String),
    Placeholder(String),
}

/// 稳健地解析格式化字符串。
///
/// - `{{` / `}}` 视为转义字符；
/// - 其余 `{...}` 视为占位符，占位符内部支持：
///   - 嵌套花括号（按深度匹配，而非遇到第一个 `}` 就截断）；
///   - 单引号/双引号字符串、字符字面量内部的 `{` `}`（含转义）不会影响边界判断。
///
/// 这样可以正确处理诸如 `"{foo('}')}"`、`"{x:foo}"` 等复杂占位符，
/// 而不会在扫描时崩溃或产生“未配对”的误报。
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
                let ph = parse_placeholder(&mut chars)?;
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

/// 解析一个已消费掉起始 `{` 的占位符，返回包含首尾花括号的完整文本。
///
/// 采用花括号深度计数 + 字符串/字符字面量状态机：
/// - 进入 `'` 或 `"` 后视为进入字面量模式，期间的 `{` `}` 被忽略，
///   直到遇到未被 `\` 转义的同类引号才退出；
/// - 不在字面量模式时，`{` 增加深度、`}` 减少深度，深度归零即闭合。
fn parse_placeholder(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, String> {
    let mut ph = String::from("{");
    let mut depth: i32 = 1;
    let mut in_string: Option<char> = None;
    let mut escaped = false;
    let mut closed = false;

    for pc in chars.by_ref() {
        ph.push(pc);

        if let Some(quote_char) = in_string {
            if escaped {
                escaped = false;
            } else if pc == '\\' {
                escaped = true;
            } else if pc == quote_char {
                in_string = None;
            }
            continue;
        }

        match pc {
            '\'' | '"' => in_string = Some(pc),
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    closed = true;
                    break;
                }
            }
            _ => {}
        }
    }

    if !closed {
        return if in_string.is_some() {
            Err("格式串占位符中的字符串/字符字面量未闭合".into())
        } else {
            Err("格式串中 '{' 未闭合".into())
        };
    }

    Ok(ph)
}

/// 用 s2 档混淆格式串中的字面量部分，展开为 `::std::format!` 调用（返回 `String`）。
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

    // 每次宏展开生成一个随机后缀，降低生成的注入参数标识符
    // 与调用方传入参数（或其他宏展开）同名冲突的概率。
    let suffix: u64 = random();

    let mut new_fmt = String::new();
    let mut obf_injections = Vec::new();
    let mut obf_idx = 0usize;

    for chunk in chunks {
        match chunk {
            Chunk::Text(text) => {
                let unescaped_text = text.replace("{{", "{").replace("}}", "}");
                let arg_name = quote::format_ident!("__s_fmt_chunk_{}_{}__", obf_idx, suffix);
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
        ::std::format!(#new_fmt_lit, #final_args)
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    fn ok(s: &str) -> Vec<Chunk> {
        parse_format_string(s).unwrap_or_else(|e| panic!("解析 {s:?} 失败: {e}"))
    }

    fn err(s: &str) -> String {
        match parse_format_string(s) {
            Ok(v) => panic!("{s:?} 应当解析失败，实际得到 {v:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn plain_text() {
        assert_eq!(ok("hello world"), vec![Chunk::Text("hello world".into())]);
    }

    #[test]
    fn empty_input() {
        assert_eq!(ok(""), Vec::<Chunk>::new());
    }

    #[test]
    fn escaped_braces_only() {
        assert_eq!(ok("{{a}}"), vec![Chunk::Text("{{a}}".into())]);
    }

    #[test]
    fn simple_and_named_placeholder() {
        assert_eq!(
            ok("{} {name}"),
            vec![
                Chunk::Placeholder("{}".into()),
                Chunk::Text(" ".into()),
                Chunk::Placeholder("{name}".into()),
            ]
        );
    }

    #[test]
    fn placeholder_with_format_spec() {
        // {x:foo} —— 冒号后的内容是否合法由最终 ::std::format! 校验，
        // 这里只验证切分阶段把整体当成一个占位符。
        assert_eq!(ok("{x:foo}"), vec![Chunk::Placeholder("{x:foo}".into())]);
    }

    #[test]
    fn placeholder_with_nested_braces() {
        assert_eq!(
            ok("{foo({bar})}"),
            vec![Chunk::Placeholder("{foo({bar})}".into())]
        );
    }

    #[test]
    fn placeholder_with_char_literal_containing_brace() {
        // '}' 内部的 } 不应被当成占位符结束 —— 这是本次修复的核心场景
        assert_eq!(
            ok("{foo('}')}"),
            vec![Chunk::Placeholder("{foo('}')}".into())]
        );
    }

    #[test]
    fn placeholder_with_string_literal_containing_brace() {
        assert_eq!(
            ok(r#"{foo("}")}"#),
            vec![Chunk::Placeholder(r#"{foo("}")}"#.into())]
        );
    }

    #[test]
    fn placeholder_with_escaped_quote_in_string() {
        // 字符串内部出现被转义的引号 \" ，不应提前结束字符串模式
        assert_eq!(
            ok(r#"{foo("a\"}b")}"#),
            vec![Chunk::Placeholder(r#"{foo("a\"}b")}"#.into())]
        );
    }

    #[test]
    fn placeholder_with_escaped_backslash_before_quote() {
        // 边界：\\" 中的 \\ 是转义自己，后面的 " 仍然应该正常结束字符串
        // r#"{foo("a\\")}"# 对应真实内容：{foo("a\")}
        assert_eq!(
            ok(r#"{foo("a\\")}"#),
            vec![Chunk::Placeholder(r#"{foo("a\\")}"#.into())]
        );
    }

    #[test]
    fn mixed_text_and_placeholders() {
        assert_eq!(
            ok("pre{a}mid{b:?}post"),
            vec![
                Chunk::Text("pre".into()),
                Chunk::Placeholder("{a}".into()),
                Chunk::Text("mid".into()),
                Chunk::Placeholder("{b:?}".into()),
                Chunk::Text("post".into()),
            ]
        );
    }

    #[test]
    fn consecutive_placeholders() {
        assert_eq!(
            ok("{a}{b}"),
            vec![
                Chunk::Placeholder("{a}".into()),
                Chunk::Placeholder("{b}".into()),
            ]
        );
    }

    #[test]
    fn escape_adjacent_to_placeholder() {
        // {{ 紧跟占位符，验证两者不会相互吞噬
        assert_eq!(
            ok("{{{a}}}"),
            vec![
                Chunk::Text("{{".into()),
                Chunk::Placeholder("{a}".into()),
                Chunk::Text("}}".into()),
            ]
        );
    }

    #[test]
    fn unmatched_closing_brace_errors() {
        let e = err("a}b");
        assert!(e.contains("未配对"), "错误信息: {e}");
    }

    #[test]
    fn unterminated_placeholder_errors() {
        let e = err("{abc");
        assert!(e.contains("未闭合"), "错误信息: {e}");
    }

    #[test]
    fn unterminated_string_in_placeholder_errors() {
        let e = err(r#"{foo("abc}"#);
        assert!(e.contains("字符串/字符字面量未闭合"), "错误信息: {e}");
    }

    #[test]
    fn deeply_nested_braces_does_not_overflow_or_panic() {
        // 构造较深的嵌套，确认不会栈溢出/死循环（depth 计数不会越界）
        let depth = 1000;
        let mut s = String::from("{");
        s.push_str(&"{".repeat(depth));
        s.push_str(&"}".repeat(depth));
        s.push('}');
        assert!(parse_format_string(&s).is_ok());
    }

    /// 已知限制：raw string 前缀（r"..."/r#"..."#/b"..."）未被状态机识别。
    /// 这里显式记录"当前行为"，而不是断言它是"正确"的——
    /// 一旦未来实现 raw string 支持，这个测试需要同步更新（最好改成断言正确切分）。
    #[test]
    fn known_limitation_raw_string_inside_placeholder() {
        let input = r###"{foo(r#"a}b"#)}"###;
        // 当前只保证“不 panic”，不保证切分结果语义正确。
        let _ = parse_format_string(input);
    }
}
