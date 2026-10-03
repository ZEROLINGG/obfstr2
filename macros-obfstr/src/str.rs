#![allow(unused)]
use crate::bytes::{b1, b2, b3};
use lib_unknown::rand::random;
use proc_macro2::{Literal as Literal2, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use std::sync::LazyLock;

pub fn s1(input: String) -> TokenStream2 {
    let size = input.len();
    let ts = b1(input.into_bytes());

    quote! {
        {
            let mut bytes = #ts;
            unsafe { ::obfstr2::types::str::StackStr::<#size>::try_from(bytes.as_mut_slice()).unwrap_unchecked() }
        }
    }
}

pub fn s2(input: String) -> TokenStream2 {
    let size = input.len();
    let ts = b2(input.into_bytes());

    let main_type_path = if cfg!(feature = "alloc") && random() {
        quote!(::obfstr2::types::str::HeapStr)
    } else {
        quote!(::obfstr2::types::str::StackStr)
    };

    quote! {
        {
            let mut bytes = #ts;
            unsafe { #main_type_path::<#size>::try_from(bytes.as_mut_slice()).unwrap_unchecked() }
        }
    }
}

pub fn s3(input: String) -> TokenStream2 {
    let size = input.len();
    let ts = b3(input.into_bytes());

    let main_type_path = if cfg!(feature = "alloc") {
        quote!(::obfstr2::types::str::HeapStr)
    } else {
        quote!(::obfstr2::types::str::StackStr)
    };

    quote! {
        {
            let mut bytes = #ts;
            unsafe { #main_type_path::<#size>::try_from(bytes.as_mut_slice()).unwrap_unchecked() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_unknown::dyntest::dny_run;
    use lib_unknown::rand::random_range;

    fn run_test(f: fn(String) -> TokenStream2, tag: &str) {
        let x = random_range(20..127) as u8;
        let input = String::from_utf8(vec![x; 1024]).unwrap();
        let ts = f(input.clone());

        let code = format!("fn main() {{ let x = {}; print!(\"{{x}}\") }}", ts);

        println!("[{tag}] size: {}\n{:.128}...", code.len(), code);
        let deps = format!("obfstr2 = {{ path = \"../../../../../obfstr2\"}} ");
        let ret = dny_run(code.as_str(), deps.as_str(), None, false);
        println!("{ret}");
        // println!("{:?}",ret.stderr);

        assert!(ret.stderr.is_empty());

        assert_eq!(ret.stdout, input);
    }
    #[test]
    fn test_s1() {
        // [s1] size: 34125
        // fn main() { let x = { let mut bytes = { let mut __bytes_17892071121591165890 = :: obfstr :: types :: bytes :: HeapBytes :: < 102...
        // === [Result: SUCCESS] ===
        // > Build: 2.867945676s | Run: 785.306µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ... [单行超长截断] ... <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
        // ==========================
        run_test(s1, "s1");
    }

    #[test]
    fn test_s2() {
        // [s2] size: 39524
        // fn main() { let x = { let mut bytes = { let mut __bytes_13391584339402994166 = :: obfstr :: types :: bytes :: HeapBytes :: < 102...
        // === [Result: SUCCESS] ===
        // > Build: 3.029923262s | Run: 2.208466ms
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        //  ... [单行超长截断] ... 
        // ==========================
        run_test(s2, "s2");
    }

    #[test]
    fn test_s3() {
        // [s3] size: 67839
        // fn main() { let x = { let mut bytes = { let mut __bytes_10391264783947038362 = :: obfstr :: types :: bytes :: StackBytes :: < 10...
        // === [Result: SUCCESS] ===
        // > Build: 3.242443274s | Run: 3.448905ms
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // ****************************************************************************************************************************************************** ... [单行超长截断] ... ******************************************************************************************************************************************************
        // ==========================
        run_test(s3, "s3");
    }

    #[test]
    fn test_casual_x_obfstr() {
        // [https://crates.io/crates/obfstr] size: 1071
        // fn main() { print!("{}", obfstr::obfstr!("??????????????????????????????????????????????????????????????????????????????????????...
        // === [Result: SUCCESS] ===
        // > Build: 1.935633662s | Run: 608.735µs
        // > Exit Code: 0
        // --- Stdout (size: 1024 bytes) ---
        // ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? ... [单行超长截断] ... ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        // ==========================

        // ❯ cargo expand > expand.txt
        //     Checking dyn_test_1789088538249806566_2945908345 v0.1.0 (/home/zz/Documents/Project/Rust/malware/obfstr/macros/target/dyn_tests/dny_1789088538249806566_2945908345)
        //     Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
        //
        // ❯ ll
        // 总计 16K
        // -rw-rw-r-- 1 zz zz  403  9月11日 09:02 Cargo.lock
        // -rw-rw-r-- 1 zz zz  127  9月11日 09:02 Cargo.toml
        // -rw-rw-r-- 1 zz zz 7.9K  9月11日 09:02 expand.txt
        // drwxrwxr-x 1 zz zz   14  9月11日 09:02 src
        // drwxrwxr-x 1 zz zz   66  9月11日 09:02 target
        let x = random_range(20..127) as u8;
        let input = String::from_utf8(vec![x; 1024]).unwrap();
        let code = format!("fn main() {{ print!(\"{{}}\", obfstr::obfstr!(\"{input}\")) }}",);
        let deps = r#"obfstr = "0.4.6""#;
        println!(
            "[https://crates.io/crates/obfstr] size: {}\n{:.128}...",
            code.len(),
            code
        );

        let ret = dny_run(code.as_str(), deps, None, false);
        println!("{ret}");

        assert!(ret.stderr.is_empty());

        assert_eq!(ret.stdout, input);
    }
}
