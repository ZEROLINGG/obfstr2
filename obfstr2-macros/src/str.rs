use crate::bytes::{b1, b2, b3};
use lib_unknown::rand::random;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;

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
