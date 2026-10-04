#![allow(unused)]
//! 字节档位入口：`b1` / `b2` / `b3`（低延迟 / 均衡 / 高强度）。
//!
//! 注册表见 `crate::crypto` / `crate::storage`，编排见 `crate::core`，
//! 本文件只保留档位参数与测试。

use crate::core::build_obfuscated_bytes;
use lib_unknown::rand::random;
use proc_macro2::TokenStream as TokenStream2;

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
    use crate::core::build_obfuscated_bytes;
    use lib_unknown::dyntest::{DnyRun, clear_dny_project, dny_run};
    use lib_unknown::rand::random_range;
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
