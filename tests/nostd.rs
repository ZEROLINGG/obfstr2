//! 裸机链路测试：`x86_64-unknown-none` 下解密并 `write(1)` 输出。
//!
//! 由原 `obfstr2-macros/src/bytes.rs::test_*_nostd` 迁移而来：
//! - 每个用例独立 `DnyRun`（目录唯一），可并行，无共享 `RUNNER`；
//! - 删除 `clear_dny_project`（原 `None` 超时在并行时会永久等待存活锁，是 hang 根因）；
//! - 载荷由 1024B 收敛为 128B（链路正确性与大载荷正交，大载荷只影响体积）；
//! - 仅保留代表档：`b1`（纯栈 + `default-features=false`，真裸机）与
//!   `b2`（默认特性，堆栈随机）；`b3` 正确性由 `smoke.rs` 覆盖。
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use lib_unknown::dyntest::DnyRun;
use std::time::Duration;

/// 根包路径（编译期确定），比相对 `../../../..` 路径稳健（不依赖目录名）。
fn obfstr2_dep(no_default: bool) -> String {
    if no_default {
        format!(
            "obfstr2 = {{ path = {:?}, default-features = false }}",
            env!("CARGO_MANIFEST_DIR")
        )
    } else {
        format!("obfstr2 = {{ path = {:?} }}", env!("CARGO_MANIFEST_DIR"))
    }
}

fn run_nostd(macro_call: &str, deps: &str, expected: (char, usize), tag: &str) {
    let template = r#"
#![no_std]
#![no_main]
#![allow(binary_asm_labels)]
#![allow(unused)]
#![allow(unsafe_code)]
#![cfg(not(test))]

use core::arch::asm;
use core::{panic};

extern crate alloc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

// 极简 bump 分配器：`b2` 可能随机展开为 `HeapBytes`，裸机需提供全局分配器。
// 128B 载荷下 64KiB 绰绰有余；不回收（测试进程一次运行）。
struct Bump;
struct BumpBuf(UnsafeCell<[u8; 65536]>);
unsafe impl Sync for BumpBuf {}
static BUMP_BUF: BumpBuf = BumpBuf(UnsafeCell::new([0; 65536]));
static BUMP_POS: AtomicUsize = AtomicUsize::new(0);
unsafe impl core::alloc::GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let mut pos = BUMP_POS.load(Ordering::Relaxed);
        loop {
            let aligned = (pos + align - 1) & !(align - 1);
            let next = aligned + size;
            if next > 65536 {
                return core::ptr::null_mut();
            }
            match BUMP_POS.compare_exchange(pos, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return unsafe { (*BUMP_BUF.0.get()).as_mut_ptr().add(aligned) },
                Err(cur) => pos = cur,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}
#[global_allocator]
static GLOBAL: Bump = Bump;

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
    let code = template.replace("[[bytes]]", macro_call);
    let mut runner = DnyRun::new(&code, deps);
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
    let ret = runner.run(Some(Duration::from_secs(180)));
    assert!(ret.ok, "[{tag}] 裸机构建或运行失败:\n{ret}");
    assert!(ret.stderr.is_empty(), "[{tag}] 编译失败:\n{ret}");
    assert_eq!(ret.stdout.len(), expected.1, "[{tag}] 输出长度不符合预期");
    assert!(
        ret.stdout.chars().all(|c| c == expected.0),
        "[{tag}] 解码数据错误，不全为预期的字符!"
    );
}

/// 整数裸机链路：`i1!` 纯栈展开的 `u32` 以小端 4 字节 `write(1)` 输出。
#[allow(clippy::too_many_arguments)]
fn run_nostd_int(macro_call: &str, deps: &str, expected_bytes: &[u8], tag: &str) {
    let template = r#"
#![no_std]
#![no_main]
#![allow(binary_asm_labels)]
#![allow(unused)]
#![allow(unsafe_code)]
#![cfg(not(test))]

use core::arch::asm;
use core::{panic};

extern crate alloc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

// 极简 bump 分配器（与字节链路同模板，i1 纯栈实际用不上，保留以对齐构建环境）。
struct Bump;
struct BumpBuf(UnsafeCell<[u8; 65536]>);
unsafe impl Sync for BumpBuf {}
static BUMP_BUF: BumpBuf = BumpBuf(UnsafeCell::new([0; 65536]));
static BUMP_POS: AtomicUsize = AtomicUsize::new(0);
unsafe impl core::alloc::GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let mut pos = BUMP_POS.load(Ordering::Relaxed);
        loop {
            let aligned = (pos + align - 1) & !(align - 1);
            let next = aligned + size;
            if next > 65536 {
                return core::ptr::null_mut();
            }
            match BUMP_POS.compare_exchange(pos, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return unsafe { (*BUMP_BUF.0.get()).as_mut_ptr().add(aligned) },
                Err(cur) => pos = cur,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}
#[global_allocator]
static GLOBAL: Bump = Bump;

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
    let v: u32 = [[int]];
    sys_write(1, &v.to_le_bytes());
    0
}

"#;
    let code = template.replace("[[int]]", macro_call);
    let mut runner = DnyRun::new(&code, deps);
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
    let ret = runner.run(Some(Duration::from_secs(180)));
    assert!(ret.ok, "[{tag}] 裸机构建或运行失败:\n{ret}");
    assert!(ret.stderr.is_empty(), "[{tag}] 编译失败:\n{ret}");
    assert_eq!(
        ret.stdout.as_bytes(),
        expected_bytes,
        "[{tag}] 解码数据错误"
    );
}

/// 浮点裸机链路：`fl1!` 纯栈展开的 `f32` 以小端 4 字节 `write(1)` 输出。
/// 模板与 `run_nostd_int` 同构，仅 `main` 改为浮点取位输出。
#[allow(clippy::too_many_arguments)]
fn run_nostd_float(macro_call: &str, deps: &str, expected_bytes: &[u8], tag: &str) {
    let template = r#"
#![no_std]
#![no_main]
#![allow(binary_asm_labels)]
#![allow(unused)]
#![allow(unsafe_code)]
#![cfg(not(test))]

use core::arch::asm;
use core::{panic};

extern crate alloc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

// 极简 bump 分配器（与整数链路同模板，fl1 纯栈实际用不上，保留以对齐构建环境）。
struct Bump;
struct BumpBuf(UnsafeCell<[u8; 65536]>);
unsafe impl Sync for BumpBuf {}
static BUMP_BUF: BumpBuf = BumpBuf(UnsafeCell::new([0; 65536]));
static BUMP_POS: AtomicUsize = AtomicUsize::new(0);
unsafe impl core::alloc::GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();
        let mut pos = BUMP_POS.load(Ordering::Relaxed);
        loop {
            let aligned = (pos + align - 1) & !(align - 1);
            let next = aligned + size;
            if next > 65536 {
                return core::ptr::null_mut();
            }
            match BUMP_POS.compare_exchange(pos, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return unsafe { (*BUMP_BUF.0.get()).as_mut_ptr().add(aligned) },
                Err(cur) => pos = cur,
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}
#[global_allocator]
static GLOBAL: Bump = Bump;

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
    // 注意：dyntest 以 String 回传 stdout，非 UTF-8 输出会被 lossy 改写，
    // 故此处将位字节转 hex ASCII 再输出，保证逐字节精确可断言。
    let v: f32 = [[float]];
    let b = v.to_bits().to_le_bytes();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 8];
    let mut k = 0;
    while k < 4 {
        out[2 * k] = HEX[(b[k] >> 4) as usize];
        out[2 * k + 1] = HEX[(b[k] & 15) as usize];
        k += 1;
    }
    sys_write(1, &out);
    0
}

"#;
    let code = template.replace("[[float]]", macro_call);
    let mut runner = DnyRun::new(&code, deps);
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
    let ret = runner.run(Some(Duration::from_secs(180)));
    assert!(ret.ok, "[{tag}] 裸机构建或运行失败:\n{ret}");
    assert!(ret.stderr.is_empty(), "[{tag}] 编译失败:\n{ret}");
    assert_eq!(
        ret.stdout.as_bytes(),
        expected_bytes,
        "[{tag}] 解码数据错误"
    );
}

#[test]
fn b1_nostd_no_alloc() {
    // 128 × 'a'，纯栈、无堆、关闭默认特性
    let lit = "a".repeat(128);
    let call = format!(r#"obfstr2::b1!(b"{lit}")"#);
    run_nostd(&call, &obfstr2_dep(true), ('a', 128), "b1_nostd");
}

#[test]
fn b2_nostd_default_features() {
    let lit = "a".repeat(128);
    let call = format!(r#"obfstr2::b2!(b"{lit}")"#);
    run_nostd(&call, &obfstr2_dep(false), ('a', 128), "b2_nostd");
}

#[test]
fn cs1_nostd_no_alloc() {
    // 128 × 'a' 的 C 字符串，纯栈、无堆、关闭默认特性；
    // 经 UFCS 取 as_bytes 后 to_vec（bump 分配器兜底），复用字节链路模板。
    let lit = "a".repeat(128);
    let call = format!(
        r#"{{ let s = obfstr2::cs1!(c"{lit}"); obfstr2::types::cstr::CStr::as_bytes(&s).to_vec() }}"#
    );
    run_nostd(&call, &obfstr2_dep(true), ('a', 128), "cs1_nostd");
}

#[test]
fn i1_nostd_no_alloc() {
    // 0x61616161u32 小端即 4 × 'a'，纯栈、无堆、关闭默认特性
    run_nostd_int(
        "obfstr2::i1!(0x61616161u32)",
        &obfstr2_dep(true),
        b"aaaa",
        "i1_nostd",
    );
}

#[test]
fn fl1_nostd_no_alloc() {
    // 1.5f32 的小端位字节 hex（"0000c03f"），纯栈、无堆、关闭默认特性
    let expected_hex: String = 1.5f32
        .to_bits()
        .to_le_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    run_nostd_float(
        "obfstr2::fl1!(1.5f32)",
        &obfstr2_dep(true),
        expected_hex.as_bytes(),
        "fl1_nostd",
    );
}
