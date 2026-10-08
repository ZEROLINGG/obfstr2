# obfstr2
<!-- i18n-sync-anchor: 58d1fb6b66e3b4e2542172fbf02fb93b4f36243af6ff3fd704c322d5596bad5b (source: README.md) -->

> **Polymorphic compile-time string/bytes/int/float/cstr/file obfuscation (`no_std` compatible)**

[![Crates.io](https://img.shields.io/crates/v/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Downloads](https://img.shields.io/crates/d/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Documentation](https://docs.rs/obfstr2/badge.svg)](https://docs.rs/obfstr2)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)

[![CI](https://github.com/ZEROLINGG/obfstr2/actions/workflows/ci.yml/badge.svg)](https://github.com/ZEROLINGG/obfstr2/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](#minimum-rust-version-msrv)

**Languages:** [简体中文](README.md) | English

A polymorphic compile-time string/bytes/int/float/file obfuscation (`no_std` compatible).

Same category as [CasualX/obfstr](https://github.com/CasualX/obfstr) but a different trade-off: CasualX delivers out-of-the-box string hiding with minimal expansion size, while obfstr2 trades several times the expansion size for polymorphic defense — random chunking, randomly stacked primitives, multiple alternative storage forms, and junk-code interference — so the same input produces different ciphertext on every compilation, and batch recovery scripts cannot reuse a fixed pattern. Coverage goes beyond strings: on top of the `s/b/f` families, `i1~3!` / `fl1~3!` cover all integer and float literals (expanding to directly usable plain values), `cs1~3!` cover C strings (`"..."` / `c"..."` / `b"..."`, all three forms equivalent, `b"..."` can express non-UTF-8 payloads; expanding to owned containers that dereference to `CStr`), and `s_fmt!` covers format strings (literal chunks obfuscated one by one, then passed to `format!`) — seven input kinds through the same chunk → encrypt → store → emit kernel. Another key difference is data lifetime: obfstr2's container types (provided by `lib-unknown`) are automatically volatile-zeroed on `Drop`, so decrypted plaintext is wiped as soon as it is used instead of lingering on the stack / heap (`s/b/f/cs` containers; `i/fl` return plain values and `s_fmt!` returns `String`, with no automatic erasure — see the macro overview). That is why obfstr2 exists: **higher reverse-engineering cost, more polymorphic obfuscation, wider type coverage, and automatic erasure of sensitive data at the end of its lifetime**.

- Same: literals in, expressions out; `no_std` compatible; obfuscation done at compile time, with `lib-unknown` as the only runtime dependency.
- Different: CasualX macros return a reference borrowing a temporary (`let x = obfstr!(...)` triggers E0716 and can only be used inline), while obfstr2 returns owned containers (plain values for `i/fl`) that can be bound, passed around, and reused; CasualX expands to a single fixed form, obfstr2 takes a different form on every compilation; CasualX focuses on strings, obfstr2 additionally covers integers / floats / C strings / files / format strings.

## Contents

- [Design Philosophy](#design-philosophy)
- [Quick Start](#quick-start)
- [Macro Overview](#macro-overview)
- [Use Cases vs Non-Use Cases](#use-cases-vs-non-use-cases)
- [Feature Flags](#feature-flags)
- [Platform Support](#platform-support)
- [Minimum Rust Version (MSRV)](#minimum-rust-version-msrv)
- [Benchmarks](#benchmarks)
- [Security](#security)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

## Design Philosophy

### Core Principles

1. **Extreme polymorphism** — the same input compiles to a different ciphertext form every time: random chunking (incrementally randomized `2i..8i` splits), randomly stacked crypto primitives (`1–3 × magnification`, stopping once the combined security level is reached), multiple randomly chosen storage forms (byte strings, `u8` / `u64` / `u128` arrays, MAC / UUID / IPv6 steganographic disguises, etc.), plus junk code and `ghost_state` interference. Batch recovery scripts cannot rely on a fixed pattern.
2. **Abstracted obfuscation pipeline** — all algorithms converge into two registries: `Crypto { enc / dec / support / security / latency }` (polymorphic encryption/decryption) and `Storage { ast / support / security / latency }` (polymorphic ciphertext storage); `build_obfuscated_bytes` only orchestrates chunk → encrypt → store → emit. New algorithms just add table entries without touching the pipeline.
3. **Compile-time evaluation, minimal runtime dependencies** — proc macros expand to a closed token stream; obfuscation is done at compile time, and at runtime only `lib-unknown`'s `types` and `crypto` are needed; `no_std` compatible; invariants already verified at expansion time use `unwrap_unchecked` with no runtime checking overhead.
4. **Out-of-the-box usability** — callers write a single macro: literals in, expressions out, with no initialization, key management, or runtime configuration; tier numbering is uniform across all families (`1` = low-latency, `2` = balanced, `3` = high-strength); results are owned containers or plain values that can be `let`-bound, passed around, and reused without fixed type annotations; invalid inputs fail at compile time pointing at the call site. Polymorphic complexity stays inside the macro and never leaks cognitive load to the caller.

### Trade-offs

| We chose | Instead of | Why |
| :--- | :--- | :--- |
| Compile time and size for strength | Minimal runtime decryption overhead | A 128B input expands to ~55k characters and a ~490KB binary under `b3` (see Benchmarks); runtime is just linear decryption |
| Different output on every build | Reproducible builds | Polymorphism is the core defense; identical artifact hashes are impossible by design |
| Effectiveness-oriented obfuscation | Cryptographic security claims | The goal is raising batch-script recovery cost, not resisting targeted manual reverse engineering |

### Non-Goals

- No control-flow obfuscation or anti-debugging.
- No reproducible builds; not a substitute for encrypting sensitive data.

## Quick Start

```toml
[dependencies]
obfstr2 = "0.1"
```

```rust
use obfstr2::{b2, cs2, f2, fl2, i2, s2, s_fmt};

fn main() {
    // Strings: evaluate to the original at runtime; owned containers that
    // can be bound, passed around, and reused
    let hello = s2!("hello");
    print!("{hello}");
    // C strings: evaluate to the original; dereference to `CStr`,
    // `as_ptr()` can be passed to syscalls directly
    let sh = cs2!(c"/bin/sh");
    assert_eq!(&*sh, c"/bin/sh");
    // Byte strings / byte arrays: dereference to the original `[u8]`
    let b = b2!(b"abc");
    let c = b2!([0x61, 98, 99]);
    assert_eq!(&*b, &*c);
    // Integers: evaluate to the original plain value, usable in arithmetic
    // and comparisons directly (empty suffix means `i32`)
    let x = i2!(42u32);
    assert_eq!(x + 1, 43u32);
    // Floats: evaluate to the original plain value (empty suffix means
    // `f64`; `inf` / `NaN` are rejected)
    let y = fl2!(3.15);
    assert_eq!(y.to_bits(), 3.15f64.to_bits());
    // Files: path relative to the compiled crate's CARGO_MANIFEST_DIR,
    // read in at compile time
    let d = f2!("assets/fixture.bin");
    // Format strings: literal chunks are obfuscated one by one, then go
    // through `format!`; placeholders work as usual, returns `String`
    let name = "world";
    let greeting = s_fmt!("hello, {}!", name);
    print!("{greeting}");
}
```

## Macro Overview

| Macros | Input | Strength tier |
|---|---|---|
| `s1!` / `s2!` / `s3!` | `"..."` string literals | Low-latency / Balanced / High-strength |
| `b1!` / `b2!` / `b3!` | `b"..."` or `[0x41, 66, ...]` (elements must be 0..=255) | Low-latency / Balanced / High-strength |
| `i1!` / `i2!` / `i3!` | `42u8` / `-1` / `0xFFu16` integer literals (empty suffix means `i32`) | Low-latency / Balanced / High-strength |
| `fl1!` / `fl2!` / `fl3!` | `3.15f32` / `-1.0` / `1e10` float literals (empty suffix means `f64`) | Low-latency / Balanced / High-strength |
| `cs1!` / `cs2!` / `cs3!` | `"..."` / `c"..."` / `b"..."` (`b"..."` may hold non-UTF-8 bytes; payload must not contain interior NUL) | Low-latency / Balanced / High-strength |
| `f1!` / `f2!` / `f3!` | `"path/to/file"` file path literals | Low-latency / Balanced / High-strength |
| `s_fmt!` | `"...{}..."` format string + args (tier 2) | Literal chunks obfuscated, then `format!`; returns `String` (needs `std` / `alloc`) |

Notes:

- String macros expand to `StackStr<N>` / `HeapStr<N>`, bytes and file macros to `StackBytes<N>` / `HeapBytes<N>`, C string macros to `StackCStr<N>` / `HeapCStr<N>` (`N` includes the trailing `\0`, `N >= 1`; dereference to `core::ffi::CStr`, auto-wiped on `Drop`), integer macros to the corresponding plain integer (`u8`/`i8`/`u16`/`i16`/`u32`/`i32`/`u64`/`i64`/`u128`/`i128`/`usize`/`isize`, decided by the literal suffix), float macros to the corresponding plain float (`f32` / `f64`, decided by the literal suffix); the concrete type may vary between compilations — use type inference instead of fixed type annotations.
- Integer / float macros reuse the same byte obfuscation kernel (integers little-endian encoded, floats encoded via `to_bits` little-endian, then chunk → encrypt → store → emit): the payload is always a single chunk with only 2 storage forms available; polymorphism comes from primitive stacking and emission forms; the plain value is returned with no `Drop` auto-wipe; `usize` / `isize` use 64-bit semantics (via `u64` / `i64`, then `as` cast); floats accept only finite ordinary values (`inf` / `NaN` are rejected), `-0.0` keeps its sign bit, and assertions should use `to_bits()` instead of `==`.
- C string macros reuse the same byte obfuscation kernel: the payload plus the trailing `\0` is obfuscated as a whole, then restored at runtime via `try_from(&mut [u8])` (truncate at the first NUL + wipe the decrypted source); the three literal forms are semantically equivalent — use `b"..."` for non-UTF-8 payloads; any interior NUL in the payload is a compile-time error.
- Obfuscation output differs on every compilation (compile-time randomness); the same macro invocation never reproduces an identical byte stream.

## Use Cases vs Non-Use Cases

**Good fit:**

- Hiding strings and constant bytes in `no_std` firmware / bare-metal programs.
- Scenarios that need to evade bulk static-string scanning.

**Not a fit:**

- Scenarios requiring compliance audits or human-readable plaintext.
- Obfuscating huge files (expansion grows significantly with payload and tier, see Benchmarks).
- Release flows requiring stable artifact hashes (reproducible builds).

## Platform Support

- `no_std` compatible; `Heap*` types require the `alloc` feature.
- Files read by `fN!` must exist at compile time (paths relative to the compiled crate's manifest directory).

## Feature Flags

| Feature | Enabled by default | Description |
| :--- | :--- | :--- |
| `default` | ✅ | `lib-unknown/alloc` + `obfstr2-macros/alloc`, enables `Heap*` heap types |
| `alloc` (per crate) | ❌ | With it off, only `Stack*` is available (pure stack, no heap, bare-metal `no_std` ready) |

## Minimum Rust Version (MSRV)

MSRV is `1.98`, declared via `rust-version` in both `Cargo.toml` files.

## Benchmarks

The sole source of the figures below is `tests/perf.rs` (re-runnable via `cargo test --test perf -- --ignored --nocapture`; report-only, figures shown but never asserted): semantically identical single-macro programs with a 128B all-`a` payload, release cold builds, 200 decryption rounds per guest for checksum verification (run time includes process startup). Polymorphism makes every run differ; the table is a single measured sample, order-of-magnitude reference only.

| Program                                 | Build time | Run time | Expanded chars | Binary (unstripped) |
|:----------------------------------------|:-----------|:---------|:---------------|:--------------------|
| Plaintext baseline (`static` reference) | ~0.1s      | ~11ms    | ~0.5k          | ~447KB              |
| CasualX/obfstr 0.4                      | ~1.1s      | ~11ms    | ~2.8k          | ~449KB              |
| obfstr2 (`b1!`)                         | ~2.2s      | ~11ms    | ~31k           | ~458KB              |
| obfstr2 (`b2!`)                         | ~2.8s      | ~11ms    | ~47k           | ~470KB              |
| obfstr2 (`b3!`)                         | ~2.4s      | ~20ms    | ~55k           | ~490KB              |


## Security


If you find a security vulnerability, please file an Issue directly (this repo has no private reporting channel yet).

## Contributing

Issues and Pull Requests are welcome!

- Local verification (layered, ~15s with warm cache):
  - `cargo test --test smoke --test s_fmt`: correctness of all macros, in-process assertions, milliseconds;
  - `cargo test --test compile_fail`: compile-time rejection of invalid inputs (isolated dyntest projects per case);
  - `cargo test --test nostd`: `x86_64-unknown-none` bare-metal link (`b1` pure-stack without allocator + `b2` with heap; install that target first);
  - `cargo test --test perf -- --ignored --nocapture`: benchmark report (plaintext baseline vs CasualX vs `b1/b2/b3`; build/run time, expanded chars, binary size; report-only, needs network for `obfstr` plus `cargo-expand`);
  - `cd obfstr2-macros && cargo test --lib`: pure unit tests (format-string splitting, polymorphic expansion, milliseconds).
- Before submitting a PR, read the [Design Philosophy](#design-philosophy): new obfuscation primitives must plug in as `Crypto` / `Storage` table entries (in `obfstr2-macros/src/crypto.rs` and `storage.rs` respectively) and leave the orchestration layer (`core.rs::build_obfuscated_bytes`) untouched.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

[MIT License](./LICENSE)
