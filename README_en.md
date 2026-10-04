# obfstr2
<!-- i18n-sync-anchor: 7c4de245b2f3ecda4451ad3cfc05f7dd34973527 (source: README.md) -->

> **Polymorphic compile-time string/bytes/file obfuscation (`no_std` compatible)**

[![Crates.io](https://img.shields.io/crates/v/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Downloads](https://img.shields.io/crates/d/obfstr2.svg)](https://crates.io/crates/obfstr2)
[![Documentation](https://docs.rs/obfstr2/badge.svg)](https://docs.rs/obfstr2)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#license)

[![CI](https://github.com/ZEROLINGG/obfstr2/actions/workflows/ci.yml/badge.svg)](https://github.com/ZEROLINGG/obfstr2/actions)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](#minimum-rust-version-msrv)

**Languages:** [简体中文](README.md) | English

A polymorphic compile-time string/bytes/file obfuscation (`no_std` compatible).

Same category as [CasualX/obfstr](https://github.com/CasualX/obfstr) but a different trade-off: CasualX delivers out-of-the-box string hiding with minimal expansion size, while obfstr2 trades roughly 6× expansion size for polymorphic defense — random chunking, randomly stacked primitives, multiple alternative storage forms, and junk-code interference — so the same input produces different ciphertext on every compilation, and batch recovery scripts cannot reuse a fixed pattern. Another key difference is data lifetime: obfstr2's container types (provided by `lib-unknown`) are automatically volatile-zeroed on `Drop`, so decrypted plaintext is wiped as soon as it is used instead of lingering on the stack / heap. That is why obfstr2 exists: **higher reverse-engineering cost, more polymorphic obfuscation, and automatic erasure of sensitive data at the end of its lifetime**.

- Same: literals in, expressions out; `no_std` compatible; obfuscation done at compile time, with `lib-unknown` as the only runtime dependency.
- Different: CasualX macros return a reference borrowing a temporary (`let x = obfstr!(...)` triggers E0716 and can only be used inline), while obfstr2 returns owned containers that can be bound, passed around, and reused; CasualX expands to a single fixed form, obfstr2 takes a different form on every compilation.

Randomness and crypto primitives come from [`lib-unknown`](https://github.com/ZEROLINGG/lib-unknown).


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

### Trade-offs

| We chose | Instead of | Why |
| :--- | :--- | :--- |
| Compile time and size for strength | Minimal runtime decryption overhead | The top tier expands 1KB of input to ~76KB of code (see Benchmarks); runtime is just linear decryption |
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
use obfstr2::{b2, f2, s2, s_fmt};

fn main() {
    // Strings: evaluate to the original at runtime; owned containers that
    // can be bound, passed around, and reused
    let hello = s2!("hello");
    print!("{hello}");
    // Byte strings / byte arrays: dereference to the original `[u8]`
    let b = b2!(b"abc");
    let c = b2!([0x61, 98, 99]);
    assert_eq!(&*b, &*c);
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
| `f1!` / `f2!` / `f3!` | `"path/to/file"` file path literals | Low-latency / Balanced / High-strength |
| `s_fmt!` | `"...{}..."` format string + args (tier 2) | Literal chunks obfuscated, then `format!`; returns `String` (needs `std` / `alloc`) |

Notes:

- String macros expand to `StackStr<N>` / `HeapStr<N>`, bytes and file macros to `StackBytes<N>` / `HeapBytes<N>`; the concrete type may vary between compilations — use type inference instead of fixed type annotations.
- Obfuscation output differs on every compilation (compile-time randomness); the same macro invocation never reproduces an identical byte stream.

## Use Cases vs Non-Use Cases

**Good fit:**

- Hiding strings and constant bytes in `no_std` firmware / bare-metal programs.
- Scenarios that need to evade bulk static-string scanning.

**Not a fit:**

- Scenarios requiring compliance audits or human-readable plaintext.
- Obfuscating huge files (code size inflates ~30–70×, see Benchmarks).
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

MSRV is not declared in `Cargo.toml`; tested stable on `rustc 1.98.1`.

## Benchmarks

End-to-end dyntest measurements below (1024-byte input, dev profile; expanded code size and runtime decryption cost; order-of-magnitude reference only):

| Tier | Expansion size | Runtime cost |
| :--- | :--- | :--- |
| `b1!` | ~39KB | ~0.7ms |
| `b2!` | ~50KB | ~2.6ms |
| `b3!` | ~76KB | ~4.2ms |
| `s1!` / `s2!` / `s3!` | ~34KB / 39KB / 67KB | increases with tier |

### Comparison with CasualX/obfstr

Expansion sizes measured in this session (`cargo-expand 1.0.126`, semantically identical 64-byte programs, in expanded-source characters); runtimes quoted from the repo's existing dyntest logs (1024-byte input, dev profile).

| Scenario | obfstr2 (`s2!` / `b2!`) | CasualX/obfstr | Ratio |
| :--- | :--- | :--- | :--- |
| String expansion size | 20520 | 3304 | ~6.2× |
| Bytes expansion size | 16999 | 2803 | ~6.1× |
| String runtime cost | `s1` 0.79ms / `s2` 2.2ms / `s3` 3.4ms | ~0.6ms | ~1.3–5× |
| Bytes runtime cost | `b1` 0.73ms / `b2` 2.7ms / `b3` 4.2ms | ~0.67ms | ~1.1–6× |

| Dimension | obfstr2 | CasualX/obfstr |
| :--- | :--- | :--- |
| Expansion form | Different on every build (random chunking / stacked primitives / multiple storage forms / junk code) | Fixed single form |
| Return value | Owned containers, can be `let`-bound and passed around | Reference borrowing a temporary; `let` binding triggers E0716, inline use only |
| Plaintext lifetime | Automatically volatile-erased on `Drop` | No erasure |
| Size / speed | ~6× size, several times the cost | Tiny and fast |

Reading: the extra size and time buy batch-recovery cost — a fixed form can be killed by one script, while polymorphism changes the signature on every build.

## Security


If you find a security vulnerability, please file an Issue directly (this repo has no private reporting channel yet).

## Contributing

Issues and Pull Requests are welcome!

- Local verification: `cd obfstr2-macros && cargo test --lib` (dyntest compiles scratch projects on the fly; the full suite takes several minutes).
- Before submitting a PR, read the [Design Philosophy](#design-philosophy): new obfuscation primitives must plug in as `Crypto` / `Storage` table entries (in `obfstr2-macros/src/crypto.rs` and `storage.rs` respectively) and leave the orchestration layer (`core.rs::build_obfuscated_bytes`) untouched.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

[MIT License](./LICENSE)
