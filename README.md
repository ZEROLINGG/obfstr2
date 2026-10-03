# obfstr2

编译期字符串 / 字节 / 文件混淆库（`no_std` 兼容）。

底层随机数与密码原语来自 [`lib-unknown`](https://github.com/ZEROLINGG/lib-unknown)。

## 快速开始

```toml
[dependencies]
obfstr2 = "0.1"
```

```rust
use obfstr2::{s2, b2, f2};

fn main() {
    // 字符串：运行时求值即得原文
    print!("{}", s2!("hello"));
    // 字节串 / 字节数组
    let b = b2!(b"abc");
    let c = b2!([0x61, 98, 99]);
    // 文件：路径相对被编译 crate 的 CARGO_MANIFEST_DIR
    let d = f2!("assets/secret.bin");
}
```

## 宏一览

| 宏 | 输入 | 强度档 |
|---|---|---|
| `s1!` / `s2!` / `s3!` | `"..."` 字符串字面量 | 低延迟 / 均衡 / 高强度 |
| `b1!` / `b2!` / `b3!` | `b"..."` 或 `[0x41, 66, ...]`（元素 0..=255） | 低延迟 / 均衡 / 高强度 |
| `f1!` / `f2!` / `f3!` | `"path/to/file"` 文件路径字面量 | 低延迟 / 均衡 / 高强度 |

说明：

- 字符串宏展开为 `StackStr<N>` / `HeapStr<N>`，字节与文件宏展开为 `StackBytes<N>` / `HeapBytes<N>`；返回的具体类型可能随编译变化，请使用类型推断，不要写死类型标注。
- 每次编译的混淆结果都不同（编译期随机），同一宏名的输出字节流不可复现。

## 平台与环境支持

- `no_std` 可用；`Heap*` 类型需启用 `alloc` feature。
- `fN!` 读取的文件需在编译时存在（路径相对被编译 crate 的 manifest 目录）。

## 开源协议

[MIT License](LICENSE)
