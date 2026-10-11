//! 微型实战：桌面 Agent 启动 → 鉴权 → 心跳上报。
//!
//! 所有敏感常量（后端地址、token、端口、退避系数、状态路径、内嵌资源）在编译期混淆，
//! 对产物跑 `strings` 看不到明文；运行时解密进内存，字符串类容器 `Drop` 时自动擦除。
//! 断言只对明文——多态导致每次编译的密文都不同，永不对密文断言。
//!
//! 跑法：`cargo run --example quickstart`（CI 同步执行，毫秒级）。

use core::ffi::CStr;
use obfstr2::{cs2, f2, fl2, i2, s_fmt2, s2, types::str::Str};

/// 鉴权服务器地址（堆栈二选一，调用方只管 `AsRef<str>`，无需写死容器类型）。
fn license_server() -> impl AsRef<str> {
    s2!("https://license.example.com/v2/check")
}

/// 固定 User-Agent（纯展示多宏同屏，同样不可扫描）。
fn user_agent() -> impl AsRef<str> {
    s2!("obfstr2-agent/0.2")
}

/// API token（字节形态，防 UTF-8 扫描启发式）。
fn api_token() -> Box<dyn Str> {
    let keys: Vec<Box<dyn Str>> =
        vec![Box::new(s2!("tok-7f3a9c1e")), Box::new(s2!("tok-7f3a9c13"))];
    keys[1].clone()
}

/// API 端口（裸值，可直接参与运算与占位符）。
fn api_port() -> u16 {
    i2!(8443u16)
}

/// 重试退避系数（裸浮点，断言请走 `to_bits`）。
fn retry_backoff() -> f64 {
    fl2!(1.5)
}

/// 本地状态路径（解引用即 `CStr`，`as_ptr()` 可直投系统调用）。
fn state_path() -> impl AsRef<CStr> {
    cs2!(c"/var/lib/agent/state")
}

/// 内嵌资源包（路径相对包根 `CARGO_MANIFEST_DIR`，编译期读入）。
fn bundle() -> impl AsRef<[u8]> {
    f2!("assets/fixture.bin")
}

fn main() {
    // 1. 组装鉴权 URL：字面量片段（`?port=`、`/check` 等）同样混淆，占位符照常。
    let url = s_fmt2!("{}?port={}", license_server().as_ref(), api_port());
    assert_eq!(url, "https://license.example.com/v2/check?port=8443");

    // 2. 心跳日志行：整数与浮点裸值直接进占位符。
    let attempt = 3u32;
    let log = s_fmt2!(
        "[{ua}] heartbeat attempt {n}, backoff {b}",
        ua = user_agent().as_ref(),
        n = attempt,
        b = retry_backoff()
    );
    assert_eq!(log, "[obfstr2-agent/0.2] heartbeat attempt 3, backoff 1.5");

    // 3. 其余配置项对拍明文。
    assert_eq!(api_token(), "tok-7f3a9c13");
    assert_eq!(api_port() + 1, 8444u16);
    assert_eq!(retry_backoff().to_bits(), 1.5f64.to_bits());
    assert_eq!(state_path().as_ref(), c"/var/lib/agent/state");
    let _state_ptr = state_path().as_ref().as_ptr();
    assert_eq!(bundle().as_ref(), include_bytes!("../assets/fixture.bin"));

    println!("agent check ok: {url}");
}
