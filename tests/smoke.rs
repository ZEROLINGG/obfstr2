//! 根 crate 冒烟测试：全部 9 个宏的小载荷 roundtrip。
//!
//! 直接调用宏做断言，无需 dyntest 现场建工程，毫秒级。
//! 大载荷（1024B）与裸机链路见 `nostd.rs`；非法输入见 `compile_fail.rs`。
use obfstr2::{b1, b2, b3, f1, f2, f3, s1, s2, s3};

#[test]
fn str_all_tiers_roundtrip() {
    // 空串 / ASCII / 多字节 UTF-8 边界
    assert_eq!(&*s1!(""), "");
    assert_eq!(&*s1!("hello"), "hello");
    assert_eq!(&*s2!("hello"), "hello");
    assert_eq!(&*s3!("hello"), "hello");
    assert_eq!(&*s2!("你好，世界🦀"), "你好，世界🦀");
    assert_eq!(&*s2!("{{literal}}"), "{{literal}}");
    // Display / Debug 与原文一致
    assert_eq!(format!("{}", s2!("abc")), "abc");
    assert_eq!(format!("{:?}", s2!("abc")), "\"abc\"");
}

#[test]
fn bytes_both_forms_all_tiers() {
    // b"..." 与数组形式等价（含 0/255 边界与混写进制）
    let a = b1!(b"abc");
    let b = b1!([0x61, 98, 99]);
    assert_eq!(&*a, &*b);
    assert_eq!(&*b2!(b""), b"");
    assert_eq!(&*b2!([0, 255]), &[0u8, 255]);
    assert_eq!(&*b3!(b"abc"), b"abc");
    assert_eq!(b2!([0x61, 98, 0, 255]).as_slice(), &[97, 98, 0, 255]);
}

#[test]
fn bytes_all_tiers_agree() {
    // 三档对同一输入解码一致
    assert_eq!(&*b1!(b"tier-check"), &*b2!(b"tier-check"));
    assert_eq!(&*b2!(b"tier-check"), &*b3!(b"tier-check"));
    assert_eq!(&*s1!("tier-check"), &*s2!("tier-check"));
    assert_eq!(&*s2!("tier-check"), &*s3!("tier-check"));
}

#[test]
fn file_all_tiers_match_include_bytes() {
    // 路径相对本 crate 的 CARGO_MANIFEST_DIR 解析
    assert_eq!(
        &*f1!("assets/fixture.bin"),
        include_bytes!("../assets/fixture.bin")
    );
    assert_eq!(
        &*f2!("assets/fixture.bin"),
        include_bytes!("../assets/fixture.bin")
    );
    assert_eq!(
        &*f3!("assets/fixture.bin"),
        include_bytes!("../assets/fixture.bin")
    );
}

#[test]
fn owned_containers_can_bind_and_reuse() {
    // 回归 CasualX E0716 差异点：自有容器可绑定、传递、复用
    let hello = s2!("hello");
    assert_eq!(hello.to_uppercase(), "HELLO");
    assert_eq!(&*hello, "hello");
    let b = b2!(b"abc");
    assert_eq!(b.len(), 3);
    assert_eq!(&*b, &*b);
    fn echo_len(data: &[u8]) -> usize {
        data.len()
    }
    assert_eq!(echo_len(&b), 3);
}
