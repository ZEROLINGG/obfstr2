//! 档位适配层：各类型载荷 → 字节混淆内核 → 容器 / 裸值的薄包装。
//!
//! 档位参数见 `crate::core::{TIER_LOW, TIER_BALANCED, TIER_HIGH}`；
//! 输入解析见 `crate::parse`。

mod bytes;
mod cstr;
mod float;
mod int;
mod str;

pub(crate) use bytes::{b1, b2, b3, want_heap};
pub(crate) use cstr::{cs1, cs2, cs3};
pub(crate) use float::{fl1, fl2, fl3};
pub(crate) use int::{i1, i2, i3};
pub(crate) use str::{s1, s2, s3};
