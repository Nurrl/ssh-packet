//! Types defined in the SSH's **architecture** (`SSH-ARCH`) part of the protocol,
//! as defined in the [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251).

mod bool;
pub use bool::Bool;

mod mpint;
pub use mpint::MpInt;

mod namelist;
pub use namelist::NameList;

mod string;
pub use string::{Bytes, StringAscii, StringUtf8};
