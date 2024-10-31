//! Types defined in the SSH's **architecture** (`SSH-ARCH`) part of the protocol,
//! as defined in the [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251).

mod bytes;
pub use bytes::Bytes;

mod string;
pub use string::{StringAscii, StringUtf8};

mod namelist;
pub use namelist::NameList;

mod mpint;
pub use mpint::MpInt;

mod bool;
pub use bool::Bool;

mod lengthed;
pub use lengthed::Lengthed;
