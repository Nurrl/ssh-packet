//! Messages involved in the SSH's **authentication** part of the protocol,
//! as defined in the [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252).

use binrw::binrw;

use crate::arch;

/// The `SSH_MSG_USERAUTH_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 50_u8)]
pub struct AuthRequest {}

/// The `SSH_MSG_USERAUTH_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 51_u8)]
pub struct AuthFailure {
    /// SSH_MSG_USERAUTH_FAILURE's _authentications that can continue_.
    pub continue_with: arch::NameList,

    /// SSH_MSG_USERAUTH_FAILURE's _partial success_.
    pub partial_success: arch::Bool,
}

/// The `SSH_MSG_USERAUTH_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 52_u8)]
pub struct AuthSuccess;

/// The `SSH_MSG_USERAUTH_BANNER` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 53_u8)]
pub struct AuthBanner {
    /// SSH_MSG_USERAUTH_BANNER's _message_.
    pub message: arch::StringUtf8,

    /// SSH_MSG_USERAUTH_BANNER's _language tag_.
    pub language: arch::StringAscii,
}
