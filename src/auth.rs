//! Messages involved in the SSH's **authentication** part of the protocol,
//! as defined in the [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252).

use binrw::binrw;

/// The `SSH_MSG_USERAUTH_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 50_u8)]
pub struct AuthRequest {}

/// The `SSH_MSG_USERAUTH_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 51_u8)]
pub struct AuthFailure {}

/// The `SSH_MSG_USERAUTH_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 52_u8)]
pub struct AuthSuccess {}

/// The `SSH_MSG_USERAUTH_BANNER` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 53_u8)]
pub struct AuthBanner {}
