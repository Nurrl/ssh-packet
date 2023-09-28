//! Messages involved in the SSH's **authentication** part of the protocol,
//! as defined in the [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) and [RFC 4256](https://datatracker.ietf.org/doc/html/rfc4256).

use binrw::binrw;

use crate::arch;

/// The `SSH_MSG_USERAUTH_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 50_u8)]
pub struct AuthRequest {
    /// SSH_MSG_USERAUTH_REQUEST's _username_.
    pub username: arch::StringUtf8,

    /// SSH_MSG_USERAUTH_REQUEST's _service name_.
    pub service_name: arch::StringAscii,

    #[bw(calc = arch::StringAscii::new(method.as_str()))]
    auth_method: arch::StringAscii,

    /// SSH_MSG_USERAUTH_REQUEST's _method_.
    #[br(args(&auth_method))]
    pub method: AuthMethod,
}

/// The Authentication method in the `SSH_MSG_USERAUTH_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[br(import(method: &str))]
pub enum AuthMethod {
    /// Authenticate using the `publickey` method,
    /// as defined in [RFC4252 section 7](https://datatracker.ietf.org/doc/html/rfc4252#section-7).
    #[br(pre_assert(method == AuthMethod::PUBLICKEY))]
    Publickey {
        #[bw(calc = arch::Bool(signature.is_some()))]
        signed: arch::Bool,

        algorithm: arch::String,
        blob: arch::String,

        #[br(if(*signed))]
        signature: Option<arch::String>,
    },

    /// Authenticate using the `password` method,
    /// as defined in [RFC4252 section 8](https://datatracker.ietf.org/doc/html/rfc4252#section-8).
    #[br(pre_assert(method == AuthMethod::PASSWORD))]
    Password {
        #[bw(calc = arch::Bool(new.is_some()))]
        change: arch::Bool,

        password: arch::StringUtf8,

        #[br(if(*change))]
        new: Option<arch::StringUtf8>,
    },

    /// Authenticate using the `hostbased` method,
    /// as defined in [RFC4252 section 9](https://datatracker.ietf.org/doc/html/rfc4252#section-9).
    #[br(pre_assert(method == AuthMethod::HOSTBASED))]
    Hostbased {
        algorithm: arch::String,
        host_key: arch::String,
        client_fqdn: arch::StringAscii,
        username: arch::StringUtf8,
        signature: arch::String,
    },

    /// Authenticate using the `keyboard-interactive` method,
    /// as defined in [RFC4256 section 3.1](https://datatracker.ietf.org/doc/html/rfc4256#section-3.1).
    #[br(pre_assert(method == AuthMethod::KEYBOARD_INTERACTIVE))]
    KeyboardInteractive {
        language: arch::StringAscii,
        submethods: arch::StringUtf8,
    },
}

impl AuthMethod {
    const PUBLICKEY: &str = "publickey";
    const PASSWORD: &str = "password";
    const HOSTBASED: &str = "hostbased";
    const KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";

    /// Transforms the [`AuthMethod`] to it's SSH identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Publickey { .. } => Self::PUBLICKEY,
            Self::Password { .. } => Self::PASSWORD,
            Self::Hostbased { .. } => Self::HOSTBASED,
            Self::KeyboardInteractive { .. } => Self::KEYBOARD_INTERACTIVE,
        }
    }
}

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
