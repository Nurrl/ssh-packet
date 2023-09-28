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

/// The `SSH_MSG_USERAUTH_PK_OK` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-7>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 60_u8)]
pub struct AuthPkOk {
    /// SSH_MSG_USERAUTH_PK_OK's _public key algorithm name from the request_.
    pub algorithm: arch::String,

    /// SSH_MSG_USERAUTH_PK_OK's _public key blob from the request_.
    pub blob: arch::String,
}

/// The `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-8>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 60_u8)]
pub struct AuthPasswdChangereq {
    /// SSH_MSG_USERAUTH_PASSWD_CHANGEREQ's _prompt_.
    pub prompt: arch::StringUtf8,

    /// SSH_MSG_USERAUTH_PASSWD_CHANGEREQ's _language tag_ (deprecated).
    pub language: arch::StringAscii,
}

/// The `SSH_MSG_USERAUTH_INFO_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4256#section-3.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 60_u8)]
pub struct AuthInfoRequest {
    /// SSH_MSG_USERAUTH_INFO_REQUEST's _name_.
    pub name: arch::StringUtf8,

    /// SSH_MSG_USERAUTH_INFO_REQUEST's _instruction_.
    pub instruction: arch::StringUtf8,

    /// SSH_MSG_USERAUTH_INFO_REQUEST's _language tag_ (deprecated).
    pub language: arch::StringAscii,

    #[bw(calc = prompts.len() as u32)]
    num_prompts: u32,

    /// SSH_MSG_USERAUTH_INFO_REQUEST's _prompts_.
    #[br(count = num_prompts)]
    pub prompts: Vec<AuthInfoRequestPrompt>,
}

/// A prompt in the `SSH_MSG_USERAUTH_INFO_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub struct AuthInfoRequestPrompt {
    /// SSH_MSG_USERAUTH_INFO_REQUEST's _prompt text_.
    pub prompt: arch::StringUtf8,

    /// SSH_MSG_USERAUTH_INFO_REQUEST's _echo_.
    pub echo: arch::Bool,
}

/// The `SSH_MSG_USERAUTH_INFO_RESPONSE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4256#section-3.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 61_u8)]
pub struct AuthInfoResponse {
    #[bw(calc = responses.len() as u32)]
    num_responses: u32,

    /// SSH_MSG_USERAUTH_INFO_RESPONSE's _responses_.
    #[br(count = num_responses)]
    pub responses: Vec<arch::StringUtf8>,
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
