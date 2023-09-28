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
    /// Username for the auth request.
    pub username: arch::StringUtf8,

    /// Service name to query.
    pub service_name: arch::StringAscii,

    #[bw(calc = arch::StringAscii::new(method.as_str()))]
    auth_method: arch::StringAscii,

    /// Authentication method used.
    #[br(args(&auth_method))]
    pub method: AuthMethod,
}

/// The Authentication method in the `SSH_MSG_USERAUTH_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[br(import(method: &str))]
pub enum AuthMethod {
    /// Authenticate using the `none` method,
    /// as defined in [RFC4252 section 5.2](https://datatracker.ietf.org/doc/html/rfc4252#section-5.2).
    #[br(pre_assert(method == AuthMethod::NONE))]
    None,

    /// Authenticate using the `publickey` method,
    /// as defined in [RFC4252 section 7](https://datatracker.ietf.org/doc/html/rfc4252#section-7).
    #[br(pre_assert(method == AuthMethod::PUBLICKEY))]
    Publickey {
        #[bw(calc = arch::Bool(signature.is_some()))]
        signed: arch::Bool,

        /// Public key algorithm's name.
        algorithm: arch::String,
        /// Public key blob.
        blob: arch::String,

        /// The optional signature of the authentication packet,
        /// signed with the according private key.
        #[br(if(*signed))]
        signature: Option<arch::String>,
    },

    /// Authenticate using the `password` method,
    /// as defined in [RFC4252 section 8](https://datatracker.ietf.org/doc/html/rfc4252#section-8).
    #[br(pre_assert(method == AuthMethod::PASSWORD))]
    Password {
        #[bw(calc = arch::Bool(new.is_some()))]
        change: arch::Bool,

        /// Plaintext password.
        password: arch::StringUtf8,

        /// In the case of a the receival of a [`AuthPasswdChangereq`],
        /// the new password to be set in place of the old one.
        #[br(if(*change))]
        new: Option<arch::StringUtf8>,
    },

    /// Authenticate using the `hostbased` method,
    /// as defined in [RFC4252 section 9](https://datatracker.ietf.org/doc/html/rfc4252#section-9).
    #[br(pre_assert(method == AuthMethod::HOSTBASED))]
    Hostbased {
        /// Public key algorithm for the host key.
        algorithm: arch::String,

        /// Public host key and certificates for client host.
        host_key: arch::String,

        /// Client host name expressed as the FQDN.
        client_fqdn: arch::StringAscii,

        /// User name on the client host.
        username: arch::StringUtf8,

        /// The signature of the authentication packet.
        signature: arch::String,
    },

    /// Authenticate using the `keyboard-interactive` method,
    /// as defined in [RFC4256 section 3.1](https://datatracker.ietf.org/doc/html/rfc4256#section-3.1).
    #[br(pre_assert(method == AuthMethod::KEYBOARD_INTERACTIVE))]
    KeyboardInteractive {
        /// Language tag.
        language: arch::StringAscii,

        /// A hint for the prefered interactive submethod.
        submethods: arch::StringUtf8,
    },
}

impl AuthMethod {
    const NONE: &str = "none";
    const PUBLICKEY: &str = "publickey";
    const PASSWORD: &str = "password";
    const HOSTBASED: &str = "hostbased";
    const KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";

    /// Transforms the [`AuthMethod`] to it's SSH identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None { .. } => Self::NONE,
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
    /// Public key algorithm name from the request.
    pub algorithm: arch::String,

    /// Public key blob from the request.
    pub blob: arch::String,
}

/// The `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4252#section-8>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 60_u8)]
pub struct AuthPasswdChangereq {
    /// Password change prompt.
    pub prompt: arch::StringUtf8,

    /// Language tag (deprecated).
    pub language: arch::StringAscii,
}

/// The `SSH_MSG_USERAUTH_INFO_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4256#section-3.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 60_u8)]
pub struct AuthInfoRequest {
    /// Name of the challenge.
    pub name: arch::StringUtf8,

    /// Instructions for the challenge.
    pub instruction: arch::StringUtf8,

    /// Language tag (deprecated).
    pub language: arch::StringAscii,

    #[bw(calc = prompts.len() as u32)]
    num_prompts: u32,

    /// The challenge's prompts.
    #[br(count = num_prompts)]
    pub prompts: Vec<AuthInfoRequestPrompt>,
}

/// A prompt in the `SSH_MSG_USERAUTH_INFO_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub struct AuthInfoRequestPrompt {
    /// Challenge prompt text.
    pub prompt: arch::StringUtf8,

    /// Whether the client should echo back typed characters.
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

    /// Responses to the provided challenge.
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
    /// Authentications that can continue.
    pub continue_with: arch::NameList,

    /// Partial success.
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
    /// The auth banner message.
    pub message: arch::StringUtf8,

    /// Language tag.
    pub language: arch::StringAscii,
}
