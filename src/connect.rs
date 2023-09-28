//! Messages involved in the SSH's **connect** (`SSH-CONNECT`) part of the protocol,
//! as defined in the [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254).

use binrw::binrw;

use crate::arch;

/// The `SSH_MSG_GLOBAL_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 80_u8)]
pub struct GlobalRequest {
    #[bw(calc = arch::StringAscii::new(context.as_str()))]
    kind: arch::StringAscii,

    /// Whether the sender wants a reply.
    pub want_reply: arch::Bool,

    /// The context of the global request.
    #[br(args(&kind))]
    pub context: GlobalRequestContext,
}

/// The `context` in the `SSH_MSG_GLOBAL_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
#[br(import(kind: &str))]
pub enum GlobalRequestContext {
    /// A request of type `tcpip-forward`,
    /// as defined in [RFC4254 section 7.1](https://datatracker.ietf.org/doc/html/rfc4254#section-7.1).
    #[br(pre_assert(kind == GlobalRequestContext::TCPIP_FORWARD))]
    TcpipForward {
        bind_address: arch::String,
        bind_port: u32,
    },

    /// A request of type `cancel-tcpip-forward`,
    /// as defined in [RFC4254 section 7.1](https://datatracker.ietf.org/doc/html/rfc4254#section-7.1).
    #[br(pre_assert(kind == GlobalRequestContext::CANCEL_TCPIP_FORWARD))]
    CancelTcpipForward {
        bind_address: arch::String,
        bind_port: u32,
    },
}

impl GlobalRequestContext {
    const TCPIP_FORWARD: &str = "tcpip-forward";
    const CANCEL_TCPIP_FORWARD: &str = "cancel-tcpip-forward";

    /// Get the [`GlobalRequestContext`]'s SSH identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TcpipForward { .. } => Self::TCPIP_FORWARD,
            Self::CancelTcpipForward { .. } => Self::CANCEL_TCPIP_FORWARD,
        }
    }
}

/// The `SSH_MSG_REQUEST_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 81_u8)]
pub struct RequestSuccess {
    /// The context of the global response.
    pub context: RequestSuccessContext,
}

/// The `context` in the `SSH_MSG_GLOBAL_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub enum RequestSuccessContext {
    /// An empty response context for standard global requests.
    Empty,

    /// A reponse to a `tcpip-forward` or a `cancel-tcpip-forward`,
    /// if the provided port was `0` and `want_reply` was [`true`],
    /// as defined in [RFC4254 section 7.1](https://datatracker.ietf.org/doc/html/rfc4254#section-7.1).
    BoundPort { bound_port: u32 },
}

/// The `SSH_MSG_REQUEST_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 82_u8)]
pub struct RequestFailure;

/// The `SSH_MSG_CHANNEL_OPEN` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 90_u8)]
pub struct ChannelOpen {
    #[bw(calc = arch::StringAscii::new(context.as_str()))]
    kind: arch::StringAscii,

    /// Sender channel.
    pub sender_channel: u32,

    /// Initial window size, in bytes.
    pub initial_window_size: u32,

    /// Maximum packet size, in bytes.
    pub maximum_packet_size: u32,

    /// The context of the open request.
    #[br(args(&kind))]
    pub context: ChannelOpenContext,
}

/// The `context` in the `SSH_MSG_CHANNEL_OPEN` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
#[br(import(kind: &str))]
pub enum ChannelOpenContext {
    /// A channel of type `session`,
    /// as defined in [RFC4254 section 6.1](https://datatracker.ietf.org/doc/html/rfc4254#section-6.1).
    #[br(pre_assert(kind == ChannelOpenContext::SESSION))]
    Session,

    /// A channel of type `x11`,
    /// as defined in [RFC4254 section 6.3.2](https://datatracker.ietf.org/doc/html/rfc4254#section-6.3.2).
    #[br(pre_assert(kind == ChannelOpenContext::X11))]
    X11 {
        originator_address: arch::StringAscii,
        originator_port: u32,
    },

    /// A channel of type `forwarded-tcpip`,
    /// as defined in [RFC4254 section 7.2](https://datatracker.ietf.org/doc/html/rfc4254#section-7.2).
    #[br(pre_assert(kind == ChannelOpenContext::FORWARDED_TCPIP))]
    ForwardedTcpip {
        address: arch::StringAscii,
        port: u32,
        originator_address: arch::StringAscii,
        originator_port: u32,
    },

    /// A channel of type `direct-tcpip`,
    /// as defined in [RFC4254 section 7.2](https://datatracker.ietf.org/doc/html/rfc4254#section-7.2).
    #[br(pre_assert(kind == ChannelOpenContext::DIRECT_TCPIP))]
    DirectTcpip {
        address: arch::StringAscii,
        port: u32,
        originator_address: arch::StringAscii,
        originator_port: u32,
    },
}

impl ChannelOpenContext {
    const SESSION: &str = "session";
    const X11: &str = "x11";
    const FORWARDED_TCPIP: &str = "forwarded-tcpip";
    const DIRECT_TCPIP: &str = "direct-tcpip";

    /// Get the [`ChannelOpenContext`]'s SSH identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Session { .. } => Self::SESSION,
            Self::X11 { .. } => Self::X11,
            Self::ForwardedTcpip { .. } => Self::FORWARDED_TCPIP,
            Self::DirectTcpip { .. } => Self::DIRECT_TCPIP,
        }
    }
}

/// The `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 91_u8)]
pub struct ChannelOpenConfirmation {
    /// Recipient channel.
    pub recipient_channel: u32,

    /// Sender channel.
    pub sender_channel: u32,

    /// Initial window size, in bytes.
    pub initial_window_size: u32,

    /// Maximum packet size, in bytes.
    pub maximum_packet_size: u32,
}

/// The `SSH_MSG_CHANNEL_OPEN_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 92_u8)]
pub struct ChannelOpenFailure {
    /// Recipient channel.
    pub recipient_channel: u32,

    /// Reason for the channel opening failure.
    pub reason: ChannelOpenFailureReason,

    /// Description of the reason.
    pub description: arch::StringUtf8,

    /// Language tag.
    pub language: arch::StringAscii,
}

/// The `reason` for failure in the `SSH_MSG_CHANNEL_OPEN_FAILURE` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub enum ChannelOpenFailureReason {
    /// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
    #[brw(magic = 1_u32)]
    AdministrativelyProhibited,

    /// `SSH_OPEN_CONNECT_FAILED`.
    #[brw(magic = 2_u32)]
    ConnectFailed,

    /// `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`.
    #[brw(magic = 3_u32)]
    UnknownChannelType,

    /// `SSH_OPEN_RESOURCE_SHORTAGE`.
    #[brw(magic = 4_u32)]
    ResourceShortage,

    /// Any other failure reason, may be non-standard.
    ///
    /// The 'reason' values in the range of `0xFE000000`
    /// through `0xFFFFFFFF` are reserved for PRIVATE USE.
    Other(u32),
}

/// The `SSH_MSG_CHANNEL_WINDOW_ADJUST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 93_u8)]
pub struct ChannelWindowAdjust {
    /// Recipient channel.
    pub recipient_channel: u32,

    /// Bytes to add to the window.
    pub bytes_to_add: u32,
}

/// The `SSH_MSG_CHANNEL_DATA` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 94_u8)]
pub struct ChannelData {
    /// Recipient channel.
    pub recipient_channel: u32,

    /// Data bytes to transport.
    pub data: arch::String,
}

/// The `SSH_MSG_CHANNEL_EXTENDED_DATA` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 95_u8)]
pub struct ChannelExtendedData {
    /// Recipient channel.
    pub recipient_channel: u32,

    /// Data type's code.
    pub data_type_code: ChannelExtendedDataType,

    /// Data bytes to transport.
    pub data: arch::String,
}

/// The `type` of extended data in the `SSH_MSG_CHANNEL_EXTENDED_DATA` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub enum ChannelExtendedDataType {
    /// `SSH_EXTENDED_DATA_STDERR`.
    #[brw(magic = 1_u32)]
    Stderr,

    /// Any other extended data type, may be non-standard.
    ///
    /// The 'type' values in the range of `0xFE000000`
    /// through `0xFFFFFFFF` are reserved for PRIVATE USE.
    Other(u32),
}

/// The `SSH_MSG_CHANNEL_EOF` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 96_u8)]
pub struct ChannelEof {
    /// Recipient channel.
    pub recipient_channel: u32,
}

/// The `SSH_MSG_CHANNEL_CLOSE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 97_u8)]
pub struct ChannelClose {
    /// Recipient channel.
    pub recipient_channel: u32,
}

/// The `SSH_MSG_CHANNEL_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 98_u8)]
pub struct ChannelRequest {
    /// Recipient channel.
    pub recipient_channel: u32,

    #[bw(calc = arch::StringAscii::new(context.as_str()))]
    kind: arch::StringAscii,

    /// Whether the sender wants a reply.
    pub want_reply: arch::Bool,

    /// The context of the channel request.
    #[br(args(&kind))]
    pub context: ChannelRequestContext,
}

/// The `context` in the `SSH_MSG_CHANNEL_REQUEST` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
#[br(import(kind: &str))]
pub enum ChannelRequestContext {
    /// A request of type `pty-req`,
    /// as defined in [RFC4254 section 6.2](https://datatracker.ietf.org/doc/html/rfc4254#section-6.2).
    #[br(pre_assert(kind == ChannelRequestContext::PTY))]
    Pty {
        term: arch::String,
        width_chars: u32,
        height_chars: u32,
        width_pixels: u32,
        height_pixels: u32,
        modes: arch::String,
    },

    /// A request of type `x11-req`,
    /// as defined in [RFC4254 section 6.3](https://datatracker.ietf.org/doc/html/rfc4254#section-6.3).
    #[br(pre_assert(kind == ChannelRequestContext::X11))]
    X11 {
        single_connection: arch::Bool,
        x11_authentication_protocol: arch::String,
        x11_authentication_cookie: arch::String,
        x11_screen_number: u32,
    },

    /// A request of type `env`,
    /// as defined in [RFC4254 section 6.4](https://datatracker.ietf.org/doc/html/rfc4254#section-6.4).
    #[br(pre_assert(kind == ChannelRequestContext::ENV))]
    Env {
        name: arch::String,
        value: arch::String,
    },

    /// A request of type `shell`,
    /// as defined in [RFC4254 section 6.5](https://datatracker.ietf.org/doc/html/rfc4254#section-6.5).
    #[br(pre_assert(kind == ChannelRequestContext::SHELL))]
    Shell,

    /// A request of type `exec`,
    /// as defined in [RFC4254 section 6.5](https://datatracker.ietf.org/doc/html/rfc4254#section-6.5).
    #[br(pre_assert(kind == ChannelRequestContext::EXEC))]
    Exec { command: arch::String },

    /// A request of type `subsystem`,
    /// as defined in [RFC4254 section 6.5](https://datatracker.ietf.org/doc/html/rfc4254#section-6.5).
    #[br(pre_assert(kind == ChannelRequestContext::SUBSYSTEM))]
    Subsystem { name: arch::String },

    /// A request of type `window-change`,
    /// as defined in [RFC4254 section 6.7](https://datatracker.ietf.org/doc/html/rfc4254#section-6.7).
    #[br(pre_assert(kind == ChannelRequestContext::WINDOW_CHANGE))]
    WindowChange {
        width_chars: u32,
        height_chars: u32,
        width_pixels: u32,
        height_pixels: u32,
    },

    /// A request of type `xon-xoff`,
    /// as defined in [RFC4254 section 6.8](hhttps://datatracker.ietf.org/doc/html/rfc4254#section-6.8).
    #[br(pre_assert(kind == ChannelRequestContext::XON_XOFF))]
    XonXoff { client_can_do: arch::Bool },

    /// A request of type `signal`,
    /// as defined in [RFC4254 section 6.9](hhttps://datatracker.ietf.org/doc/html/rfc4254#section-6.9).
    #[br(pre_assert(kind == ChannelRequestContext::SIGNAL))]
    Signal { name: arch::String },

    /// A request of type `exit-status`,
    /// as defined in [RFC4254 section 6.10](hhttps://datatracker.ietf.org/doc/html/rfc4254#section-6.10).
    #[br(pre_assert(kind == ChannelRequestContext::EXIT_STATUS))]
    ExitStatus { code: u32 },

    /// A request of type `exit-signal`,
    /// as defined in [RFC4254 section 6.10](hhttps://datatracker.ietf.org/doc/html/rfc4254#section-6.10).
    #[br(pre_assert(kind == ChannelRequestContext::EXIT_SIGNAL))]
    ExitSignal {
        name: arch::String,
        core_dumped: arch::Bool,
        error_message: arch::StringUtf8,
        language: arch::StringAscii,
    },
}

impl ChannelRequestContext {
    const PTY: &str = "pty-req";
    const X11: &str = "x11-req";
    const ENV: &str = "env";
    const SHELL: &str = "shell";
    const EXEC: &str = "exec";
    const SUBSYSTEM: &str = "subsystem";
    const WINDOW_CHANGE: &str = "window-change";
    const XON_XOFF: &str = "xon-xoff";
    const SIGNAL: &str = "signal";
    const EXIT_STATUS: &str = "exit-status";
    const EXIT_SIGNAL: &str = "exit-signal";

    /// Get the [`ChannelRequestContext`]'s SSH identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pty { .. } => Self::PTY,
            Self::X11 { .. } => Self::X11,
            Self::Env { .. } => Self::ENV,
            Self::Shell { .. } => Self::SHELL,
            Self::Exec { .. } => Self::EXEC,
            Self::Subsystem { .. } => Self::SUBSYSTEM,
            Self::WindowChange { .. } => Self::WINDOW_CHANGE,
            Self::XonXoff { .. } => Self::XON_XOFF,
            Self::Signal { .. } => Self::SIGNAL,
            Self::ExitStatus { .. } => Self::EXIT_STATUS,
            Self::ExitSignal { .. } => Self::EXIT_SIGNAL,
        }
    }
}

/// The `SSH_MSG_CHANNEL_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 99_u8)]
pub struct ChannelSuccess {
    /// Recipient channel.
    pub recipient_channel: u32,
}

/// The `SSH_MSG_CHANNEL_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 100_u8)]
pub struct ChannelFailure {
    /// Recipient channel.
    pub recipient_channel: u32,
}
