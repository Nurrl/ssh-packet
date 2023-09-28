//! Messages involved in the SSH's **transport** part of the protocol,
//! as defined in the [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253).

use binrw::binrw;

use crate::arch;

/// The `SSH_MSG_DISCONNECT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 1_u8)]
pub struct Disconnect {
    /// SSH_MSG_DISCONNECT's _reason code_.
    pub reason: DisconnectReason,

    /// SSH_MSG_DISCONNECT's _description_.
    pub description: arch::StringUtf8,

    /// SSH_MSG_DISCONNECT's _language tag_.
    pub language: arch::StringAscii,
}

/// The `reason` for disconnect in the `SSH_MSG_DISCONNECT` message.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub enum DisconnectReason {
    /// `SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT`.
    #[brw(magic = 1_u32)]
    HostNotAllowedToConnect,

    /// `SSH_DISCONNECT_PROTOCOL_ERROR`.
    #[brw(magic = 2_u32)]
    ProtocolError,

    /// `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`.
    #[brw(magic = 3_u32)]
    KeyExchangeFailed,

    /// `SSH_DISCONNECT_RESERVED`.
    #[brw(magic = 4_u32)]
    Reserved,

    /// `SSH_DISCONNECT_MAC_ERROR`.
    #[brw(magic = 5_u32)]
    MacError,

    /// `SSH_DISCONNECT_COMPRESSION_ERROR`.
    #[brw(magic = 6_u32)]
    CompressionError,

    /// `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`.
    #[brw(magic = 7_u32)]
    ServiceNotAvailable,

    /// `SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED`.
    #[brw(magic = 8_u32)]
    ProtocolVersionNotSupported,

    /// `SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE`.
    #[brw(magic = 9_u32)]
    HostKeyNotVerifiable,

    /// `SSH_DISCONNECT_CONNECTION_LOST`.
    #[brw(magic = 10_u32)]
    ConnectionLost,

    /// `SSH_DISCONNECT_BY_APPLICATION`.
    #[brw(magic = 11_u32)]
    ByApplication,

    /// `SSH_DISCONNECT_TOO_MANY_CONNECTIONS`.
    #[brw(magic = 12_u32)]
    TooManyConnections,

    /// `SSH_DISCONNECT_AUTH_CANCELLED_BY_USER`.
    #[brw(magic = 13_u32)]
    AuthCancelledByUser,

    /// `SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE`.
    #[brw(magic = 14_u32)]
    NoMoreAuthMethodsAvailable,

    /// `SSH_DISCONNECT_ILLEGAL_USER_NAME`.
    #[brw(magic = 15_u32)]
    IllegalUserName,

    /// Any other disconnect reason, may be non-standard.
    ///
    /// The 'reason code' values in the range of `0xFE000000`
    /// through `0xFFFFFFFF` are reserved for PRIVATE USE.
    Other(u32),
}

/// The `SSH_MSG_IGNORE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 2_u8)]
pub struct Ignore {
    /// SSH_MSG_IGNORE's _data_.
    pub data: arch::String,
}

/// The `SSH_MSG_DEBUG` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.3>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 4_u8)]
pub struct Debug {
    /// SSH_MSG_DEBUG's _always_display_.
    pub always_display: arch::Bool,

    /// SSH_MSG_DEBUG's _message_.
    pub message: arch::StringUtf8,

    /// SSH_MSG_DEBUG's _language_.
    pub language: arch::StringAscii,
}

/// The `SSH_MSG_UNIMPLEMENTED` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-11.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 3_u8)]
pub struct Unimplemented {
    /// SSH_MSG_UNIMPLEMENTED's _packet sequence number of rejected message_.
    pub seq: u32,
}

/// The `SSH_MSG_SERVICE_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-10>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 5_u8)]
pub struct ServiceRequest {
    /// SSH_MSG_SERVICE_REQUEST's _service name_.
    pub service_name: u32,
}

/// The `SSH_MSG_SERVICE_ACCEPT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-10>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 6_u8)]
pub struct ServiceAccept {
    /// SSH_MSG_SERVICE_ACCEPT's _service name_.
    pub service_name: u32,
}

/// The `SSH_MSG_KEXINIT` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-7.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 20_u8)]
pub struct KexInit {
    /// SSH_MSG_KEXINIT's _cookie_.
    pub cookie: [u8; 16],

    /// SSH_MSG_KEXINIT's _kex_algorithms_.
    pub kex_algorithms: arch::NameList,

    /// SSH_MSG_KEXINIT's _server_host_key_algorithms_.
    pub server_host_key_algorithms: arch::NameList,

    /// SSH_MSG_KEXINIT's _encryption_algorithms_client_to_server_.
    pub encryption_algorithms_client_to_server: arch::NameList,

    /// SSH_MSG_KEXINIT's _encryption_algorithms_server_to_client_.
    pub encryption_algorithms_server_to_client: arch::NameList,

    /// SSH_MSG_KEXINIT's _mac_algorithms_client_to_server_.
    pub mac_algorithms_client_to_server: arch::NameList,

    /// SSH_MSG_KEXINIT's _mac_algorithms_server_to_client_.
    pub mac_algorithms_server_to_client: arch::NameList,

    /// SSH_MSG_KEXINIT's _compression_algorithms_client_to_server_.
    pub compression_algorithms_client_to_server: arch::NameList,

    /// SSH_MSG_KEXINIT's _compression_algorithms_server_to_client_.
    pub compression_algorithms_server_to_client: arch::NameList,

    /// SSH_MSG_KEXINIT's _languages_client_to_server_.
    pub languages_client_to_server: arch::NameList,

    /// SSH_MSG_KEXINIT's _languages_server_to_client_.
    pub languages_server_to_client: arch::NameList,

    /// SSH_MSG_KEXINIT's _first_kex_packet_follows_.
    pub first_kex_packet_follows: arch::Bool,

    reserved: u32,
}

/// The `SSH_MSG_NEWKEYS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-7.3>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 21_u8)]
pub struct NewKeys;
