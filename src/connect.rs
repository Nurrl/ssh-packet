//! Messages involved in the SSH's **connect** part of the protocol,
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
    /// SSH_MSG_GLOBAL_REQUEST's _request name_.
    pub name: arch::StringAscii,

    /// SSH_MSG_GLOBAL_REQUEST's _want reply_.
    pub want_reply: arch::Bool,

    /// SSH_MSG_GLOBAL_REQUEST's _request-specific data_.
    pub data: todo!(),
}

/// The `SSH_MSG_REQUEST_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 81_u8)]
pub struct RequestSuccess {
    /// SSH_MSG_REQUEST_SUCCESS's _response-specific data_.
    pub data: todo!(),
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
    /// SSH_MSG_REQUEST_SUCCESS's _channel type_.
    pub channel_type: arch::StringAscii,

    /// SSH_MSG_CHANNEL_OPEN's _sender channel_.
    pub sender_channel: u32,

    /// SSH_MSG_CHANNEL_OPEN's _initial window size_.
    pub initial_window_size: u32,

    /// SSH_MSG_CHANNEL_OPEN's _maximum packet size_.
    pub maximum_packet_size: u32,

    pub data: todo!(),
}

/// The `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 91_u8)]
pub struct ChannelOpenConfirmation {
    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION's _recipient channel_.
    pub recipient_channel: u32,

    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION's _sender channel_.
    pub sender_channel: u32,

    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION's _initial window size_.
    pub initial_window_size: u32,

    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION's _maximum packet size_.
    pub maximum_packet_size: u32,

    pub data: todo!(),
}

/// The `SSH_MSG_CHANNEL_OPEN_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.1>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 92_u8)]
pub struct ChannelOpenFailure {
    /// SSH_MSG_CHANNEL_OPEN_FAILURE's _recipient channel_.
    pub recipient_channel: u32,

    /// SSH_MSG_CHANNEL_OPEN_FAILURE's _reason code_.
    pub reason: ChannelOpenFailureReason,

    /// SSH_MSG_CHANNEL_OPEN_FAILURE's _description_.
    pub description: arch::StringUtf8,

    /// SSH_MSG_CHANNEL_OPEN_FAILURE's _language tag_.
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
    /// SSH_MSG_CHANNEL_WINDOW_ADJUST's _recipient channel_.
    pub recipient_channel: u32,

    /// SSH_MSG_CHANNEL_WINDOW_ADJUST's _bytes to add to the window_.
    pub bytes_to_add: u32,
}

/// The `SSH_MSG_CHANNEL_DATA` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 94_u8)]
pub struct ChannelData {
    /// SSH_MSG_CHANNEL_DATA's _recipient channel_.
    pub recipient_channel: u32,

    /// SSH_MSG_CHANNEL_DATA's _bytes to add to the window_.
    pub data: arch::String,
}

/// The `SSH_MSG_CHANNEL_EXTENDED_DATA` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.2>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 95_u8)]
pub struct ChannelExtendedData {
    /// SSH_MSG_CHANNEL_EXTENDED_DATA's _recipient channel_.
    pub recipient_channel: u32,

    /// SSH_MSG_CHANNEL_EXTENDED_DATA's _data type's code_.
    pub data_type_code: ChannelExtendedDataType,

    /// SSH_MSG_CHANNEL_EXTENDED_DATA's _bytes to add to the window_.
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
    /// SSH_MSG_CHANNEL_EOF's _recipient channel_.
    pub recipient_channel: u32,
}

/// The `SSH_MSG_CHANNEL_CLOSE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.3>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 97_u8)]
pub struct ChannelClose {
    /// SSH_MSG_CHANNEL_CLOSE's _recipient channel_.
    pub recipient_channel: u32,
}

/// The `SSH_MSG_CHANNEL_REQUEST` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 98_u8)]
pub struct ChannelRequest {
    /// SSH_MSG_CHANNEL_REQUEST's _recipient channel_.
    pub recipient_channel: u32,

    /// SSH_MSG_CHANNEL_REQUEST's _request type_.
    pub request_type: arch::StringAscii,

    /// SSH_MSG_CHANNEL_REQUEST's _want reply_.
    pub want_reply: arch::Bool,

    /// SSH_MSG_CHANNEL_REQUEST's _request-specific data_.
    pub data: todo!(),
}

/// The `SSH_MSG_CHANNEL_SUCCESS` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 99_u8)]
pub struct ChannelSuccess {
    /// SSH_MSG_CHANNEL_SUCCESS's _recipient channel_.
    pub recipient_channel: u32,
}

/// The `SSH_MSG_CHANNEL_FAILURE` message.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4254#section-5.4>.
#[binrw]
#[derive(Debug)]
#[brw(big, magic = 100_u8)]
pub struct ChannelFailure {
    /// SSH_MSG_CHANNEL_FAILURE's _recipient channel_.
    pub recipient_channel: u32,
}
