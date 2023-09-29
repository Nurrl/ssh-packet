use binrw::binrw;

pub mod arch;
pub mod connect;
pub mod trans;
pub mod userauth;

#[cfg(doc)]
use userauth::{
    AuthInfoRequest, AuthInfoResponse, AuthMethod, AuthPasswdChangereq, AuthPkOk, AuthRequest,
};

/// The purpose of this macro is to automatically document variants
/// and link to the underlying item documentation.
macro_rules! message {
    ($( $name:ident($path:path) ),+ $(,)?) => {
        /// A SSH 2.0 message in it's decrypted form.
        ///
        /// The [`AuthPkOk`], [`AuthPasswdChangereq`], [`AuthInfoRequest`] and [`AuthInfoResponse`]
        /// messages still need to be looked for manually when sending a [`AuthRequest`]
        /// respectively with a [`AuthMethod::Publickey`], [`AuthMethod::Password`] or [`AuthMethod::KeyboardInteractive`]
        /// because they share the same `magic` byte in the protocol.
        #[binrw]
        #[derive(Debug)]
        #[brw(big)]
        pub enum Message {
            $(
                #[doc = concat!("See [`", stringify!($path), "`] for more details.")]
                $name($path)
            ),+
        }
    };
}

message! {
    Disconnect(trans::Disconnect),
    Ignore(trans::Ignore),
    Debug(trans::Debug),
    Unimplemented(trans::Unimplemented),
    ServiceRequest(trans::ServiceRequest),
    ServiceAccept(trans::ServiceAccept),
    KexInit(trans::KexInit),
    NewKeys(trans::NewKeys),

    AuthRequest(userauth::AuthRequest),
    AuthFailure(userauth::AuthFailure),
    AuthSuccess(userauth::AuthSuccess),
    AuthBanner(userauth::AuthBanner),

    GlobalRequest(connect::GlobalRequest),
    RequestSuccess(connect::RequestSuccess),
    ChannelOpen(connect::ChannelOpen),
    ChannelOpenConfirmation(connect::ChannelOpenConfirmation),
    ChannelOpenFailure(connect::ChannelOpenFailure),
    ChannelWindowAdjust(connect::ChannelWindowAdjust),
    ChannelData(connect::ChannelData),
    ChannelExtendedData(connect::ChannelExtendedData),
    ChannelEof(connect::ChannelEof),
    ChannelClose(connect::ChannelClose),
    ChannelRequest(connect::ChannelRequest),
    ChannelSuccess(connect::ChannelSuccess),
    ChannelFailure(connect::ChannelFailure),
}
