#![doc = include_str!("../README.md")]

pub use ::binrw;

mod packet;
pub use packet::{Cipher, Packet};

mod error;
pub use error::Error;

mod message;
pub use message::{arch, connect, trans, userauth, Message};

const VERSION: &str = "2.0";

/// The SSH identification string as defined in the SSH protocol.
///
/// The format must match the following pattern:
/// `SSH-<protoversion>-<softwareversion>[ <comments>]\r\n`.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-4.2>.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    /// The SSH's protocol version, should be `2.0` in our case.
    pub protoversion: String,

    /// A string identifying the software curently used, in example `billsSSH_3.6.3q3`.
    pub softwareversion: String,

    /// Optional comments with additionnal informations about the software.
    pub comments: Option<String>,
}

impl Identifier {
    /// Convenience method to create an `SSH-2.0` identifier string.
    pub fn v2(softwareversion: impl Into<String>, comments: Option<impl Into<String>>) -> Self {
        Self {
            protoversion: VERSION.into(),
            softwareversion: softwareversion.into(),
            comments: comments.map(Into::into),
        }
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSH-{}-{}", self.protoversion, self.softwareversion)?;

        if let Some(comments) = &self.comments {
            write!(f, " {comments}",)?;
        }

        write!(f, "\r\n")
    }
}

impl std::str::FromStr for Identifier {
    type Err = Error<()>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (id, comments) = s
            .split_once(' ')
            .map_or_else(|| (s, None), |(id, comments)| (id, Some(comments)));

        match id.splitn(3, '-').collect::<Vec<_>>()[..] {
            ["SSH", protoversion, softwareversion] => Ok(Self {
                protoversion: protoversion.to_string(),
                softwareversion: softwareversion.to_string(),
                comments: comments.map(str::to_string),
            }),
            _ => Err(Error::BadIdentifer),
        }
    }
}
