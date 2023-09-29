use std::str::Utf8Error;

use binrw::{binrw, helpers};

use crate::Error;

const VERSION: &str = "2.0";

#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    #[br(parse_with = helpers::until(|byte| *byte == b'\n'))]
    blob: Vec<u8>,
}

impl Line {
    fn as_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(&self.blob)
    }
}

/// The SSH identification string as defined in the SSH protocol.
///
/// The format must match the following pattern:
/// `SSH-<protoversion>-<softwareversion>[ <comments>]`.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-4.2>.
#[binrw]
#[derive(Debug, Clone, PartialEq, Eq)]
#[br(try_map = |line: Line| line.as_str()?.parse())]
#[bw(map = |id: &Id| id.to_string().into_bytes())]
pub struct Id {
    /// The SSH's protocol version, should be `2.0` in our case.
    pub protoversion: String,

    /// A string identifying the software curently used, in example `billsSSH_3.6.3q3`.
    pub softwareversion: String,

    /// Optional comments with additionnal informations about the software.
    pub comments: Option<String>,
}

impl Id {
    /// Convenience method to create an `SSH-2.0` identifier string.
    pub fn v2(softwareversion: impl Into<String>, comments: Option<impl Into<String>>) -> Self {
        Self {
            protoversion: VERSION.into(),
            softwareversion: softwareversion.into(),
            comments: comments.map(Into::into),
        }
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSH-{}-{}", self.protoversion, self.softwareversion)?;

        if let Some(comments) = &self.comments {
            write!(f, " {comments}")?;
        }

        write!(f, "\r\n")
    }
}

impl std::str::FromStr for Id {
    type Err = Error<&'static str>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s
            .strip_suffix('\n')
            .map(|line| line.strip_suffix('\r').unwrap_or(line))
            .ok_or(Error::BadIdentifer)?;

        let (id, comments) = data
            .split_once(' ')
            .map_or_else(|| (data, None), |(id, comments)| (id, Some(comments)));

        match id.splitn(3, '-').collect::<Vec<_>>()[..] {
            ["SSH", protoversion, softwareversion]
                if !protoversion.is_empty() && !softwareversion.is_empty() =>
            {
                Ok(Self {
                    protoversion: protoversion.to_string(),
                    softwareversion: softwareversion.to_string(),
                    comments: comments.map(str::to_string),
                })
            }
            _ => Err(Error::BadIdentifer),
        }
    }
}

#[cfg(test)]
mod tests {
    use binrw::{BinRead, BinWrite};
    use rstest::rstest;
    use std::str::FromStr;

    use super::*;

    #[rstest]
    #[case("SSH-2.0-billsSSH_3.6.3q3\r\n")]
    #[case("SSH-1.99-billsSSH_3.6.3q3\n")]
    #[case("SSH-2.0-billsSSH_3.6.3q3 with-comment\r\n")]
    #[case("SSH-2.0-billsSSH_3.6.3q3 utf∞-comment\r\n")]
    #[case("SSH-2.0-billsSSH_3.6.3q3 \r\n")] // empty comment
    fn it_parses_valid_sshid(#[case] text: &str) {
        let parsed = Id::from_str(text).expect(text);
        let read = Id::read(&mut std::io::Cursor::new(text)).expect(text);

        // They read the same from buffer
        assert_eq!(parsed, read)
    }

    #[rstest]
    #[case("")]
    #[case("\r\n")]
    #[case("SSH-2.0-billsSSH_3.6.3q3")]
    #[case("FOO-2.0-billsSSH_3.6.3q3\r\n")]
    #[case("-2.0-billsSSH_3.6.3q3\r\n")]
    #[case("SSH--billsSSH_3.6.3q3\r\n")]
    #[case("SSH-2.0-\r\n")]
    fn it_rejects_invalid_sshid(#[case] text: &str) {
        Id::from_str(text).expect_err(text);
    }

    #[rstest]
    #[case(Id::v2("billsSSH_3.6.3q3", None::<String>))]
    #[case(Id::v2("billsSSH_utf∞", None::<String>))]
    #[case(Id::v2("billsSSH_3.6.3q3", Some("with-comment")))]
    #[case(Id::v2("billsSSH_3.6.3q3", Some("utf∞-comment")))]
    #[case(Id::v2("billsSSH_3.6.3q3", Some("")))] // empty comment
    fn it_writes_stable_ids(#[case] id: Id) {
        let stringified = id.to_string();
        let written = {
            let mut buf = std::io::Cursor::new(Vec::new());
            id.write(&mut buf).unwrap();

            buf.into_inner()
        };

        // They write the same data to buffer
        assert_eq!(stringified.as_bytes(), &written);

        // They reparse in a stable way
        assert_eq!(id, stringified.parse().unwrap());
        assert_eq!(id, Id::read(&mut std::io::Cursor::new(&written)).unwrap());

        // They reparse the other one in a stable way
        assert_eq!(
            id,
            Id::read(&mut std::io::Cursor::new(stringified)).unwrap()
        );
        assert_eq!(id, std::str::from_utf8(&written).unwrap().parse().unwrap());
    }
}
