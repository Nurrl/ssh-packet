use thiserror::Error;

/// The error types that can occur when manipulating this crate.
#[derive(Debug, Error)]
pub enum Error {
    /// An error occured while performing I/O operations.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The parsed identifier was not conformant.
    #[error("The SSH identifier was either misformatted or misprefixed")]
    BadIdentifer(String),

    /// An EOF occured while parsing.
    #[error("Unexpected EOF while waiting for SSH identifer")]
    UnexpectedEof,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Io(l0), Self::Io(r0)) => l0.kind() == r0.kind(),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}
