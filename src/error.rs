use thiserror::Error;

/// The error types that can occur when manipulating this crate.
#[non_exhaustive]
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
