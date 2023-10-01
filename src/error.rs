use thiserror::Error;

/// The error type used in the library.
#[derive(Debug, Error)]
pub enum Error<E> {
    /// An error occured while using [`binrw`].
    #[error(transparent)]
    BinRw(#[from] binrw::Error),

    /// An error occured while performing I/O operations.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An error occured manipulating the Cipher trait.
    #[error(transparent)]
    Cipher(E),

    /// The parsed identifier was not conformant.
    #[error("The SSH identifier was either misformatted or misprefixed")]
    BadIdentifer(String),

    /// An EOF occured while parsing.
    #[error("Unexpected EOF while waiting for SSH identifer")]
    UnexpectedEof,
}

impl<E: PartialEq> PartialEq for Error<E> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::BinRw { .. }, Self::BinRw { .. }) => true,
            (Self::Io(l0), Self::Io(r0)) => l0.kind() == r0.kind(),
            (Self::Cipher(l0), Self::Cipher(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}
