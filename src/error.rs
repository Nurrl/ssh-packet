use thiserror::Error;

/// The error type used in the library.
#[derive(Debug, Error)]
pub enum Error<E> {
    /// An error occured while using [`binrw`].
    #[error(transparent)]
    BinRw(#[from] binrw::Error),

    /// An error occured while performing I/O operations.
    #[error(transparent)]
    IO(#[from] std::io::Error),

    /// An error occured because the data wasn't UTF-8.
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    /// An error occured manipulating the Cipher trait.
    #[error(transparent)]
    Cipher(E),

    /// The parsed identifier was not conformant.
    #[error("The SSH identifier was either misformatted or misprefixed")]
    BadIdentifer,
}
