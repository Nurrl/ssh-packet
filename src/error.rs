use thiserror::Error;

/// The error type used in the library.
#[derive(Debug, Error)]
pub enum Error<E> {
    /// An error occured while using [`binrw`].
    BinRw(#[from] binrw::Error),

    /// An error occured manipulating the Cipher trait.
    Cipher(E),
}
