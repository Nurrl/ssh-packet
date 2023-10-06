/// The algorithm parameters for the _Message Authentication Code_.
pub trait Mac {
    /// The size of the MAC at the end of the SSH packet.
    fn size(&self) -> usize;

    /// Whether the MAC is applied over encrypted data.
    fn etm(&self) -> bool;
}
