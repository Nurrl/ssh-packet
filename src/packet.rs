use binrw::{
    binrw, helpers,
    meta::{ReadEndian, WriteEndian},
    BinRead, BinWrite,
};

use crate::Error;

/// A SSH 2.0 binary packet representation, including it's encrypted payload.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4253#section-6>.
#[binrw]
#[derive(Debug)]
#[brw(big)]
pub struct Packet {
    #[bw(assert(payload.len() > u32::MAX as usize, "payload size is too large"), calc = payload.len() as u32)]
    len: u32,

    #[bw(assert(padding.len() > u8::MAX as usize, "padding size is too large"), calc = padding.len() as u8)]
    padding_len: u8,

    /// SSH packet's payload as binary.
    #[br(count = len - padding_len as u32 - 1)]
    pub payload: Vec<u8>,

    /// SSH packet's padding as binary.
    #[br(count = padding_len)]
    pub padding: Vec<u8>,

    /// SSH packet's Message Authentication Code as binary.
    #[br(parse_with = helpers::until_eof)]
    pub mac: Vec<u8>,
}

impl Packet {
    /// Decrypt the received [`Packet`] from the remote into `T`.
    pub fn decrypt<T, C>(self, cipher: &mut C) -> Result<T, Error<C::Err>>
    where
        for<'r> T: BinRead<Args<'r> = ()> + ReadEndian,
        C: Cipher,
    {
        let payload = cipher.decrypt(self).map_err(Error::Cipher)?;

        Ok(T::read(&mut std::io::Cursor::new(payload))?)
    }

    /// Encrypt `T` to a [`Packet`] to be sent to the remote.
    pub fn encrypt<T, C>(message: T, cipher: &mut C) -> Result<Self, Error<C::Err>>
    where
        for<'w> T: BinWrite<Args<'w> = ()> + WriteEndian,
        C: Cipher,
    {
        let mut payload = std::io::Cursor::new(Vec::new());
        message.write(&mut payload)?;

        cipher.encrypt(payload.into_inner()).map_err(Error::Cipher)
    }
}

/// The cipher implemented to `decrypt` data from a [`Packet`]
/// or `encrypt` data to [`Packet`].
pub trait Cipher {
    /// The associated error which can be returned when encrypting or decrypting.
    type Err;

    /// Transform the [`Packet`] using the [`Cipher`] into it's decrypted `payload`.
    fn decrypt(&mut self, packet: Packet) -> Result<Vec<u8>, Self::Err>;

    /// Transform the `payload` into it's encrypted [`Packet`] using the [`Cipher`].
    fn encrypt(&mut self, payload: Vec<u8>) -> Result<Packet, Self::Err>;
}
