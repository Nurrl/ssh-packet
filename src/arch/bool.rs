use binrw::binrw;

/// A `boolean` as defined in the SSH protocol.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[brw(big)]
pub struct Bool(
    #[br(map = |n: u8| n > 0)]
    #[bw(map = |b| u8::from(*b))]
    bool,
);

impl std::ops::Not for Bool {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl std::ops::Deref for Bool {
    type Target = bool;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::convert::From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl std::convert::From<Bool> for bool {
    fn from(value: Bool) -> Self {
        value.0
    }
}
