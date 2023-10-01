use binrw::binrw;

use super::StringAscii;

/// A `name-list` as defined in the SSH protocol,
/// a `,`-separated list of **ASCII** identifiers,
/// prefixed with it's `size` as a [`u32`].
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct NameList(StringAscii);

impl NameList {
    /// Create new [`NameList`] from a list of names.
    pub fn new(names: &[impl std::borrow::Borrow<str>]) -> Self {
        Self(StringAscii::new(names.join(",")))
    }

    /// Retrieve the first name from `self` that is also in `other`.
    pub fn preferred(&self, other: &Self) -> Option<&str> {
        self.into_iter()
            .find(|&name| other.into_iter().any(|n| name == n))
    }
}

impl<'n> IntoIterator for &'n NameList {
    type Item = &'n str;
    type IntoIter = std::iter::Filter<std::str::Split<'n, char>, for<'a> fn(&'a &'n str) -> bool>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.split(',').filter(|s| !s.is_empty())
    }
}

impl std::fmt::Debug for NameList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NameList")
            .field(&self.into_iter().collect::<Vec<_>>())
            .finish()
    }
}
