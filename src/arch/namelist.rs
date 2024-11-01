use binrw::binrw;

use super::{Ascii, StringAscii};

/// A `name-list` as defined in the SSH protocol,
/// a `,`-separated list of **ASCII** identifiers.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Default, Clone)]
pub struct NameList2<'b>(pub Ascii<'b>);

impl NameList2<'_> {
    /// Retrieve the first name from `self` that is also in `other`.
    pub fn preferred_in(&self, other: &Self) -> Option<&str> {
        self.into_iter()
            .find(|&name| other.into_iter().any(|n| name == n))
    }
}

impl<A> FromIterator<A> for NameList2<'_>
where
    A: AsRef<str>,
{
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        Self(
            Ascii::owned(
                iter.into_iter()
                    .map(|item| item.as_ref().to_owned())
                    .filter(|name| !name.is_empty())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .expect("unable to collect the iterator into a `NameList`"),
        )
    }
}

impl<'a: 'b, 'b> IntoIterator for &'a NameList2<'b> {
    type Item = &'b str;

    type IntoIter = std::iter::Filter<std::str::Split<'b, char>, for<'f> fn(&'f &'b str) -> bool>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.as_ref().split(',').filter(|name| !name.is_empty())
    }
}

/// A `name-list` as defined in the SSH protocol,
/// a `,`-separated list of **ASCII** identifiers.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Default, Clone, PartialEq, Eq)]
#[brw(big)]
pub struct NameList(StringAscii);

impl NameList {
    /// Create new [`NameList`] from a list of names.
    pub fn new(names: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self(StringAscii::new(
            names
                .into_iter()
                .map(|name| name.as_ref().to_string())
                .collect::<Vec<_>>()
                .join(","),
        ))
    }

    /// Retrieve the first name from `self` that is also in `other`.
    pub fn preferred_in(&self, other: &Self) -> Option<&str> {
        self.into_iter()
            .find(|&name| other.into_iter().any(|n| name == n))
    }
}

impl std::fmt::Debug for NameList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NameList")
            .field(&self.into_iter().collect::<Vec<_>>())
            .finish()
    }
}

impl<'n> IntoIterator for &'n NameList {
    type Item = &'n str;
    type IntoIter = std::iter::Filter<std::str::Split<'n, char>, for<'a> fn(&'a &'n str) -> bool>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.split(',').filter(|s| !s.is_empty())
    }
}
