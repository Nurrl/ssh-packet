use binrw::binrw;

use super::Ascii;

/// A `name-list` as defined in the SSH protocol,
/// a `,`-separated list of **ASCII** identifiers.
///
/// see <https://datatracker.ietf.org/doc/html/rfc4251#section-5>.
#[binrw]
#[derive(Debug, Default, Clone)]
pub struct NameList<'b>(pub Ascii<'b>);

impl NameList<'_> {
    /// Retrieve the first name from `self` that is also in `other`.
    pub fn preferred_in(&self, other: &Self) -> Option<&str> {
        self.into_iter()
            .find(|&name| other.into_iter().any(|n| name == n))
    }
}

impl<A> FromIterator<A> for NameList<'_>
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

impl<'a: 'b, 'b> IntoIterator for &'a NameList<'b> {
    type Item = &'b str;

    type IntoIter = std::iter::Filter<std::str::Split<'b, char>, for<'f> fn(&'f &'b str) -> bool>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.as_ref().split(',').filter(|name| !name.is_empty())
    }
}
