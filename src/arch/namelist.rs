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
    pub fn preferred_in(&self, other: &Self) -> Option<Ascii<'_>> {
        self.into_iter()
            .find(|this| other.into_iter().any(|other| this == &other))
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
                    .filter(|item| !item.as_ref().is_empty())
                    .map(|item| item.as_ref().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .expect("unable to collect the iterator into a `NameList`"),
        )
    }
}

impl<'a: 'b, 'b> IntoIterator for &'a NameList<'b> {
    type Item = Ascii<'b>;

    type IntoIter =
        std::iter::FilterMap<std::str::Split<'b, char>, fn(&'b str) -> Option<Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        #[allow(deprecated)]
        self.0
            .split(',')
            .filter_map(|name| (!name.is_empty()).then_some(Ascii::borrowed_unchecked(name)))
    }
}
