pub mod sha3;

use derive_more::{
    self,
    derive::{AsRef, Display, From},
};

/// A hash algorithm with the given fixed output size.
pub trait Hasher<const N: usize>
where
    Self: Clone,
{
    /// The output size of this hash algorithm.
    const OUTPUT_SIZE: usize = N;

    /// Calculate the hash value for the given value which can be referenced as bytes.
    fn hash(&self, value: impl AsRef<[u8]>) -> Hash<N>;

    /// Calculate the hash value of the concatenation of the two given hash values.
    fn concat_hashes(&self, left: Hash<N>, right: Hash<N>) -> Hash<N> {
        let mut value = Vec::with_capacity(2 * N);

        value.extend(left.0);
        value.extend(right.0);

        self.hash(value)
    }
}

/// A hash value of the given size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, AsRef, From, Display)]
#[as_ref([u8])]
#[display("0x{}", const_hex::encode(_0))]
pub struct Hash<const N: usize>(pub [u8; N]);

#[cfg(test)]
mod tests {
    use crate::Hash;

    #[test]
    fn test_hash_derive() {
        let hash = Hash::from([0, 1, 2, 3]);
        assert_eq!(hash.as_ref(), [0, 1, 2, 3].as_slice());
        assert_eq!(format!("{hash:?}"), "Hash([0, 1, 2, 3])");
        assert_eq!(format!("{hash}"), "0x00010203");
    }
}
