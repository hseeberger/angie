use crate::{Hash, Hasher};
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy)]
pub struct Sha3Hasher;

impl Hasher<32> for Sha3Hasher {
    fn hash(&self, value: impl AsRef<[u8]>) -> Hash<32> {
        let output = Sha3_256::new().chain_update(value).finalize().into();
        Hash(output)
    }
}
