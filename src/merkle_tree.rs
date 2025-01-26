use crate::{Hash, Hasher};
use std::iter;

/// A perfect (padded) Merkle tree using a hash algorithm with the given fixed output size.
#[derive(Debug, Clone)]
pub struct MerkleTree<const N: usize> {
    nodes: Vec<Hash<N>>,
    leaf_count: usize,
}

impl<const N: usize> MerkleTree<N> {
    pub fn new(items: &[impl AsRef<[u8]>], hasher: impl Hasher<N>) -> Self {
        let Some(last_hash) = items.last().map(|item| hasher.hash(item)) else {
            panic!("Merkle tree must not be empty");
        };

        let leaf_count = items.len().next_power_of_two();

        let mut nodes = Vec::with_capacity(2 * leaf_count - 1);
        let leaves = items
            .iter()
            .map(|item| hasher.hash(item))
            .chain(iter::repeat(last_hash))
            .take(leaf_count);
        nodes.extend(leaves);

        let mut index = 0;
        let mut level_len = leaf_count;
        while level_len > 1 {
            let end = index + level_len;
            let parents = &nodes[index..end]
                .chunks(2)
                .map(|chunk| {
                    let (left, right) = (chunk[0], chunk[1]);
                    hasher.concat_hashes(left, right)
                })
                .collect::<Vec<_>>();
            nodes.extend(parents);

            index += level_len;
            level_len /= 2;
        }

        Self { nodes, leaf_count }
    }

    pub fn root(&self) -> Hash<N> {
        *self.nodes.last().unwrap()
    }

    pub fn proof(&self, mut index: usize) -> MerkleProof<N> {
        assert!(
            index < self.leaf_count,
            "index must be within number of leaf nodes"
        );

        let path_len = self.leaf_count.trailing_zeros() as usize;
        let mut path = Vec::with_capacity(path_len);

        let mut prev_level_len = 0;
        let mut level_len = self.leaf_count;
        while level_len > 1 {
            let position = if index % 2 == 0 {
                PositionedHash::Right(self.nodes[index + 1])
            } else {
                PositionedHash::Left(self.nodes[index - 1])
            };
            path.push(position);

            index = index + level_len - (index - prev_level_len + 1) / 2;
            prev_level_len = level_len;
            level_len /= 2;
        }

        MerkleProof {
            root: self.root(),
            path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof<const N: usize> {
    root: Hash<N>,
    path: Vec<PositionedHash<N>>,
}

impl<const N: usize> MerkleProof<N> {
    pub fn validate(&self, item: &(impl AsRef<[u8]> + ?Sized), hasher: &impl Hasher<N>) -> bool {
        let mut hash = hasher.hash(item);

        for positioned_hash in &self.path {
            match positioned_hash {
                PositionedHash::Left(left) => hash = hasher.concat_hashes(*left, hash),
                PositionedHash::Right(right) => hash = hasher.concat_hashes(hash, *right),
            }
        }

        hash == self.root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionedHash<const N: usize> {
    Left(Hash<N>),
    Right(Hash<N>),
}

#[cfg(test)]
mod tests {
    use crate::{sha3::Sha3Hasher, Hasher, MerkleProof, MerkleTree, PositionedHash};

    #[test]
    #[should_panic]
    fn test_new_empty() {
        MerkleTree::new(&[[0; 0]; 0], Sha3Hasher);
    }

    #[test]
    fn test_new_one() {
        let hasher = Sha3Hasher;

        let value = "one";
        let hash = hasher.hash(value);
        let tree = MerkleTree::new(&[value], hasher);

        let root_hash = tree.root();
        assert_eq!(root_hash, hash);
    }

    #[test]
    fn test_new_two() {
        let hasher = Sha3Hasher;

        let one = "one";
        let two = "two";
        let one_hash = hasher.hash(one);
        let two_hash = hasher.hash(two);
        let tree = MerkleTree::new(&[one, two], hasher);

        let root_hash = tree.root();
        let expected_root_hash = hasher.concat_hashes(one_hash, two_hash);
        assert_eq!(root_hash, expected_root_hash);
    }

    #[test]
    fn test_new_three() {
        let hasher = Sha3Hasher;

        let one = "one";
        let two = "two";
        let three = "three";
        let one_hash = hasher.hash(one);
        let two_hash = hasher.hash(two);
        let three_hash = hasher.hash(three);
        let tree = MerkleTree::new(&[one, two, three], hasher);

        let root_hash = tree.root();
        let expected_root_hash = {
            let one_two_hash = hasher.concat_hashes(one_hash, two_hash);
            let three_three_hash = hasher.concat_hashes(three_hash, three_hash);
            hasher.concat_hashes(one_two_hash, three_three_hash)
        };
        assert_eq!(root_hash, expected_root_hash);
    }

    #[test]
    fn test_proof() {
        let hasher = Sha3Hasher;

        let items = (0..8).map(|n| n.to_string()).collect::<Vec<_>>();

        let hash_0 = hasher.hash(&items[0]);
        let hash_1 = hasher.hash(&items[1]);
        let hash_2 = hasher.hash(&items[2]);
        let hash_3 = hasher.hash(&items[3]);
        let hash_01 = hasher.concat_hashes(hash_0, hash_1);
        let hash_23 = hasher.concat_hashes(hash_2, hash_3);
        let hash_03 = hasher.concat_hashes(hash_01, hash_23);

        let hash_4 = hasher.hash(&items[4]);
        let hash_5 = hasher.hash(&items[5]);
        let hash_6 = hasher.hash(&items[6]);
        let hash_7 = hasher.hash(&items[7]);
        let hash_45 = hasher.concat_hashes(hash_4, hash_5);
        let hash_67 = hasher.concat_hashes(hash_6, hash_7);
        let hash_47 = hasher.concat_hashes(hash_45, hash_67);

        let hash_07 = hasher.concat_hashes(hash_03, hash_47);

        let tree = MerkleTree::new(&items, hasher);

        assert_eq!(tree.root(), hash_07);

        assert_eq!(
            tree.proof(0),
            MerkleProof {
                root: tree.root(),
                path: vec![
                    PositionedHash::Right(hash_1),
                    PositionedHash::Right(hash_23),
                    PositionedHash::Right(hash_47),
                ]
            }
        );

        assert_eq!(
            tree.proof(1),
            MerkleProof {
                root: tree.root(),
                path: vec![
                    PositionedHash::Left(hash_0),
                    PositionedHash::Right(hash_23),
                    PositionedHash::Right(hash_47),
                ]
            }
        );

        assert_eq!(
            tree.proof(3),
            MerkleProof {
                root: tree.root(),
                path: vec![
                    PositionedHash::Left(hash_2),
                    PositionedHash::Left(hash_01),
                    PositionedHash::Right(hash_47),
                ]
            }
        );

        let proof_6 = tree.proof(6);
        assert_eq!(
            proof_6,
            MerkleProof {
                root: tree.root(),
                path: vec![
                    PositionedHash::Right(hash_7),
                    PositionedHash::Left(hash_45),
                    PositionedHash::Left(hash_03),
                ]
            }
        );

        assert!(proof_6.validate(&items[6], &hasher));
        assert!(!proof_6.validate("foo", &hasher));
    }
}
