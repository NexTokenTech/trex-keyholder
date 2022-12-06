use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub struct TmpKeyPiece {
    pub release_time: u64,
    pub from_block: u32,
    pub key_piece: Vec<u8>,
    pub ext_index: u32,
}

impl Ord for TmpKeyPiece {
    fn cmp(&self, other: &Self) -> Ordering {
        self.release_time.cmp(&other.release_time).reverse()
    }
}