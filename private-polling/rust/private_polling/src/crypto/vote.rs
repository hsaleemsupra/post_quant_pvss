use curve25519_dalek::{RistrettoPoint, Scalar};
use rust_bindings::IbeCiphertext;
use crate::crypto::nizk_commit_or::ZkProofPedersenOr;
use crate::crypto::nizk_commit_zero::ZkProofPedersenZero;

pub struct Vote {
    pub commited_shares: Vec<Vec<RistrettoPoint>>,
    pub nizk_commit_zero_or_one: Vec<ZkProofPedersenOr>,
    pub encrypted_shares: Vec<(IbeCiphertext, IbeCiphertext)>,
    pub commit_pad: RistrettoPoint,
    pub commitment_r_sum: Scalar,
    pub nizk_commit_pad_zero: ZkProofPedersenZero,
}