use std::fmt;

pub mod ibe_encryption;
pub mod polynomial;
pub mod interpolate;
pub mod share_commitment;
pub mod nizk_commit_or;
pub mod nizk_commit_zero;
pub mod public_evals;
pub mod vote;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofError {
    InvalidProof,
    InvalidInstance,
    DeserializationError
}

impl fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZkProofError::InvalidProof => write!(f, "Invalid proof provided"),
            ZkProofError::InvalidInstance => write!(f, "Invalid instance data"),
            ZkProofError::DeserializationError => write!(f, "Deserialization Error"),
        }
    }
}