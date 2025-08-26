use std::ops::SubAssign;
use rand::thread_rng;
use crate::crypto::{ZkProofError};
use curve25519_dalek::{RistrettoPoint, Scalar};
use curve25519_dalek::traits::Identity;
use sha2::Sha512;

/// The nizk proof is used to prove that the message in the elgamal encryption is zero
/// And the prover has the knowledge of the randomness r in elgamal encryption

/// Domain separators for the zk proof
pub const DOMAIN_NIZK_PROOF_OF_PEDERSEN_ZERO_CHALLENGE: &str = "crypto-ristretto-zk-proof-of-pedersen-zero-challenge";

#[derive(Clone, Debug)]
pub struct ZkInstancePedersenZero {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub commitment: RistrettoPoint,
}

pub struct ZkWitnessPedersenZero {
    pub commitment_r: Scalar,
}

pub struct ZkProofPedersenZero {
    pub z: Scalar,
    pub c: Scalar
}

impl ZkInstancePedersenZero {
    pub fn check_instance(&self) -> Result<(), ZkProofError> {
        let identity = RistrettoPoint::identity();
        if self.h.eq(&identity) ||
            self.commitment.eq(&identity) {
            return Err(ZkProofError::InvalidInstance);
        }
        Ok(())
    }
}

fn zk_pedersen_zero_proof_challenge(instance: &ZkInstancePedersenZero, aa: &RistrettoPoint) -> Scalar {
    let mut transcript: Vec<u8> = Vec::new();

    let mut domain_sep = Vec::from(DOMAIN_NIZK_PROOF_OF_PEDERSEN_ZERO_CHALLENGE);
    let mut g = instance.g.compress().to_bytes().to_vec();
    let mut h = instance.h.compress().to_bytes().to_vec();
    let mut commitment = instance.commitment.compress().to_bytes().to_vec();
    let mut a = aa.compress().to_bytes().to_vec();

    transcript.append(&mut domain_sep);
    transcript.append(&mut Vec::from(b"g"));
    transcript.append(&mut g);
    transcript.append(&mut Vec::from(b"h"));
    transcript.append(&mut h);
    transcript.append(&mut Vec::from(b"commitment"));
    transcript.append(&mut commitment);
    transcript.append(&mut Vec::from(b"A"));
    transcript.append(&mut a);

    Scalar::hash_from_bytes::<Sha512>(&*transcript)
}

pub fn prove_nizk_pedersen_zero(
    instance: &ZkInstancePedersenZero,
    witness: &ZkWitnessPedersenZero,
) -> Result<ZkProofPedersenZero, ZkProofError> {

    instance.check_instance()?;
    let alpha = Scalar::random(&mut thread_rng());
    let aa = instance.h * alpha;

    //challenge = H(g,pk,cipher,A,B)
    let challenge = zk_pedersen_zero_proof_challenge(&instance, &aa);
    let z = alpha + (challenge * witness.commitment_r);

    Ok(ZkProofPedersenZero {
        z,
        c: challenge
    })
}

pub fn verify_nizk_pedersen_zero(
    instance: &ZkInstancePedersenZero,
    nizk: &ZkProofPedersenZero,
) -> Result<(), ZkProofError> {

    instance.check_instance()?;
    let mut a_prime = instance.h * nizk.z;
    let c_cmt = instance.commitment * nizk.c;
    a_prime.sub_assign(c_cmt);

    let challenge_prime = zk_pedersen_zero_proof_challenge(&instance, &a_prime);

    if !nizk.c.eq(&challenge_prime) {
        return Err(ZkProofError::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use bulletproofs::PedersenGens;
    use super::*;

    fn setup_instance_and_witness() -> (RistrettoPoint, RistrettoPoint, RistrettoPoint, Scalar) {
        let m = Scalar::ZERO;
        let r = Scalar::random(&mut thread_rng());
        let pedersen = PedersenGens::default();
        let commitment = pedersen.commit(m, r);

        (pedersen.B, pedersen.B_blinding, commitment, r)
    }

    #[test]
    fn nizk_should_verify() {
        let (g, h, commitment, r) = setup_instance_and_witness();

        let instance = ZkInstancePedersenZero { g, h, commitment };
        let witness = ZkWitnessPedersenZero { commitment_r: r };

        let nizk_proof = prove_nizk_pedersen_zero(&instance, &witness).unwrap();
        assert_eq!(
            Ok(()),
            verify_nizk_pedersen_zero(&instance, &nizk_proof),
            "verify_nizk_pedersen_zero verifies NIZK proof"
        );
    }

    #[test]
    fn prover_should_panic_on_invalid_instance() {
        let (g, _h, commitment, r) = setup_instance_and_witness();

        let instance = ZkInstancePedersenZero {
            g,
            h: RistrettoPoint::identity(),
            commitment,
        };
        let witness = ZkWitnessPedersenZero { commitment_r: r };

        assert!(prove_nizk_pedersen_zero(&instance, &witness).is_err());
    }

    #[test]
    fn nizk_should_fail_on_invalid_proof() {
        let (g, h, commitment, r) = setup_instance_and_witness();

        let instance = ZkInstancePedersenZero { g, h, commitment };
        let witness = ZkWitnessPedersenZero { commitment_r: r };

        let mut invalid = prove_nizk_pedersen_zero(&instance, &witness).unwrap();
        invalid.z = Scalar::random(&mut thread_rng());

        assert!( verify_nizk_pedersen_zero(&instance, &invalid).is_err());
    }
}