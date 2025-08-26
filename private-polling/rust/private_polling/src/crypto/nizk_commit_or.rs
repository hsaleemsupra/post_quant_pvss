use std::ops::Neg;
use curve25519_dalek::{RistrettoPoint, Scalar};
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::thread_rng;
use sha2::Sha512;
use crate::crypto::ZkProofError;

/// The nizk proof is used to prove that the elgamal ciphertext either encrypts zero or one

/// Domain separators for the zk proof of or relation
pub const DOMAIN_NIZK_PROOF_OF_OR_PEDERSEN_CHALLENGE: &str = "crypto-zk-proof-of-or-pedersen-challenge";

#[derive(Clone, Debug)]
pub struct ZkInstancePedersenOr {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
    pub c: RistrettoPoint,
    pub d: RistrettoPoint,
}

pub struct ZkWitnessPedersenOr {
    pub r: Scalar,
}

/// Zero-knowledge proof of or relation.
pub struct ZkProofPedersenOr {
    pub challenge_1: Scalar,
    pub challenge_2: Scalar,
    pub z1: Scalar,
    pub z2: Scalar,
}

impl ZkInstancePedersenOr {
    pub fn check_instance(&self) -> Result<(), ZkProofError> {

        let identity = RistrettoPoint::identity();
        if self.h.eq(&identity) || self.c.eq(&identity) || self.d.eq(&identity){

            return Err(ZkProofError::InvalidInstance);
        }
        Ok(())
    }
}

//challenge = H(G,H,C,D,A1,A2)
fn zk_pedersen_or_proof_challenge(instance: &ZkInstancePedersenOr
                                  , aa1: &RistrettoPoint
                                  , aa2: &RistrettoPoint) -> Scalar {

    let mut transcript: Vec<u8> = Vec::new();

    let mut domain_sep = Vec::from(DOMAIN_NIZK_PROOF_OF_OR_PEDERSEN_CHALLENGE);
    let mut g = instance.g.compress().to_bytes().to_vec();
    let mut h = instance.h.compress().to_bytes().to_vec();
    let mut c = instance.c.compress().to_bytes().to_vec();
    let mut d = instance.d.compress().to_bytes().to_vec();
    let mut a1 = aa1.compress().to_bytes().to_vec();
    let mut a2 = aa2.compress().to_bytes().to_vec();

    transcript.append(&mut domain_sep);
    transcript.append(&mut Vec::from(b"g"));
    transcript.append(&mut g);
    transcript.append(&mut Vec::from(b"h"));
    transcript.append(&mut h);
    transcript.append(&mut Vec::from(b"c"));
    transcript.append(&mut c);
    transcript.append(&mut Vec::from(b"d"));
    transcript.append(&mut d);
    transcript.append(&mut Vec::from(b"A1"));
    transcript.append(&mut a1);
    transcript.append(&mut Vec::from(b"A2"));
    transcript.append(&mut a2);

    Scalar::hash_from_bytes::<Sha512>(&*transcript)
}

/// Prover for the case m = 0 (real: C = r*H; simulated: D = r*H with D = C - G)
pub fn prove_nizk_pedersen_or_relation_zero(
    instance: &ZkInstancePedersenOr,
    witness: &ZkWitnessPedersenOr,
) -> Result<ZkProofPedersenOr, ZkProofError> {

    instance
        .check_instance()
        .expect("The zk proof instance is invalid");

    // Simulated branch 2 (m = 1): A2 = z2*H - c2*D
    let z2 = Scalar::random(&mut thread_rng());
    let challenge_2 = Scalar::random(&mut thread_rng());
    let a2 = RistrettoPoint::multiscalar_mul(&[z2, challenge_2.neg()], &[instance.h, instance.d]);

    // Real branch 1 (m = 0): A1 = α1*H
    let alpha_1 = Scalar::random(&mut thread_rng());
    let a1 = instance.h * alpha_1;

    // challenge = H(G,H,C,D,A1,A2)
    let challenge = zk_pedersen_or_proof_challenge(&instance, &a1, &a2);
    let challenge_1 = challenge - challenge_2;
    let z1 = alpha_1 + challenge_1 * witness.r;

    Ok(ZkProofPedersenOr {
        challenge_1,
        challenge_2,
        z1,
        z2,
    })
}

/// Prover for the case m = 1 (real: D = r*H; simulated: C = r*H)
pub fn prove_nizk_pedersen_or_relation_one(
    instance: &ZkInstancePedersenOr,
    witness: &ZkWitnessPedersenOr,
) -> Result<ZkProofPedersenOr, ZkProofError> {

    instance
        .check_instance()?;

    // Simulated branch 1 (m = 0): A1 = z1*H - c1*C
    let z1 = Scalar::random(&mut thread_rng());
    let challenge_1 = Scalar::random(&mut thread_rng());
    let a1 = RistrettoPoint::multiscalar_mul(&[z1, challenge_1.neg()], &[instance.h, instance.c]);

    // Real branch 2 (m = 1): A2 = α2*H
    let alpha_2 = Scalar::random(&mut thread_rng());
    let a2 = instance.h * alpha_2;

    // challenge = H(G,H,C,D,A1,A2)
    let challenge = zk_pedersen_or_proof_challenge(instance, &a1, &a2);
    let challenge_2 = challenge - challenge_1;
    let z2 = alpha_2 + challenge_2 * witness.r;

    Ok(ZkProofPedersenOr {
        challenge_1,
        challenge_2,
        z1,
        z2,
    })
}

pub fn verify_nizk_pedersen_or_relation(
    instance: &ZkInstancePedersenOr,
    nizk: &ZkProofPedersenOr,
) -> Result<(), ZkProofError> {
    instance.check_instance()?;

    // A1' = z1*H - c1*C
    let a1 = RistrettoPoint::multiscalar_mul(
        &[nizk.z1, nizk.challenge_1.neg()],
        &[instance.h, instance.c],
    );
    // A2' = z2*H - c2*D   (with D = C - G)
    let a2 = RistrettoPoint::multiscalar_mul(
        &[nizk.z2, nizk.challenge_2.neg()],
        &[instance.h, instance.d],
    );

    let challenge = nizk.challenge_1 + nizk.challenge_2;
    let challenge_prime = zk_pedersen_or_proof_challenge(instance, &a1, &a2);

    if challenge != challenge_prime {
        return Err(ZkProofError::InvalidProof);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use bulletproofs::PedersenGens;
    use super::*;

    fn setup_instance_and_witness_zero() -> (RistrettoPoint, RistrettoPoint, RistrettoPoint, RistrettoPoint, Scalar) {
        let m = Scalar::ZERO;
        let r = Scalar::random(&mut thread_rng());
        let pedersen = PedersenGens::default();
        let commitment = pedersen.commit(m, r);
        let d = commitment - pedersen.B; // C - G

        (pedersen.B, pedersen.B_blinding, commitment, d, r)
    }

    fn setup_instance_and_witness_one() -> (RistrettoPoint, RistrettoPoint, RistrettoPoint, RistrettoPoint, Scalar) {
        let m = Scalar::ONE;
        let r = Scalar::random(&mut thread_rng());
        let pedersen = PedersenGens::default();
        let commitment = pedersen.commit(m, r);
        let d = commitment - pedersen.B; // C - G

        (pedersen.B, pedersen.B_blinding, commitment, d, r)
    }

    #[test]
    fn nizk_should_verify_zero() {
        let (g, h, c, d, r) = setup_instance_and_witness_zero();
        let instance = ZkInstancePedersenOr { g, h, c, d };
        let witness = ZkWitnessPedersenOr { r };
        let proof = prove_nizk_pedersen_or_relation_zero(&instance, &witness).unwrap();
        assert_eq!(Ok(()), verify_nizk_pedersen_or_relation(&instance, &proof));
    }

    #[test]
    fn nizk_should_verify_one() {
        let (g, h, c, d, r) = setup_instance_and_witness_one();
        let instance = ZkInstancePedersenOr { g, h, c, d };
        let witness = ZkWitnessPedersenOr { r };
        let proof = prove_nizk_pedersen_or_relation_one(&instance, &witness).unwrap();
        assert_eq!(Ok(()), verify_nizk_pedersen_or_relation(&instance, &proof));
    }

    #[test]
    fn prover_should_panic_on_invalid_instance() {
        let (g, _h, c, d, r) = setup_instance_and_witness_zero();
        let instance = ZkInstancePedersenOr { g, h: RistrettoPoint::identity(), c, d };
        let witness = ZkWitnessPedersenOr { r };
        assert!(prove_nizk_pedersen_or_relation_one(&instance, &witness).is_err());
    }

    #[test]
    fn nizk_should_fail_on_invalid_proof_a() {
        // Use m=1 instance but run the "zero" prover → should fail.
        let (g, h, c, d, r) = setup_instance_and_witness_one();
        let instance = ZkInstancePedersenOr { g, h, c, d };
        let witness = ZkWitnessPedersenOr { r };
        let invalid = prove_nizk_pedersen_or_relation_zero(&instance, &witness).unwrap();
        assert_eq!(Err(ZkProofError::InvalidProof),
                   verify_nizk_pedersen_or_relation(&instance, &invalid));
    }

    #[test]
    fn nizk_should_fail_on_invalid_proof_b() {
        // Use m=0 instance but run the "one" prover → should fail.
        let (g, h, c, d, r) = setup_instance_and_witness_zero();
        let instance = ZkInstancePedersenOr { g, h, c, d };
        let witness = ZkWitnessPedersenOr { r };
        let invalid = prove_nizk_pedersen_or_relation_one(&instance, &witness).unwrap();
        assert_eq!(Err(ZkProofError::InvalidProof),
                   verify_nizk_pedersen_or_relation(&instance, &invalid));
    }
}