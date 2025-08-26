use std::fmt;
use std::ops::{Add ,Mul};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ec::{
    short_weierstrass::{Affine, Projective},
    AffineRepr, CurveGroup,
    hashing::{
        curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve, HashToCurveError
    }
};
use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_ff::UniformRand;
use ark_bls12_381::{g1::Config as G1Config};
use sha2::Sha256;

/// Error enum to wrap underlying failures in HinTS operations, 
/// or wrap errors coming from dependencies (namely, arkworks).
#[derive(Debug)]
pub enum PVSSError {
    /// Error coming from `ark_ec` upon hashing to curve
    HashingError(HashToCurveError),
}

impl fmt::Display for PVSSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PVSSError::HashingError(ref err) => err.fmt(f),
        }
    }
}

impl std::error::Error for PVSSError {}

impl From<HashToCurveError> for PVSSError {
    fn from(err: HashToCurveError) -> PVSSError {
        PVSSError::HashingError(err)
    }
}

type F = ark_bls12_381::Fr;
pub type PedComParams = (Affine<G1Config>, Affine<G1Config>);
pub type PedComCommitment = Affine<G1Config>;
pub type PedComMessage = ark_bls12_381::Fr;
pub type PedComRandomness = ark_bls12_381::Fr;

fn hash_to_curve(
    msg: impl AsRef<[u8]>
) -> Result<Affine<G1Config>, PVSSError> {
    const DST_G1: &str = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    let g1_mapper = MapToCurveBasedHasher::<
        Projective<G1Config>,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G1Config>,
    >::new(DST_G1.as_bytes())?;
    g1_mapper.hash(msg.as_ref()).map_err(|e| PVSSError::HashingError(e))
}

fn compute_scrape_coefficient(n: u64, i: u64) -> F {
    // lambda_i = product( 1 / (i - j) ) for all j in 1..n and j != i
    let lambda_i = (1..=n)
        .filter(|&j| j != i)
        .fold(F::from(1u64), |acc, j| {
            acc * (F::from(1u64) / (F::from(i) - F::from(j)))
        });
    lambda_i
}

pub fn setup() -> PedComParams {
    let g = Affine::<G1Config>::generator();
    let h = hash_to_curve(b"Pedersen Commitment Generator").unwrap();
    (g, h)
}

pub fn commit(
    params: &PedComParams,
    m: PedComMessage,
    r: PedComRandomness
) -> PedComCommitment {
    let (g, h) = params;
    (g.mul(m) + h.mul(r)).into_affine()
}

pub fn degree_check(commitments: &[PedComCommitment], degree: u64) -> bool {
    let n = commitments.len() as u64;
    let d = degree as u64;
    if n < d + 2 {
        return true;
    }

    let mut rng = rand::thread_rng();
    let z = DensePolynomial { coeffs: (0..=(n - d - 2)).map(|_| F::rand(&mut rng)).collect() };
    let sum: PedComCommitment = (1..=n).fold(PedComCommitment::zero(), |acc, i| {
        let scrape_coeff_i = compute_scrape_coefficient(n, i);
        let v_i = commitments[i as usize - 1];
        let z_i = z.evaluate(&F::from(i));
        acc.add(v_i.mul(z_i * scrape_coeff_i)).into()
    });

    return sum == PedComCommitment::zero();
}

#[cfg(test)]
mod tests {
    type F = ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_poly::{Polynomial, univariate::DensePolynomial};
    use super::*;

    #[test]
    fn sample_scrape_test() {
        let d = 10;
        let n = 20;
        let mut rng = rand::thread_rng();
        let p = DensePolynomial { coeffs: (0..=d).map(|_| F::rand(&mut rng)).collect() };
        let z = DensePolynomial { coeffs: (0..=(n - d - 2)).map(|_| F::rand(&mut rng)).collect() };
        // compute sum of p(i) * z(i) * compute_scrape_coefficient(n, i) for i in 1..=n
        let sum: F = (1..=n).map(|i| {
            let scrape_coeff = compute_scrape_coefficient(n, i);
            p.evaluate(&F::from(i)) * z.evaluate(&F::from(i)) * scrape_coeff
        }).sum();

        assert_eq!(sum, F::from(0), "The sum should be zero for the scrape test");
    }

}