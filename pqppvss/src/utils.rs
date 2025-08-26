use ark_ff::{PrimeField, BigInteger};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use rand::Rng;

pub fn bytes_to_bits_be(x: &[u8]) -> Vec<bool> {
    //convert byte array to bit array for BigInt conversion
    let mut output: Vec<bool> = Vec::new();

    for &byte in x {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) == 1;
            output.push(bit);
        }
    }

    output
}

pub fn sample_poly<F: PrimeField, R: Rng>(
    secret: Option<&[u8; 32]>,
    degree: u64,
    rng: &mut R,
) -> DensePolynomial<F> {
    // degree + 1 coefficients define a polynomial of degree `degree`.
    let mut coeffs: Vec<F> = (0..(degree+1))
        .map(|_| F::rand(rng))
        .collect();

    if secret.is_some() {
        // But we don't want a completely random polynomial, 
        // but rather one whose evaluation at x=0 is the secret.
        // So, let us replace zero-th coefficient with our secret.
        let secret_bigint = BigInteger::from_bits_be(
            &bytes_to_bits_be(secret.unwrap()));
        coeffs[0] = F::from_bigint(secret_bigint).unwrap();
    }

    DensePolynomial { coeffs }
}

/// computes polynomial c . f(x), for some constant c and input polynomial f(x)
pub fn poly_eval_mult_c<F: PrimeField>(f: &DensePolynomial<F>, c: &F) -> DensePolynomial<F> {
    if f.coeffs.is_empty() {
        return f.clone();
    }

    DensePolynomial { coeffs: f.coeffs.iter().map(|a| a.clone() * c.clone()).collect() }
}

pub fn digest_sha256(data: &[&[u8]]) -> [u8; 32] {
    // create a Sha256 object
    let mut hasher = Sha256::new();
    // write input message
    for &d in data.iter() {
        hasher.update(d);
    }
    // read hash digest and consume hasher
    let result: [u8; 32] = hasher.finalize().into();

    result
}

pub fn serialize<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    // unwrap() should be safe because we serialize into a variable-size vector.
    // However, it might fail if the `t` is invalid somehow, although this
    // should only occur if there is an error in the caller or this library.
    t.serialize_compressed(&mut buf).unwrap();
    buf
}

pub fn deserialize<T: CanonicalDeserialize>(buf: &[u8]) -> T {
    T::deserialize_compressed(buf).unwrap()
}