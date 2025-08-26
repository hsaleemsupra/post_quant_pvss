use ark_poly::univariate::DensePolynomial;
use rust_bindings::{lattice_ibe_ffi::MasterPublicKey, IbeCiphertext, IbeSecretKeyID};
use ark_poly::Polynomial;
use rand::Rng;

use crate::ibe::*;
use crate::utils;

pub type F = ark_bls12_381::Fr;
pub type Hash = [u8; 32];

pub struct Sharing {
    pub committed_secret: Vec<F>, // c = W(x)
    pub csh: Vec<Hash>, // H(s_i, r_i)
    pub cpt: Vec<Hash>, // H(b_i, q_i)
    pub ciphertexts: Vec<IbeCiphertext>, // E_i
}

pub fn share<R: Rng>(
    pub_keys: &[&MasterPublicKey],
    secret: &[u8; 32], 
    access: (u64, u64),
    rng: &mut R
) -> Sharing {
    // parse the desired access structure.
    // n is the number of shares, while
    // t <= n is the reconstruction threshold.
    let (t, n) = access;

    assert!(n == pub_keys.len() as u64,
        "Number of public keys must match the number of shares requested.");

    let s_poly = utils::sample_poly(Some(secret), t, rng);
    let r_poly = utils::sample_poly(None, t, rng);
    let b_poly = utils::sample_poly(None, t, rng);
    let q_poly = utils::sample_poly(None, t, rng);

    let mut csh = Vec::new();
    let mut cpt = Vec::new();
    let mut ciphertexts = Vec::new();

    for i in 0..n {
        // For each share, we need to evaluate the secret polynomial and the random polynomial
        // at x = i + 1 (1-indexed).
        let x = F::from((i + 1) as u64);
        let s_i = utils::serialize(&s_poly.evaluate(&x));
        let r_i = utils::serialize(&r_poly.evaluate(&x));
        let b_i = utils::serialize(&b_poly.evaluate(&x));
        let q_i = utils::serialize(&q_poly.evaluate(&x));

        csh.push(utils::digest_sha256(&[&s_i, &r_i]));
        cpt.push(utils::digest_sha256(&[&b_i, &q_i]));

        let mut msg: [u8; 96] = [0; 96];
        msg[0..32].copy_from_slice(&s_i);
        msg[32..64].copy_from_slice(&r_i);
        msg[64..96].copy_from_slice(&q_i);
        let id = [i as u8; 96];
        let ciphertext = ibe_encrypt(&msg, &pub_keys[i as usize], &id);
        ciphertexts.push(ciphertext);
    }

    let chal = F::from(42);
    let w_poly = b_poly - utils::poly_eval_mult_c(&s_poly, &chal);
    let committed_secret = w_poly.coeffs.clone();

    Sharing {
        committed_secret,
        csh,
        cpt,
        ciphertexts
    }
}

pub fn verify(
    sharing: &Sharing,
    access: (u64, u64),
    index: usize,
    sk: &IbeSecretKeyID
) {
    let (t, _n) = access;
    // degree check on the coefficients
    assert!(sharing.committed_secret.len() == (t + 1) as usize);
    let msg = ibe_decrypt(&sharing.ciphertexts[index], sk);
    let s = utils::deserialize::<F>(&msg[0..32]);
    let _r = utils::deserialize::<F>(&msg[32..64]);
    let _q = utils::deserialize::<F>(&msg[64..96]);
    let chal = F::from(42);
    let w_poly = DensePolynomial { coeffs: sharing.committed_secret.clone() };
    let lhs = w_poly.evaluate(&F::from(index as u64 + 1)) + chal * s;
    assert!(sharing.csh[index] == utils::digest_sha256(&[&msg[0..32], &msg[32..64]]));
    assert!(sharing.cpt[index] == utils::digest_sha256(&[&utils::serialize(&lhs), &msg[64..96]]));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ibe;
    use rand::thread_rng;

    #[test]
    fn test_share_basic() {
        // Setup IBE master keys and public keys
        let n = 128;
        let t = 64;
        let mut ibe_keys = Vec::new();
        for _ in 0..n {
            let key = ibe::ibe_keygen();
            ibe_keys.push(key);
        }
        let pub_keys: Vec<&MasterPublicKey> = ibe_keys.iter().map(|k| k.master_pk()).collect();

        // Secret to share
        let secret = [42u8; 32];

        // Call share
        let share_timer = std::time::Instant::now();
        let sharing = share(
            pub_keys.as_slice(),
            &secret,
            (t, n),
            &mut thread_rng(),
        );
        let share_duration = share_timer.elapsed();
        println!("Share duration: {:?}", share_duration);

        // Verify the sharing
        let verify_timer = std::time::Instant::now();
        let id = [0 as u8; 96];
        let sk_id_0 = ibe_extract_id_secret_key(&id, &ibe_keys[0]);
        verify(&sharing, (t, n), 0, &sk_id_0);
        let verify_duration = verify_timer.elapsed();
        println!("Verify duration: {:?}", verify_duration);
    }
}
