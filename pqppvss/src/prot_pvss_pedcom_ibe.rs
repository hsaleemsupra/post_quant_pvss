use rust_bindings::{lattice_ibe_ffi::MasterPublicKey, IbeCiphertext, IbeSecretKeyID};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_poly::Polynomial;
use rand::Rng;

use crate::pedcom::*;
use crate::ibe::*;
use crate::utils;

pub type F = ark_bls12_381::Fr;

pub struct Sharing {
    pub commitments: Vec<PedComCommitment>,
    pub ciphertexts: Vec<IbeCiphertext>,
}

pub fn share<R: Rng>(
    pedcom_params: &PedComParams,
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

    let secret_poly = utils::sample_poly(Some(secret), t, rng);
    let random_poly = utils::sample_poly(None, t, rng);

    let mut secret_shares = Vec::new();
    let mut random_shares = Vec::new();
    let mut commitments = Vec::new();
    let mut ciphertexts = Vec::new();

    for i in 0..n {
        // For each share, we need to evaluate the secret polynomial and the random polynomial
        // at x = i + 1 (1-indexed).
        let x = F::from((i + 1) as u64);
        let secret_y = secret_poly.evaluate(&x);
        let random_y = random_poly.evaluate(&x);

        secret_shares.push(secret_y);
        random_shares.push(random_y);
        commitments.push(commit(pedcom_params, secret_y, random_y));

        let mut msg: [u8; 96] = [0; 96];
        secret_y.serialize_compressed(&mut msg[0..32]).unwrap();
        random_y.serialize_compressed(&mut msg[32..64]).unwrap();
        let id = [i as u8; 96];
        let ciphertext = ibe_encrypt(&msg, &pub_keys[i as usize], &id);
        ciphertexts.push(ciphertext);
    }

    Sharing {
        commitments,
        ciphertexts
    }
}

pub fn verify(
    pedcom_params: &PedComParams,
    sharing: &Sharing,
    access: (u64, u64),
    index: usize,
    sk: &IbeSecretKeyID
) {
    let (t, _n) = access;
    assert!(degree_check(&sharing.commitments, t));
    let msg = ibe_decrypt(&sharing.ciphertexts[index], sk);
    let s = F::deserialize_compressed(&msg[0..32]).unwrap();
    let r = F::deserialize_compressed(&msg[32..64]).unwrap();
    assert!(sharing.commitments[index] == commit(pedcom_params, s, r));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedcom;
    use crate::ibe;
    use rand::thread_rng;

    #[test]
    fn test_share_basic() {
        // Setup PedComParams (dummy for test)
        let pedcom_params = pedcom::setup();

        // Setup IBE master keys and public keys
        let n = 1000;
        let t = 500;
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
            &pedcom_params,
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
        verify(&pedcom_params, &sharing, (t, n), 0, &sk_id_0);
        let verify_duration = verify_timer.elapsed();
        println!("Verify duration: {:?}", verify_duration);

        // Check lengths
        assert_eq!(sharing.commitments.len(), n as usize);
        assert_eq!(sharing.ciphertexts.len(), n as usize);
    }
}
