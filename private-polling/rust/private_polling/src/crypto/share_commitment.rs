use bulletproofs::PedersenGens;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::thread_rng;
use crate::crypto::polynomial::Polynomial;

pub fn compute_commited_shares(x: &Scalar, n: u32, t: u32) -> (Scalar, Vec<Scalar>, Vec<Scalar>, Vec<RistrettoPoint>) {
    
    let mut x_poly = Polynomial::random(t as usize);
    x_poly.coefficients[0] = x.clone();
    let x_shares = x_poly.get_n_evals(n as usize);
    
    let r = Scalar::random(&mut thread_rng());
    let mut r_poly = Polynomial::random(t as usize);
    r_poly.coefficients[0] = r.clone();
    let r_shares = r_poly.get_n_evals(n as usize);
    
    let pedersen = PedersenGens::default();
    let mut share_comms = Vec::new();
    share_comms.push(pedersen.commit(x.clone(), r));
    share_comms.extend(x_shares.iter().zip(r_shares.iter())
        .map(|(x_share, r_share)| {
            pedersen.commit(*x_share, *r_share)
        }).collect::<Vec<RistrettoPoint>>());

    (r, x_shares, r_shares, share_comms)
}