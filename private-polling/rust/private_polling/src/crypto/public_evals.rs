use std::borrow::Borrow;
use std::ops;
use std::ops::Mul;
use curve25519_dalek::{RistrettoPoint, Scalar};
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;
use crate::crypto::polynomial::Polynomial;

/// Given a polynomial with secret evaluations <a0, ..., an> at points <0,1,2,..,n> the public
/// evaluations are the public points <A0, ..., An> corresponding to those secret evaluations.
#[derive(Clone, Debug)]
pub struct PublicEvals {
    pub g: RistrettoPoint,
    pub evals: Vec<RistrettoPoint>,
}

impl PartialEq<Self> for PublicEvals {
    fn eq(&self, other: &Self) -> bool {
        if !self.g.eq(&other.g) {
            return false;
        }
        if self.evals.len() != other.evals.len() {
            return false;
        }
        self.evals.iter()
            .zip(&other.evals)
            .all(|(x, y)| {
                x.eq(y)
            })
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<B: Borrow<PublicEvals>> ops::AddAssign<B> for PublicEvals {
    fn add_assign(&mut self, rhs: B) {
        assert!(self.g.eq(&rhs.borrow().g));
        let len = self.evals.len();
        let rhs_len = rhs.borrow().evals.len();
        assert!(rhs_len == len);
        for (self_c, rhs_c) in self.evals.iter_mut().zip(&rhs.borrow().evals) {
            *self_c += rhs_c;
        }
    }
}

impl<B: Borrow<PublicEvals>> ops::Add<B> for PublicEvals {
    type Output = Self;

    fn add(mut self, rhs: B) -> Self {
        self += rhs;
        self
    }
}

// Implement Mul for &PublicEvals * Scalar
impl Mul<Scalar> for &PublicEvals {
    type Output = PublicEvals;

    fn mul(self, rhs: Scalar) -> PublicEvals {
        PublicEvals {
            g: self.g,
            evals: self.evals.iter().map(|eval| eval.mul(rhs)).collect(),
        }
    }
}

// Implement Mul for PublicEvals * Scalar by delegating to the reference implementation
impl Mul<Scalar> for PublicEvals {
    type Output = PublicEvals;

    fn mul(self, rhs: Scalar) -> PublicEvals {
        &self * rhs
    }
}

impl PublicEvals {
    pub fn from_evals(evals: &Vec<Scalar>, g: &RistrettoPoint) -> Self {
        PublicEvals {
            g: g.clone(),
            evals: evals
                .iter()
                .map(|x| (g * x).into())
                .collect(),
        }
    }

    pub fn from_evals_parallelized(evals: &Vec<Scalar>, g: &RistrettoPoint) -> Self {
        PublicEvals {
            g: g.clone(),
            evals: evals
                .par_iter()
                .map(|x| (g * x).into())
                .collect(),
        }
    }

    pub fn perform_low_degree_test(&self, n: u32, t: u32) -> bool{
        let evals = self.evals[1..].to_vec().clone();
        if t == n{
            return true;
        }

        let degree = (t - 1) as usize;

        // Generate the dual code word
        let vf = PublicEvals::get_dual_codeword(degree, n as usize);

        // Ensure lengths match
        if evals.len() != vf.len() {
            return false;
        }

        // Compute the inner product
        let ip = RistrettoPoint::multiscalar_mul(vf.as_slice(), evals.as_slice());

        // Check if the inner product is the identity element
        ip.is_identity()
    }

    pub fn add_random_linear_combination<R: RngCore + CryptoRng>(
        &mut self,
        other: &PublicEvals,
        rng: &mut R,
    ) -> Scalar {
        assert_eq!(self.g, other.g, "Generators must match");
        assert_eq!(self.evals.len(), other.evals.len(), "Mismatched eval vector lengths");

        let r = Scalar::random(rng);
        self.add_linear_combination_with_coeff(other, r);
        r
    }

    /// self := self + coeff * other (deterministic coefficient).
    /// Uses multiscalar_mul for each index.
    pub fn add_linear_combination_with_coeff(
        &mut self,
        other: &PublicEvals,
        coeff: Scalar,
    ) {
        assert_eq!(self.g, other.g, "Generators must match");
        assert_eq!(self.evals.len(), other.evals.len(), "Mismatched eval vector lengths");

        // Update in place using 2-term MSM: 1*self_i + coeff*other_i
        for (self_i, other_i) in self.evals.iter_mut().zip(other.evals.iter()) {
            // Take clones to avoid aliasing while overwriting
            let a = self_i.clone();
            let b = other_i.clone();
            *self_i = a+coeff*b;
        }
    }

    /// In-place convenience: self := self + sum_j r_j * others[j].
    /// Returns the sampled r_j. Sequential; no multithreading.
    pub fn add_random_linear_combination_many<R: RngCore + CryptoRng>(
        &mut self,
        others: &[PublicEvals],
        rng: &mut R,
    ) -> Vec<Scalar> {
        // Build [self, others...] and coeffs [1, r_1, ..., r_k]
        let mut all = Vec::with_capacity(1 + others.len());
        all.push(self.clone());
        all.extend_from_slice(others);

        let mut coeffs = Vec::with_capacity(1 + others.len());
        coeffs.push(Scalar::ONE);
        coeffs.extend((0..others.len()).map(|_| Scalar::random(rng)));

        let combined = Self::linear_combination_of_many(&all, &coeffs);
        *self = combined;

        // Return only the random r_j (drop the leading 1)
        coeffs[1..].to_vec()
    }

    /// Deterministic: returns sum_j coeffs[j] * evals_vec[j].
    /// Uses a k-term MSM per evaluation index, sequentially.
    pub fn linear_combination_of_many(
        evals_vec: &[PublicEvals],
        coeffs: &[Scalar],
    ) -> PublicEvals {
        assert!(!evals_vec.is_empty(), "empty evals_vec");
        assert_eq!(evals_vec.len(), coeffs.len(), "k mismatch");

        // Shape & generator checks
        let g = evals_vec[0].g;
        let m = evals_vec[0].evals.len();
        for pe in evals_vec.iter() {
            assert_eq!(pe.g, g, "generator mismatch");
            assert_eq!(pe.evals.len(), m, "length mismatch");
        }

        // For each index i, do MSM over k points: sum_j coeffs[j] * evals_vec[j].evals[i]
        let mut out_evals = Vec::with_capacity(m);
        for i in 0..m {
            // gather points at position i
            let mut points_at_i = Vec::with_capacity(evals_vec.len());
            for pe in evals_vec.iter() {
                points_at_i.push(pe.evals[i]);
            }
            let acc = RistrettoPoint::multiscalar_mul(coeffs, &points_at_i);
            out_evals.push(acc);
        }

        PublicEvals { g, evals: out_evals }
    }

    pub fn perform_low_degree_test_with_precomputation(&self, n: u32, t: u32, dual_codeword: &Vec<Scalar>) -> bool{
        let evals = self.evals[1..].to_vec().clone();
        if t == n{
            return true;
        }

        let vf = dual_codeword.clone();

        // Ensure lengths match
        if evals.len() != vf.len() {
            return false;
        }

        // Compute the inner product
        let ip = RistrettoPoint::multiscalar_mul(vf.as_slice(), evals.as_slice());

        // Check if the inner product is the identity element
        ip.is_identity().into()
    }

    pub fn get_dual_codeword(degree: usize, n: usize) -> Vec<Scalar> {

        let dual_degree = n - degree - 2;
        let f_poly = Polynomial::random(dual_degree+1);

        let evaluations: Vec<Scalar> = (0..n)
            .map(|i| f_poly.evaluate_at(&Scalar::from(i as u64)))
            .collect();

        let denominators = PublicEvals::all_lagrange_denominators(n);

        let vf: Vec<Scalar> = evaluations
            .iter()
            .zip(denominators.iter())
            .map(|(f_i, denom_i)| {
                let denom_inv = denom_i.invert();
                f_i * denom_inv
            })
            .collect();

        vf
    }

    fn all_lagrange_denominators(n: usize) -> Vec<Scalar> {

        let mut denominators = Vec::with_capacity(n);
        for i in 0..n {
            let mut denom = Scalar::ONE;
            let x_i = Scalar::from(i as u64);

            for j in 0..n {
                if i != j {
                    let x_j = Scalar::from(j as u64);
                    let diff = x_i - x_j;
                    denom *= diff
                }
            }

            denominators.push(denom);
        }

        denominators
    }
}

#[cfg(test)]
mod tests {
    use group::Group;
    use crate::crypto::polynomial::Polynomial;
    use super::*;
    #[test]
    fn test_low_deg_test() {
        // Setup
        let g = RistrettoPoint::generator();
        let n = 5;
        let t = 3;

        // Create a random polynomial of degree t - 1 (degree 2)
        let poly = Polynomial::random(t as usize);
        let evals: Vec<Scalar> = (0..n+1)
            .map(|i| poly.evaluate_at(&Scalar::from(i as u64)))
            .collect();

        let public_evals = PublicEvals::from_evals(&evals, &g);

        // Test
        assert!(public_evals.perform_low_degree_test(n,t));

        // Now create a polynomial of higher degree
        let poly_high_deg = Polynomial::random((t + 1) as usize);
        let evals_high_deg: Vec<Scalar> = (0..n)
            .map(|i| poly_high_deg.evaluate_at(&Scalar::from(i as u64)))
            .collect();

        let public_evals_high_deg = PublicEvals::from_evals(&evals_high_deg, &g);

        // Test
        assert!(!public_evals_high_deg.perform_low_degree_test(n,t));
    }
}
