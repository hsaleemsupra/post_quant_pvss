use std::iter;
use curve25519_dalek::Scalar;
use rand::thread_rng;

/// A univariate polynomial
/// Note: The polynomial terms are: coefficients[i] * x^i
///       E.g. 3 + 2x + x^2 - x^4 is encoded as:
///       Polynomial{ coefficients: [3,2,1,0,-1] }
#[derive(Clone, Debug)]
pub struct Polynomial {
    pub coefficients: Vec<Scalar>,
}

/// Creates a new `Polynomial` instance from a vector of prime field elements
/// representing the coefficients of the polynomial.
impl From<Vec<Scalar>> for Polynomial {
    fn from(coefficients: Vec<Scalar>) -> Self {
        let mut ans = Polynomial { coefficients };
        ans.remove_zeros();
        ans
    }
}

impl Polynomial {
    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Polynomial {
            coefficients: vec![],
        }
    }

    /// Remove trailing zeros; this should be applied by internal constructors
    /// to get the canonical representation of each polynomial.
    pub fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| (*c).eq(&Scalar::from(0 as u8)))
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len)
    }

    /// Creates a random polynomial.
    pub fn random(number_of_coefficients: usize) -> Self {
        let coefficients: Vec<_> = iter::repeat(())
            .map(|()| Scalar::random(&mut thread_rng()))
            .take(number_of_coefficients)
            .collect();
        Polynomial::from(coefficients)
    }

    /// Evaluate the polynomial at x
    /// Note: This uses Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
    pub fn evaluate_at(&self, x: &Scalar) -> Scalar {
        let mut coefficients = self.coefficients.iter().rev();
        let first = coefficients.next();
        match first {
            None => Scalar::from(0 as u8),
            Some(ans) => {
                let mut ans: Scalar = ans.clone();
                for coeff in coefficients {
                    ans*=x;
                    ans+=coeff;
                }
                ans
            }
        }
    }
    
    pub fn get_n_evals(&self, n:usize) -> Vec<Scalar> {
        let mut n_evals = Vec::new();
        
        for i in 1..=n{
            n_evals.push(self.evaluate_at(&Scalar::from(i as u32)));
        }
        n_evals
    }
}