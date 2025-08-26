use std::ops::MulAssign;
use curve25519_dalek::{RistrettoPoint, Scalar};
use curve25519_dalek::traits::Identity;

/// Interpolation failed because of duplicate x-coordinates.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InterpolationError {
    DuplicateX,
}

fn contains_duplicates(scalars: &[Scalar]) -> bool {
    let mut set = std::collections::HashSet::new();

    for scalar in scalars {
        if !set.insert(scalar.to_bytes()) {
            return true;
        }
    }

    false
}

/// Compute the Lagrange coefficients at x=0.
///
/// # Arguments
/// * `samples` is a list of values x_0, x_1, ...x_n.
/// # Result
/// * `[lagrange_0, lagrange_1, ..., lagrange_n]` where:
///    * lagrange_i = numerator_i/denominator_i
///    * numerator_i = x_0 * x_1 * ... * x_(i-1) * x_(i+1) * ... * x_n
///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
///      (x_(i+1) - x_i) * ... * (x_n - x_i)
/// # Errors
/// `ThresholdSignatureError::DuplicateX`: in case the interpolation points `samples` are not all distinct.
pub fn lagrange_coefficients_at_zero(samples: &[Scalar]) -> Result<Vec<Scalar>, InterpolationError> {
    let len = samples.len();
    if len == 0 {
        return Ok(Vec::new());
    }
    if len == 1 {
        return Ok(vec![Scalar::from(1 as u8)]);
    }

    if contains_duplicates(samples) {
        return Err(InterpolationError::DuplicateX);
    }

    // The j'th numerator is the product of all `x_prod[i]` for `i!=j`.
    // Note: The usual subtractions can be omitted as we are computing the Lagrange
    // coefficient at zero.
    let mut x_prod: Vec<Scalar> = Vec::with_capacity(len);
    let mut tmp = Scalar::from(1 as u8);
    x_prod.push(tmp);
    for x in samples.iter().take(len - 1) {
        tmp*=x;
        x_prod.push(tmp);
    }
    tmp = Scalar::from(1 as u8);
    for (i, x) in samples[1..].iter().enumerate().rev() {
        tmp*=x;
        x_prod[i]*=tmp;
    }

    for (i, (lagrange_0, x_i)) in x_prod.iter_mut().zip(samples).enumerate() {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other
        // data points but `1` at `x`.
        let mut denom = Scalar::from(1 as u8);
        for (_, x_j) in samples.iter().enumerate().filter(|(j, _)| *j != i) {
            let diff = x_j - x_i;
            denom*=diff;
        }

        if denom == Scalar::from(0 as u8){
            return Err(InterpolationError::DuplicateX);
        }
        else{
            let inv = denom.invert();
            lagrange_0.mul_assign(inv);
        }
    }
    Ok(x_prod)
}

/// Given a list of samples `(x, f(x) * g)` for a polynomial `f` in the scalar field, and a generator g of G1 returns
/// `f(0) * g`.
/// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
/// # Arguments:
/// * `samples` contains the list of `(x, y)` points to be used in the interpolation, where `x` is an element in the scalar field, and the `y` is an element of G1.
/// # Returns
/// The generator `g` of G1 multiplied by to the constant term of the interpolated polynomial `f(x)`. If `samples` contains multiple entries for the same scalar `x`, only the first sample contributes toward the interpolation and the subsequent entries are discarded.
pub fn interpolate_g1(samples: &[(Scalar, RistrettoPoint)]) -> Result<RistrettoPoint, InterpolationError> {
    let all_x: Vec<_> = samples.iter().map(|(x, _)| *x).collect();
    let coefficients = lagrange_coefficients_at_zero(&all_x)?;
    let mut result = RistrettoPoint::identity();
    for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
        result += sample*coefficient;
    }
    Ok(result)
}

pub fn interpolate_scalar(samples: &[(Scalar, Scalar)]) -> Result<Scalar, InterpolationError> {
    let all_x: Vec<_> = samples.iter().map(|(x, _)| *x).collect();
    let coefficients = lagrange_coefficients_at_zero(&all_x)?;
    let mut result = Scalar::ZERO;
    for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
        result += sample*coefficient;
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use curve25519_dalek::{RistrettoPoint, Scalar};
    use crate::crypto::interpolate::{interpolate_g1, interpolate_scalar};

    /// Polynomial evaluation for small polynomials; this will overflow and panic if
    /// used for large values.
    pub fn evaluate_integer_polynomial(x: u32, polynomial: &[u32]) -> u32 {
        let mut ans = 0u32;
        let mut power = 1u32;
        for coefficient in polynomial {
            ans += power * coefficient;
            power *= x;
        }
        ans
    }

    fn uint_to_g1(num: u32) -> RistrettoPoint {
        RistrettoPoint::mul_base(&Scalar::from(num))
    }

    #[test]
    fn test_g1_interpolation_is_correct() {
        let polynomial = [2, 4, 9];
        let x_5 = (
            Scalar::from(5 as u8),
            uint_to_g1(evaluate_integer_polynomial(5, &polynomial)),
        );
        let x_3 = (
            Scalar::from(3 as u8),
            uint_to_g1(evaluate_integer_polynomial(3, &polynomial)),
        );
        let x_8 = (
            Scalar::from(8 as u8),
            uint_to_g1(evaluate_integer_polynomial(8, &polynomial)),
        );

        let random_points = [x_5, x_3, x_8];
        let interpolated_polynomial_at_0 = interpolate_g1(&random_points).expect("Failed to interpolate");
        assert!(interpolated_polynomial_at_0.eq(&uint_to_g1(2)));
    }

    #[test]
    fn test_scalar_interpolation_is_correct() {
        let polynomial = [2, 4, 9];
        let x_5 = (
            Scalar::from(5 as u8),
            Scalar::from(evaluate_integer_polynomial(5, &polynomial)),
        );
        let x_3 = (
            Scalar::from(3 as u8),
            Scalar::from(evaluate_integer_polynomial(3, &polynomial)),
        );
        let x_8 = (
            Scalar::from(8 as u8),
            Scalar::from(evaluate_integer_polynomial(8, &polynomial)),
        );

        let random_points = [x_5, x_3, x_8];
        let interpolated_polynomial_at_0 = interpolate_scalar(&random_points).expect("Failed to interpolate");
        assert!(interpolated_polynomial_at_0.eq(&Scalar::from(2 as u32)));
    }
}