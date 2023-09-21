#![allow(dead_code)]

use bigint::uint::U512;
use crate::constants::*;
use crate::utils::*;
use crate::edwards::EdwardsPoint;

#[derive(Debug, Clone)]
pub struct ProjectiveEdwardsPoint {
    x: U512,
    y: U512,
    z: U512,
    t: U512,
}

impl ProjectiveEdwardsPoint {

    pub fn new(x: U512, y: U512, z: U512, t: U512) -> Self {
        Self {
            x,
            y,
            z,
            t,
        }
    }

    pub fn into_edwards(&self) -> EdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let z = modinv(self.z, f);
        let x = (self.x * z) % f;
        let y = (self.y * z) % f;
        EdwardsPoint::new(x, y)
    }

    pub fn add(&self, other: &ProjectiveEdwardsPoint) -> ProjectiveEdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let difference = |x, y| -> U512 {
            if x > y {
                x - y
            }
            else {
                f - (y - x)
            }
        };
        let a = difference((self.x * other.y) % f, (self.y * other.x) % f);
        let b = (((self.t * other.z) % f) + ((self.z * other.t) % f)) % f;
        let x3 = (a * b) % f;
        let c = difference((self.y * other.y) % f, (self.x * other.x) % f);
        let d = difference((self.t * other.z) % f, (self.z * other.t) % f);
        let y3 = (c * d) % f;
        let e = (((self.t * other.z) % f) + ((self.z * other.t) % f)) % f;
        let g = difference((self.t * other.z) % f, (self.z * other.t) % f);
        let t3 = (e * g) % f;
        let h = difference((self.y * other.y) % f, (self.x * other.x) % f);
        let i = difference((self.x * other.y) % f, (self.y * other.x) % f);
        let z3 = (h * i) % f;
        ProjectiveEdwardsPoint::new(x3, y3, z3, t3)
    }

    pub fn assumption_add(&self, other: &ProjectiveEdwardsPoint) -> ProjectiveEdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let difference = |x, y| -> U512 {
            if x > y {
                x - y
            }
            else {
                f - (y - x)
            }
        };
        let a = (difference(self.y, self.x) * ((other.x + other.y) % f)) % f;
        let b = (((self.y + self.x) % f) * difference(other.y, other.x)) % f;
        let c = (((U512::from(2u32) * self.z) % f) * other.t) % f;
        let d = (((U512::from(2u32) * self.t) % f) * other.z) % f;
        let e = (d + c) % f;
        let g = difference(b, a);
        let h = (b + a) % f;
        let i = difference(d, c);
        let x3 = (e * g) % f;
        let y3 = (h * i) % f;
        let z3 = (g * h) % f;
        let t3 = (e * i) % f;
        ProjectiveEdwardsPoint::new(x3, y3, z3, t3)
    }

    pub fn naf_ecmult(&self, s: &U512) -> ProjectiveEdwardsPoint {
        if *s == U512::zero() { return self.clone(); }
        let f = U512::from_big_endian(&FIELD);
        let mut res = ProjectiveEdwardsPoint::default();
        let mut garbage = self.clone();
        let mut multiplier = self.clone();
        let (mut np, mut nm) = naf(&s);
        for _ in 0..256 {
            if np & U512::one() == U512::one() {
                res = res.assumption_add(&multiplier);
            }
            else if nm & U512::one() == U512::one() {
                res = res.assumption_add(&ProjectiveEdwardsPoint::new(f - self.x, self.y, self.z, f - self.t));
            }
            else {
                garbage = garbage.assumption_add(&multiplier);
            }
            np = np >> 1usize;
            nm = nm >> 1usize;
            multiplier = multiplier.double();
        }
        res
    }

    pub fn double(&self) -> ProjectiveEdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let difference = |x, y| -> U512 {
            if x > y {
                x - y
            }
            else {
                f - (y - x)
            }
        };
        let a = (((U512::from(2u32) * self.x) % f) * self.y) % f;
        let b = difference((((((U512::from(2u32) * self.z) % f) * self.z) % f) + ((self.x * self.x) % f)) % f, (self.y * self.y) % f);
        let x3 = (a * b) % f;
        let c = difference((self.y * self.y) % f, (self.x * self.x) % f);
        let d = (((self.y * self.y) % f) + ((self.x * self.x) % f)) % f;
        let y3 = (c * d) % f;
        let e = (((U512::from(2u32) * self.x) % f) * self.y) % f;
        let g = (((self.y * self.y) % f) + ((self.x * self.x) % f)) % f;
        let t3 = (e * g) % f;
        let h = difference((self.y * self.y) % f, (self.x * self.x) % f);
        let i = difference((((((U512::from(2u32) * self.z) % f) * self.z) % f) + ((self.x * self.x) % f)) % f, (self.y * self.y) % f);
        let z3 = (h * i) % f;
        ProjectiveEdwardsPoint::new(x3, y3, z3, t3)
    }
}

impl Default for ProjectiveEdwardsPoint {
    fn default() -> Self {
        Self {
            x: U512::zero(),
            y: U512::one(),
            z: U512::one(),
            t: U512::zero(),
        }
    }
}

// I'm just going to impl another entirely new block because my current one just does not want to
// work

impl ProjectiveEdwardsPoint {

}

#[cfg(test)]
mod projective_tests {

    use super::*;
    use rand::*;
 
    #[test]
    #[ignore]
    fn projective_equivalence() {

        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        let projective_generator = edwards_generator.into_projective();

        for _ in 0..=10 {
            let s = U512::from(rand::thread_rng().next_u64());
            let x = edwards_generator.naf_ecmult(&s);
            let y = projective_generator.naf_ecmult(&s);
            assert_eq!(x, y.into_edwards());
        }
    }

    #[test]
    fn projective_comparisons() {
        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        let projective_generator = edwards_generator.into_projective();
        let mut edwards_double = edwards_generator.double();
        let mut projective_double = projective_generator.double();
        for _ in 0..=10 {
            assert_eq!(edwards_double, projective_double.into_edwards());
            edwards_double = edwards_double.double();
            projective_double = projective_double.double();
        }
    }

}

