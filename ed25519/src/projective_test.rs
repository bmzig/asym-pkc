#![allow(dead_code)]
use crate::edwards::*;
use bigint::uint::U512;
use crate::utils::*;
use crate::constants::*;

#[derive(PartialEq, Clone, Copy)]
pub struct ProjectiveEdwardsPoint {
    x: U512,
    y: U512,
    z: U512,
}

impl EdwardsPoint {

    pub fn into_projective_test(&self) -> ProjectiveEdwardsPoint {
        ProjectiveEdwardsPoint::new(self.x, self.y, U512::one())
    }
}

impl ProjectiveEdwardsPoint {

    pub fn new(x: U512, y: U512, z: U512) -> Self {
        Self {
            x,
            y, 
            z,
        }
    }

    pub fn default() -> Self {
        Self {
            x: U512::zero(),
            y: U512::zero(),
            z: U512::one(),
        }
    }

    pub fn into_edwards(&self) -> EdwardsPoint {
        let field = U512::from_big_endian(&FIELD);
        let x = modinv(self.z, field) * self.x;
        let y = modinv(self.z, field) * self.y;
        EdwardsPoint::new(x % field, y % field)
    }

    pub fn add_no_assumptions(&self, other: &ProjectiveEdwardsPoint) -> ProjectiveEdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let d = U512::from_big_endian(&EDWARDS_COEFFICIENT);
        let diff = |a, b| -> U512 { if a > b { a - b } else { f - (b - a) } };
        let r1 = self.x;
        let r2 = self.y;
        let r3 = self.z;
        let r4 = other.x;
        let r5 = other.y;
        let r6 = other.z;
        let r3 = (r3 * r6) % f;
        let r7 = (r1 + r2) % f;
        let r8 = (r4 + r5) % f;
        let r1 = (r1 * r4) % f;
        let r2 = (r2 * r5) % f;
        let r7 = (r7 * r8) % f;
        let r7 = diff(r7, r1);
        let r7 = diff(r7, r2);
        let r7 = (r7 * r3) % f;
        let r8 = (r1 * r2) % f;
        let r8 = (d * r8) % f;
        let r2 = diff(r2, r1);
        let r2 = (r2 * r3) % f;
        let r3 = (r3 * r3) % f;
        let r1 = diff(r3, r8);
        let r3 = (r3 + r8) % f;
        let r2 = (r2 * r3) % f;
        let r3 = (r3 * r1) % f;
        let r1 = (r1 * r7) % f;
        // let r3 = (c * r3) % f;
        let x = r1;
        let y = r2;
        let z = r3;
        ProjectiveEdwardsPoint::new(x, y, z)
    }

    pub fn add_no_assumptions_2(&self, other: &ProjectiveEdwardsPoint) -> ProjectiveEdwardsPoint {
        let field = U512::from_big_endian(&FIELD);
        let d_coeff = U512::from_big_endian(&EDWARDS_COEFFICIENT);
        // let a_coeff = U512::from_big_endian(&PROJECTIVE_COEFFICIENT);
        let diff = |a, b| -> U512 { if a > b { a - b } else { field - (b - a) } };
        let a = (self.z * other.z) % field;
        let b = (a * a) % field;
        let c = (self.x * other.x) % field;
        let d = (self.y * other.y) % field;
        let e = (((d_coeff * c) % field) * d) % field;
        let f = diff(b, e);
        let g = (b + e) % field;
        let h = (((self.x + self.y) % field) * ((other.x + other.y) % field)) % field;
        let i = diff(diff(h, c), d);
        let x = (((a * f) % field) * i) % field;
        let y = (((a * g) % f) * (diff(d, (a * c) % field))) % field; // This y is wrong. Should be
                                                                      // A*G*(D-a*C) where 'a' is
                                                                      // from (aX2 + Y 2)Z2 = Z4 + dX2Y 2
        let z = (f * g) % field;
        ProjectiveEdwardsPoint::new(x, y, z)
    }

    pub fn double_no_assumptions(&self) -> ProjectiveEdwardsPoint {
        let field = U512::from_big_endian(&FIELD);
        // let a_coeff = U512::from_big_endian(&PROJECTIVE_COEFFICIENT);
        let diff = |a, b| -> U512 { if a > b { a - b } else { field - (b - a) } };
        let a = (self.x * self.y) % field;
        let b = (a * a) % field;
        let c = (self.x * self.x) % field;
        let d = (self.y * self.y) % field;
        let e = (a * c) % field;
        let f = (e + d) % field;
        let h = (self.z * self.z) % field;
        let j = diff(f, (U512::from(2u32) * h) % field);
        let x = (diff(diff(b, c), d) * j) % field;
        let y = (f * diff(e, d)) % field;
        let z = (f * j) % field;
        ProjectiveEdwardsPoint::new(x, y, z)
    }

    pub fn double_no_assumptions_2(&self) -> ProjectiveEdwardsPoint {
        let field = U512::from_big_endian(&FIELD);
        // let a_coeff = U512::from_big_endian(&PROJECTIVE_COEFFICIENT);
        let diff = |a, b| -> U512 { if a > b { a - b } else { field - (b - a) } };
        let a = (self.x * self.y) % field;
        let b = (a * a) % field;
        let c = (self.x * self.x) % field;
        let d = (self.y * self.y) % field;
        let e = (c + d) % field;
        let h = (self.z * self.z) % field;
        let j = diff(e, (U512::from(2u32) * h) % field);
        let x = (((U512::one() * diff(b, e)) % field) * j) % field;
        let y = (((U512::one() * e) % field) * diff(c, d)) % field;
        let z = (e * j) % field;
        ProjectiveEdwardsPoint::new(x, y, z)
    }

}

#[cfg(test)]
mod projective_tests {

    use super::*;

    #[test]
    fn proper_edwards_conversion() {
        let g = EdwardsPoint::new(U512::from_big_endian(&ED_GENX), U512::from_big_endian(&ED_GENY));
        let ed_double = g.add(&g);
        let proj_gen = g.into_projective_test();
        let proj_double = proj_gen.add_no_assumptions(&proj_gen);
        let res = proj_double.into_edwards();
        assert_eq!(res, ed_double);
    }

    // The formulas for the additions are found here: https://www.hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
    #[test]
    fn no_assumption_checks() {

        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        let projective_generator = edwards_generator.into_projective_test();
        let mut edwards_double = edwards_generator.double();
        let mut projective_double = projective_generator.double_no_assumptions();
        for _ in 0..=10 {
            assert_eq!(edwards_double, projective_double.into_edwards());
            edwards_double = edwards_double.double();
            projective_double = projective_double.double_no_assumptions();
        }
        let mut edwards_add = edwards_generator;
        let mut projective_add = projective_generator.clone();
        for _ in 0..=10 {
            assert_eq!(edwards_double, projective_add.into_edwards());
            edwards_add = edwards_add.add(&edwards_generator);
            projective_add = projective_add.add_no_assumptions_2(&projective_generator);
        }

    }

    #[test]
    fn double_na_test() {

        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        let projective_generator = edwards_generator.into_projective_test();
        let edwards_double = edwards_generator.double();
        let projective_double = projective_generator.double_no_assumptions_2();
        assert_eq!(edwards_double, projective_double.into_edwards());
    }
}
