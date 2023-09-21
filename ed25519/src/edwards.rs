#![allow(dead_code)]

use bigint::uint::U512;
use crate::constants::*;
use crate::utils::*;
use crate::montgomery::MontgomeryPoint;
use crate::projective::ProjectiveEdwardsPoint;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EdwardsPoint {
    pub x: U512,
    pub y: U512,
}

impl EdwardsPoint {

    pub fn generator() -> Self {
        Self::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        )
    }

    pub fn new(x: U512, y: U512) -> Self {
        Self {
            x,
            y,
        }
    } 

    pub fn into_montgomery(&self) -> MontgomeryPoint {
        let f = U512::from_big_endian(&FIELD);
        let sf = U512::from_big_endian(&INV_FACTOR);
        let u = ((self.y + U512::one()) * modinv(f - (self.y - U512::one()), f)) % f;
        let v = (((u * modinv(self.x, f)) % f) * sf) % f;
        MontgomeryPoint::new(u, v)
    }

    pub fn add(&self, other: &EdwardsPoint) -> EdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let d = U512::from_big_endian(&EDWARDS_COEFFICIENT);
        let difference = |x, y| -> U512 {
            if x > y {
                x - y
            }
            else {
                f - (y - x)
            }
        };
        let a = (((self.x * other.y) % f) + ((self.y * other.x) % f)) % f;
        let b = (((((((((d * self.x) % f) * other.x) % f) * self.y) % f) * other.y) % f) + U512::one()) % f;
        let c = (((self.y * other.y) % f) + ((self.x) * other.x) % f) % f;
        let e = difference(U512::one(), (((((((d * self.x) % f) * other.x) % f) * self.y) % f) * other.y) % f);
        let x3 = (modinv(b, f) * a) % f;
        let y3 = (modinv(e, f) * c) % f;
        EdwardsPoint::new(x3, y3)
    }

    pub fn double(&self) -> EdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let xs = (self.x * self.x) % f;
        let ys = (self.y * self.y) % f;
        let difference = |x, y| -> U512 {
            if x > y {
                x - y
            }
            else {
                f - (y - x)
            }
        };
        let a = (((U512::from(2u32) * self.x) % f) * self.y) % f;
        let b = difference(ys, xs);
        let c = (xs + ys) % f;
        let d = difference((U512::from(2u32) + xs) % f, ys);
        let x3 = (modinv(b, f) * a) % f;
        let y3 = (modinv(d, f) * c) % f;
        EdwardsPoint::new(x3, y3)
    }

    pub fn naf_ecmult(&self, s: &U512) -> EdwardsPoint {
        if *s == U512::zero() { return self.clone(); }
        let f = U512::from_big_endian(&FIELD);
        let mut res = EdwardsPoint::default();
        let mut garbage = self.clone();
        let mut multiplier = self.clone();
        let (mut np, mut nm) = naf(&s);
        for _ in 0..256 {
            if np & U512::one() == U512::one() {
                res = res.add(&multiplier);
            }
            else if nm & U512::one() == U512::one() {
                res = res.add(&EdwardsPoint::new(f - self.x, self.y));
            }
            else {
                garbage = garbage.add(&multiplier);
            }
            np = np >> 1usize;
            nm = nm >> 1usize;
            multiplier = multiplier.double();
        }
        res
    }

    pub fn valid(&self) -> bool {
        let f = U512::from_big_endian(&FIELD);
        let d = U512::from_big_endian(&EDWARDS_COEFFICIENT);
        let a = (self.x * self.x) % f;
        let a = f - a;
        let b = (self.y * self.y) % f;
        let c = (a + b) % f;
        let e = (((((((d * self.x) % f) * self.x) % f) * self.y) % f) * self.y) % f;
        let f = (e + U512::one()) % f;
        f == c
    }

    pub fn into_projective(&self) -> ProjectiveEdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        ProjectiveEdwardsPoint::new(self.x, self.y, U512::one(), (self.x * self.y) % f)
    }
}

impl Default for EdwardsPoint {

    fn default() -> Self {
        Self {
            x: U512::zero(),
            y: U512::one(),
        }
    }
}

// I'm going to impl another new block for testing. I need to see that the vanilla edwards formulas
// are not incorrect because curve25519's formulas are correct

impl EdwardsPoint {

}

#[cfg(test)]
mod edwards_tests {

    use super::*;

    #[test]
    pub fn birational_equivalence() {

        let montgomery_generator = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );

        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        assert_eq!(montgomery_generator.into_edwards(), edwards_generator);
        assert_eq!(edwards_generator.into_montgomery(), montgomery_generator);
    }

    #[test]
    pub fn private_key_equivalence() {
        use rand::*;

        let f = U512::from_big_endian(&FIELD);
        let montgomery_generator = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );

        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        let mut bytes: [u8; 32] = [0u8; 32];
        for _ in 0..=100 {
            rand::thread_rng().fill_bytes(&mut bytes);
            let s = U512::from_big_endian(&bytes) % f;
            let montgomery_convert = montgomery_generator.naf_ecmult(&s).into_edwards();
            let edwards = edwards_generator.naf_ecmult(&s);
            assert!(montgomery_convert.valid());
            assert!(edwards.valid());
            eprintln!("This was the private key: {:?}", s);
            assert_eq!(montgomery_convert, edwards);
        }
    }

    #[test]
    pub fn cofactor_check() {

        let f = U512::from_big_endian(&FIELD);
        let montgomery_generator = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );

        let edwards_generator = EdwardsPoint::new(
            U512::from_big_endian(&ED_GENX),
            U512::from_big_endian(&ED_GENY)
        );

        for i in 1..=100 {
            let s = U512::from(i as u8);
            let montgomery_convert = montgomery_generator.naf_ecmult(&s).into_edwards();
            let edwards = edwards_generator.naf_ecmult(&s);
            assert!(montgomery_convert.valid());
            assert!(edwards.valid());
            eprintln!("This was the private key: {:?}", s);
            assert_eq!(montgomery_convert, edwards);
        }
    }

}

