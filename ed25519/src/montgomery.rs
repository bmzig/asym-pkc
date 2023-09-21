#![allow(dead_code)]

use crate::utils::*;
use bigint::uint::U512;
use crate::constants::*;
use crate::window::*;
use crate::edwards::EdwardsPoint;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MontgomeryPoint {
    pub x: U512,
    pub y: U512,
    pub infinity: bool,
}

impl MontgomeryPoint {

    pub fn generator() -> Self {
        Self::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        )
    }

    pub fn add(&self, other: &MontgomeryPoint) -> MontgomeryPoint {
        let f = U512::from_big_endian(&FIELD);
        if self.infinity { return other.clone(); }
        if other.infinity { return self.clone(); }
        if (self.x == other.x) && (self.y == f - other.y) { return MontgomeryPoint::default(); }
        let a = U512::from(486662u32);
        let lambda = self.slope(other, f);
        let lambda_s = (lambda * lambda) % f;
        let lambda_c = (lambda_s * lambda) % f;
        let x3;
        if lambda_s > (a + self.x + other.x) % f {
            x3 = lambda_s - ((a + self.x + other.x) % f);
        }
        else {
            x3 = f - (((a + self.x + other.x) % f) - lambda_s);
        }
        let o = (((U512::from(2u32) * self.x) % f) + other.x + a) % f;
        let y3;
        if (o * lambda) % f > (lambda_c + self.y) % f {
            y3 = ((o * lambda) % f) - ((lambda_c + self.y) % f);
        }
        else {
            y3 = f - (((lambda_c + self.y) % f) - ((o * lambda) % f));
        }
        MontgomeryPoint::new(x3, y3)
    }

    /// In this update, I replace the double and add algorithm with non-adjacent-form, or
    /// NAF for short, for elliptic curve multiplication. On average, this takes ~17% less
    /// calculations compared to the double-and-add method due to the efficiency of the NAF algorithm.
    ///
    /// Input: scalar multiplier (s) -> number of times to add the elliptic curve point.
    /// Input: point (P) -> Affine point of the elliptic curve to multiply.
    /// Input: field (f) -> The field size of the elliptic curve (we're using secp256k1).
    ///
    /// Output: result point -> The point of nP.
    pub fn naf_ecmult(&self, s: &U512) -> MontgomeryPoint {
        let f = U512::from_big_endian(&FIELD);
        let mut res = MontgomeryPoint::default();
        let mut garbage = self.clone();
        let mut multiplier = self.clone();
        let (mut np, mut nm) = naf(s);
        for _ in 0..256 {
            if np & U512::one() == U512::one() {
                res = res.add(&multiplier);
            }
            else if nm & U512::one() == U512::one() {
                res = res.add(&MontgomeryPoint::new(multiplier.x, f - multiplier.y));
            }
            else {
                garbage = garbage.add(&multiplier);
            }
            np = np >> 1usize;
            nm = nm >> 1usize;
            multiplier = multiplier.add(&multiplier);
        }
        res
    }

    /// The we are going to use a window of 8 bits for this, meaning that there will be 32 total windows (8 * 32 = 256). Every window will have 255 different states.
    /// | 0 0 0 0 0 0 0 1 | 0 0 0 0 0 0 1 0 | 0 0 0 0 0 0 1 1 | 0 0 0 0 0 1 0 0 | 0 0 0 0 0 1 0 1 | 0 0 0 0 0 1 1 0 | 0 0 0 0 0 1 1 1 | 0 0 0 0 1 0 0 0 | ... ... ... ..|
    /// |_______________________________________________________________________________________________________________________________________________________________|
    /// |        1        |        2        |        3        |        4        |        5        |        6        |        7        |        8        | ... ... ... ..|
    /// |_______________________________________________________________________________________________________________________________________________________________|
    #[allow(non_snake_case)]
    pub fn wNAF8(s: &[u8], lt: &LookupTable) -> MontgomeryPoint {
        let mut res = MontgomeryPoint::default();
        for i in 0..32 {
            let w: u8 = s[i];
            res = res.add(lt.map.get(&(i as u8, w)).unwrap());
        }
        res
    }

    pub fn slope(&self, other: &MontgomeryPoint, f: U512) -> U512 {
        if self.eq(&other) { return self.implicit(f); }
        let n;
        if other.y > self.y {
            n = other.y - self.y;
        }
        else {
            n = f - (self.y - other.y);
        }
        let d;
        if other.x > self.x {
            d = other.x - self.x;
        }
        else {
            d = f - (self.x - other.x);
        }
        let d = modinv(d, f);
        (d * n) % f
    }

    pub fn implicit(&self, f: U512) -> U512 {
        let a = U512::from(486662u32);
        let n = (((U512::from(3u32) * ((self.x * self.x) % f)) % f) + ((U512::from(2u32) * ((a * self.x) % f)) % f) + (U512::one())) % f;
        let d = (self.y * U512::from(2u32)) % f;
        let d = modinv(d, f);
        (n * d) % f
    }

    pub fn on_curve(&self) -> bool {
        let a = U512::from(486662u32);
        let f = U512::from_big_endian(&FIELD);
        (self.y * self.y) % f == (((((((self.x * self.x) % f) * self.x) % f) + ((((self.x * self.x) % f) * a) % f)) % f) + self.x) % f
    }

    pub fn eq(&self, other: &MontgomeryPoint) -> bool {
        !self.infinity && !other.infinity && self.x == other.x && self.y == other.y
    }

    pub fn new(x: U512, y: U512) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    pub fn into_edwards(&self) -> EdwardsPoint {
        let f = U512::from_big_endian(&FIELD);
        let sf = U512::from_big_endian(&INV_FACTOR);
        let y = ((self.x - U512::one()) * modinv(self.x + U512::one(), f)) % f;
        let x = (sf * ((self.x * modinv(self.y, f)) % f)) % f;
        EdwardsPoint::new(x, y)
    }
}

impl Default for MontgomeryPoint {
    fn default() -> Self {
        Self {
            x: U512::zero(),
            y: U512::zero(),
            infinity: true,
        }
    }
}

#[cfg(test)]
mod montgomery_tests {

    use super::*;
    use bigint::uint::U256;


    // The following test uses the curve25519 lookup table to perform the calculations. It takes
    // a while to create (~2200 seconds or 35 mins). For that reason, the test will be optional.
    #[test]
    #[ignore]
    fn wnaf_window8_montgomery() {
        let lt = LookupTable::initialize_window8();
        let g = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );
        let secret_key: [u8; 32] = [
            11, 130, 44, 152, 138, 23, 143, 215, 
            135, 229, 158, 183, 169, 57, 110, 97, 
            1, 20, 168, 121, 253, 55, 60, 70, 
            160, 246, 59, 63, 129, 202, 37, 112
        ];
        let s2 = U512::from(U256::from_little_endian(&secret_key));
        let p1 = g.naf_ecmult(&s2);
        let p2 = MontgomeryPoint::wNAF8(&secret_key, &lt);
        assert_eq!(p1, p2);
    }

    #[test]
    fn curve25519_validity() {
        let edwards_generator = EdwardsPoint::generator();
        let montgomery_generator = MontgomeryPoint::generator();

        for i in 1..=100 {
            let s = U512::from(i as u8);
            let edwards = edwards_generator.naf_ecmult(&s).into_montgomery();
            let montgomery = montgomery_generator.naf_ecmult(&s);
            eprintln!("This is the private key: {:?}", &s);
            eprintln!("This is the montgomery point: {:x}", &montgomery.x);
            // assert_eq!(edwards, montgomery);
        }
        assert!(false);
    }
}
