use crate::euclidian::modinv;
use bigint::uint::U512;
use crate::constants::*;

#[derive(Clone, Copy, Debug)]
pub struct MontgomeryPoint {
    pub x: U512,
    pub y: U512,
    pub infinity: bool,
}

impl MontgomeryPoint {
    pub fn add(&self, other: &MontgomeryPoint) -> MontgomeryPoint {
        let f = U512::from_big_endian(&FIELD);
        if self.infinity { return other.clone(); }
        if other.infinity { return self.clone(); }
        if (self.x == other.x) && (self.y == f - other.y) { return MontgomeryPoint::default(); }
        let a = U512::from(486662u32);
        let lambda = self.slope(*other, f);
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
    /// calculations compared to the double-and-add method due to the efficiency of the NAF lookup
    /// table.
    ///
    /// Input: scalar multiplier (s) -> number of times to add the elliptic curve point.
    /// Input: point (P) -> Affine point of the elliptic curve to multiply.
    /// Input: field (f) -> The field size of the elliptic curve (we're using secp256k1).
    ///
    /// Output: result point -> The point of nP.
    ///
    /// As in other files in this repository, I originally mistook NAF with wNAF. NAF is much, much
    /// slower than wNAF
    pub fn naf_ecmult(&self, s: &U512) -> MontgomeryPoint {
        let f = U512::from_big_endian(&FIELD);
        let mut res = MontgomeryPoint::default();
        let mut garbage = self.clone();
        let mut multiplier = self.clone();
        let (mut np, mut nm) = naf(*s);
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
            multiplier = multiplier.double();
        }
        res
    }

    pub fn double(&self) -> MontgomeryPoint {
        self.add(self)
    }
 
    pub fn on_curve(&self) -> bool {
        let a = U512::from(486662u32);
        let f = U512::from_big_endian(&FIELD);
        (self.y * self.y) % f == (((((((self.x * self.x) % f) * self.x) % f) + ((((self.x * self.x) % f) * a) % f)) % f) + self.x) % f
    }

    pub fn slope(&self, other: MontgomeryPoint, f: U512) -> U512 {
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

    pub fn new(x: U512, y: U512) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }
}

fn naf(x: U512) -> (U512, U512) {
    let xh = x >> 1usize;
    let x3 = x + xh;
    let c = xh ^ x3;
    let np = x3 & c;
    let nm = xh & c;
    (np, nm)
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

impl PartialEq for MontgomeryPoint {

    fn eq(&self, other: &MontgomeryPoint) -> bool {
        self.x == other.x && self.y == other.y && !self.infinity && !other.infinity
    }
}

