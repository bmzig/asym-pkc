use crate::euclidian::modinv;
use bigint::uint::U512;
use crate::constants::*;

#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    pub x: U512,
    pub y: U512,
    pub infinity: bool,
}

impl AffinePoint {

    /// The ecadd function is the backbone of multiplying two elliptic curves. We add two points on an
    /// elliptic curve by finding the line that intersects the two points on the curve which we want to
    /// add and reflecting the third intersection point across the x-axis. The secp256k1 curve has the
    /// equation:
    ///
    /// Y^2 = X^3 + 7
    ///
    /// so any point (x, y) which satsifies this equation is on the elliptic curve.
    ///
    /// Input: point #1 (p1) -> first point to add in P + Q = R.
    /// Input: point #2 (p2) -> second point to add in P + Q = R.
    /// Input: field size (f) -> the size of the secp256k1 field to use (must be prime).
    ///
    /// Output: sum -> the sum of P + Q = R.
    pub fn add(&self, other: &AffinePoint) -> AffinePoint {
        let f = U512::from_big_endian(&FIELD_SIZE);
        if self.infinity { return other.clone(); }
        if other.infinity { return self.clone(); }
        if self.x == other.x {
            if self.y == (f - other.y) { return AffinePoint::default(); }
        }

        let (dy, dx) = self.slope(&other, f);
        let dx = modinv(dx, f);
        let lambda = (dy * dx) % f;
        
        let x3 = {
            if (lambda * lambda) % f < ((self.x + other.x) % f) {
                f - (((self.x + other.x) % f) - ((lambda * lambda) % f))
            }
            else {
                ((lambda * lambda) % f) - ((self.x + other.x) % f)
            }
        };

        let y3 = {
            let t;
            if self.x > x3 {
                t = self.x - x3;
            }
            else {
                t = f - (x3 - self.x);
            }

            if lambda * t > self.y {
                (lambda * t - self.y) % f
            }
            else {
                f - ((self.y - (lambda * t) % f))
            }
        };

        AffinePoint::new(x3, y3)
    }

    #[allow(non_snake_case)]
    pub fn ecmult_double_and_add(&self, s: &U512) -> AffinePoint {
        let mut n = *s;
        let mut res = AffinePoint::default();
        let mut multiplier = self.clone();
        while n > U512::zero() {
            if n.low_u32() % 2 == 1 {
                res = res.add(&multiplier);
            }
            n = n>>1usize;
            multiplier = multiplier.double();
        }
        res
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
    /// NOTE: This is NOT windowed-non-adjacent form as my former self thought it was. wNAF uses
    /// a lookup table and a "window" of precomputed values to make computation exceptionally fast.
    pub fn naf_ecmult(&self, s: &U512) -> AffinePoint {
        let f = U512::from_big_endian(&FIELD_SIZE);
        let mut res = AffinePoint::default();
        let mut multiplier = self.clone();
        let (mut np, mut nm) = naf(*s);
        let mut garbage = self.clone();
        for _ in 0..=256 {
            if np & U512::one() == U512::one() {
                res = res.add(&multiplier);
            }
            else if nm & U512::one() == U512::one() {
                res = res.add(&AffinePoint::new(multiplier.x, f - multiplier.y));
            }
            else {
                garbage = garbage.add(&res);
            }
            np = np >> 1usize;
            nm = nm >> 1usize;
            multiplier = multiplier.double();
        }
        res
    }

    pub fn double(&self) -> AffinePoint {
        self.add(self)
    }

    pub fn new(x: U512, y: U512) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }
 
    pub fn slope(&self, other: &AffinePoint, field: U512) -> (U512, U512) {

        if self.eq(other) {
            return ((((U512::from(3u32) * self.x) % field) * self.x) % field, (U512::from(2u32) * self.y) % field);
        }
        let y;
        if self.y > other.y {
            y = field - (self.y - other.y);
        }
        else {
            y = other.y - self.y;
        }
        let x;
        if self.x > other.x {
            x = field - (self.x - other.x);
        }
        else {
            x = other.x - self.x;
        }
        (y, x)
    }

}

impl PartialEq for AffinePoint {

    fn eq(&self, other: &AffinePoint) -> bool {
        (self.x == other.x) && (self.y == other.y) && (self.infinity == other.infinity)
    }
}

impl Default for AffinePoint {

    fn default() -> Self {
        Self {
            x: U512::zero(),
            y: U512::zero(),
            infinity: true,
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

