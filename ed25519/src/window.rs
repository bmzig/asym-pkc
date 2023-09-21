#![allow(dead_code)]

use std::collections::HashMap;
use crate::montgomery::*;
use crate::constants::*;
use bigint::uint::U512;
use crate::utils::naf;

#[derive(Debug, Clone)]
pub struct LookupTable {
    pub map: HashMap<(u8, u8), MontgomeryPoint>,
}

// This can most certainly be cleaned up with macros, and I plan on doing so later, but for now
// I am using a basic HashMap to represent the NAF LookupTable to serve as a simple PoC for a real
// implementation.
//
//     |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9  |  10  |  11  |  12  |  13  |  14  | ||| | 32 |
// | 0 |  0  |2^0*1|2^0*2|2^0*3|2^0*4|2^0*5|2^0*6|2^0*7|2^0*8|2^0*9|2^0*10|2^0*11|2^0*12|2^0*13|2^0*14|
// | 1 |  0  |2^8*1|2^8*2|2^8*3|2^8*4|2^8*5|2^8*6|2^8*7|2^8*8|2^8*9|2^8*10|2^8*11|2^8*12|2^8*13|2^8*14|
// | 2 |  0  |2^16*1|2^16*2|2^16*3|2^16*4|2^16*5|2^16*6|2^16*7|2^16*8|2^16*9|2^16*10|2^16*11|2^16*12|2^16*13|2^16*14|
// | 3 |  0  |2^24*1|2^24*2|2^24*3|2^24*4|2^24*5|2^24*6|2^24*7|2^24*8|2^24*9|2^24*10|2^24*11|2^24*12|2^24*13|2^24*14|
// | 4 |  0  |2^32*1|2^32*2|2^32*3|2^32*4|2^32*5|2^32*6|2^32*7|2^32*8|2^32*9|2^32*10|2^32*11|2^32*12|2^32*13|2^32*14|
// | 5 |  0  |2^40*1|2^40*2|2^40*3|2^40*4|2^40*5|2^40*6|2^40*7|2^40*8|2^40*9|2^40*10|2^40*11|2^40*12|2^40*13|2^40*14|
// | 6 |  0  |2^48*1|2^48*2|2^48*3|2^48*4|2^48*5|2^48*6|2^48*7|2^48*8|2^48*9|2^48*10|2^48*11|2^48*12|2^48*13|2^48*14|
// | 7 |  0  |2^56*1|2^56*2|2^56*3|2^56*4|2^56*5|2^56*6|2^56*7|2^56*8|2^56*9|2^56*10|2^56*11|2^56*12|2^56*13|2^56*14|
// | 8 |  0  |2^64*1|2^64*2|2^64*3|2^64*4|2^64*5|2^64*6|2^64*7|2^64*8|2^64*9|2^64*10|2^64*11|2^64*12|2^64*13|2^64*14|
// | 9 |  0  |2^72*1|2^72*2|2^72*3|2^72*4|2^72*5|2^72*6|2^72*7|2^72*8|2^72*9|2^72*10|2^72*11|2^72*12|2^72*13|2^72*14|
// | 10 |  0  |2^80*1|2^80*2|2^80*3|2^80*4|2^80*5|2^80*6|2^80*7|2^80*8|2^80*9|2^80*10|2^80*11|2^80*12|2^80*13|2^80*14|
// | 11 |  0  |2^88*1|2^88*2|2^88*3|2^88*4|2^88*5|2^88*6|2^88*7|2^88*8|2^88*9|2^88*10|2^88*11|2^88*12|2^88*13|2^88*14|
// | 12 |  0  |2^96*1|2^96*2|2^96*3|2^96*4|2^96*5|2^96*6|2^96*7|2^96*8|2^96*9|2^96*10|2^96*11|2^96*12|2^96*13|2^96*14|
// | ||| |
// | 32

impl LookupTable {

    /// This is the initialization for a window of length 4 bits. It takes ~1800 seconds to make.
    /// I do not use it because it is less efficient than a table with length 8 bits, which is
    /// below.
    #[allow(dead_code)]
    pub fn initialize_window4() -> Self {
        let z = MontgomeryPoint::default();
        let g = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );
        let mut r = z.clone();
        let f = U512::from_big_endian(&PRIME_ORDER);
        let mut ret = Self { map: HashMap::new() };
        for i in 0..=63 {
            let m = fast_pow(U512::from(2u32), U512::from(4u32 * i as u32));
            for j in 0..=63 {
                let x = non_ct_ecmult(m * U512::from(j as u32), r, f);
                // eprintln!("This is the input point for 2^{:?} * {:?}\n{:?}", i * 4, j, x);
                ret.map.insert((i, j), x);
                if j == 0 { r = r.add(&g); }
            }
            r = z.clone();
        }
        ret
    }

    /// This is the implementation the creation of a lookup table for elliptic curve multiplication
    /// for curve25519. It takes ~2200 seconds to create, but it requires half the amount of
    /// additions as compared to the table with a window of 4 bits. Over time, this makes this
    /// table much more efficient.
    pub fn initialize_window8() -> Self {
        let z = MontgomeryPoint::default();
        let g = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );
        let mut r = z.clone();
        let f = U512::from_big_endian(&PRIME_ORDER);
        let mut ret = Self { map: HashMap::new() };
        for i in 0..32 {
            let m = fast_pow(U512::from(2u32), U512::from(8u32 * i as u32));
            for j in 0..=255 {
                let x = non_ct_ecmult(m * U512::from(j as u32), r, f);
                ret.map.insert((i, j), x);
                if j == 0 { r = r.add(&g); }
            }
            r = z.clone();
        }
        ret
    }

}


/// This is not constant time because it doesn't have to be -- we are just filling up the lookup
/// table.
fn non_ct_ecmult(s: U512, p: MontgomeryPoint, f: U512) -> MontgomeryPoint {
    let mut res = MontgomeryPoint::default();
    let mut multiplier = p.clone();
    let (mut np, mut nm) = naf(&s);
    while np != U512::zero() || nm != U512::zero() {
        if np & U512::one() == U512::one() {
            res = res.add(&multiplier);
        }
        else if nm & U512::one() == U512::one() {
            res = res.add(&MontgomeryPoint::new(multiplier.x, f - multiplier.y));
        }
        np = np >> 1usize;
        nm = nm >> 1usize;
        multiplier = multiplier.add(&multiplier);
    }
    res
}

fn fast_pow(g: U512, a: U512) -> U512 {
    if g == U512::zero() { return U512::zero(); }
    if a == U512::zero() { return U512::one(); }
    let is_even = |x : &U512| x.low_u64() & 1 == 0;
    let mut ret = U512::one();
    let mut exp = a;
    let mut x = g;
    while exp > U512::one() {
        if is_even(&exp) {
            x = x * x;
            exp = exp >> 1;
        }
        else {
            ret = ret * x;
            x = x * x;
            exp = exp >> 1;
        }
    }
    x * ret
}

#[cfg(test)]
mod tests {

    use rand::RngCore;

    use super::*;

    fn random() -> [u8; 32] {
        let mut ret: [u8; 32] = [0; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut ret);
        ret
    }

    // This test takes a very long time to run because it generates a lookup table for curve25519.
    // For this reason it is optional.
    #[test]
    #[ignore]
    pub fn proper_initialization() {
        let lt = LookupTable::initialize_window8();
        let g = MontgomeryPoint::new(
            U512::from_big_endian(&GENERATOR_X),
            U512::from_big_endian(&GENERATOR_Y)
        );
        let f = U512::from_big_endian(&PRIME_ORDER);
        for _ in 0..=100 {
            let bytes = random();
            let expected = non_ct_ecmult(U512::from_little_endian(&bytes), g, f);
            let wnaf = MontgomeryPoint::wNAF8(&bytes, &lt);
            assert_eq!(expected, wnaf);
        }
    }
}
