use bigint::uint::U512;
use crate::math::mod_exp;

pub fn flt(p: U512) -> bool {
    for i in 2..10 {
        if mod_exp(U512::from(i as u32), p - U512::one(), p) != U512::one() { return false; }
    }
    true
}
