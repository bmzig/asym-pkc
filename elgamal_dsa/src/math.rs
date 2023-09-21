use bigint::uint::U512;

#[allow(dead_code)]
pub fn mod_exp(g: U512, a: U512, f: U512) -> U512 {
    if g == U512::zero() { return U512::zero(); }
    if a == U512::zero() { return U512::one(); }
    let is_even = |x : &U512| x.low_u64() & 1 == 0;
    let mut ret = U512::one();
    let mut exp = a;
    let mut x = g;
    while exp > U512::one() {
        if is_even(&exp) {
            x = (x * x) % f;
            exp = exp >> 1;
        }
        else {
            ret = (ret * x) % f;
            x = (x * x) % f;
            exp = exp >> 1;
        }
    }
    (x * ret) % f
}

