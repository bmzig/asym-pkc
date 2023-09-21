use bigint::uint::U512;

#[allow(dead_code)]
pub fn gcd(a: U512, b: U512) -> U512 {
    let mut r0 = a;
    let mut r1 = b;
    if r1 > r0 {
        std::mem::swap(&mut r0, &mut r1);
    }
    loop {
        let r2 = r0 % r1;
        if r2 == U512::zero() {
            return r1;
        }
        r0 = r1;
        r1 = r2;
    }
}
