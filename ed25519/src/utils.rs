use bigint::uint::U512;

pub fn modinv(e: U512, p: U512) -> U512 {
    if p == U512::one() { return U512::one(); }
    let (mut a, mut m, mut x, mut inv) = (e.clone(), p.clone(), U512::zero(), U512::one());

    while a > U512::one() {
        let div = a / m;
        let rem = a % m;
        if (div * x) > inv {
            inv = p - (((div * x) % p) - inv);
        }
        else {
            inv = (inv - (div * x)) % p;
        }
        a = rem;
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x, &mut inv);
    }
    inv
}

pub fn naf(x: &U512) -> (U512, U512) {
    let xh = *x >> 1usize;
    let x3 = *x + xh;
    let c = xh ^ x3;
    let np = x3 & c;
    let nm = xh & c;
    (np, nm)
}

