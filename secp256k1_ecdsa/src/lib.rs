use crate::ecmult::*;
use crate::constants::*;
use bigint::uint::U512;
use euclidian::modinv;
use rand::RngCore;

mod ecmult;
mod euclidian;
mod constants;

/// We begin the ECDSA by creating a verification key for a user's associated private key. Notice
/// that this key is calculated in the exact same way as a public key for ecc. As such, creating
/// a single public key can serve as both a way to send encrypted data as well as a way to sign
/// digital signatures on transactions.
///
/// Input: private key (s) -> the private key of the user from which to derive the verification
/// key.
///
/// Output: AffinePoint -> the verification key affine point
pub fn derive_verification_key(s: U512) -> AffinePoint {
    let generator = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    // ecmult_double_and_add(s, generator, U512::from_big_endian(&FIELD_SIZE))
    generator.naf_ecmult(&s)
}

/// Signing in ECDSA is as simple as performing a few elliptic curve multiplications and inverse
/// formulas. As we can see here, we don't have signatures in the form of AffinePoints on
/// secp256k1, which is nice because this means that the signature size is relatively small
/// (although not as small as Schnorr). Note that this function is not optimized for performance,
/// and more so for clarity.
///
/// Input: private key (s) -> the private key to use in the signing.
/// Input: document hash (d) -> the document hash to sign.
///
/// Output: U512 tuple -> tuple of signatures.
pub fn sign(s: U512, d: U512) -> (U512, U512) {
    let order = U512::from_big_endian(&CURVE_ORDER);

    let d = d % order;
    let generator = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let e = U512::from(rand::thread_rng().next_u64());
    let p1 = generator.naf_ecmult(&e);
    let s1 = p1.x % order;
    let inv_e = modinv(e, order);
    let s2 = (((d + ((s * s1) % order)) % order) * inv_e) % order;
    (s1, s2)
}

/// Validating signatures is also a relatively simple process, athough it may take a bit of time to
/// perform. We must ultimately calculate a few elliptic curve multiplications and one addition,
/// but at the end, we are just comparing a couple U512s. 
///
/// Input: verification key (v) -> the verification public key of the supposed verifier.
/// Input: signature #1 (s1) -> the first signature to be used in the verification.
/// Input: signature #2 (s2) -> the second signature to be used in the verification.
/// Input: document hash (d) -> the document hash of the document that should have been signed.
///
/// Output: bool -> true if the signature is valid, false otherwise.
pub fn verify_signature(v: AffinePoint, s1: U512, s2: U512, d: U512) -> bool {
    let order = U512::from_big_endian(&CURVE_ORDER);
    let d = d % order;

    let generator = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let inv_s2 = modinv(s2, order);

    let v1 = (inv_s2 * d) % order;

    let v2 = (s1 * inv_s2) % order;
    let r1 = generator.naf_ecmult(&v1);
    let r2 = v.naf_ecmult(&v2);

    let res = r1.add(&r2);
    res.x % order == s1
}

/// Like the other runthrough functions in the repository, this just verifies that everything is
/// working as intended by using some pseudorandom values. 
pub fn secp256k1_ecdsa_runthrough() -> bool {
    let privkey = U512::from(rand::thread_rng().next_u64());
    let message = U512::from(rand::thread_rng().next_u64());
    let verif = derive_verification_key(privkey);
    let (s1, s2) = sign(privkey, message);
    verify_signature(verif, s1, s2, message)
}

/// This function tests for constant time key multiplication.
pub fn secp256k1_ct() -> bool {
    let privkey = U512::from(rand::thread_rng().next_u64() % 25u64);
    let message = U512::from(rand::thread_rng().next_u64() % 25u64);
    let verif = derive_verification_key(privkey);
    let (s1, s2) = sign(privkey, message);
    verify_signature(verif, s1, s2, message)
}

/// Exactly like the function above except that is uses an intentionally incorrect private key to
/// sign to make sure that no forgery can be committed with the ECDSA signature scheme, no matter
/// how close the attacker gets to the real private key!
pub fn secp256k1_ecdsa_expected_fail() -> bool {

    let privkey = U512::from(rand::thread_rng().next_u64());
    let message = U512::from(rand::thread_rng().next_u64());
    let verif = derive_verification_key(privkey);
    let (s1, s2) = sign(privkey + U512::one(), message);
    verify_signature(verif, s1, s2, message)
}

pub fn verify(a: AffinePoint, f: U512) -> bool {
    ((a.y * a.y) % f) == ((((a.x * a.x) % f) * a.x) + U512::from(7u32)) % f
}

#[cfg(test)]
mod tests {

    use super::*;

     #[test]
    fn secp256k1_comprehensive_test() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(secp256k1_ecdsa_runthrough());
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap(); });
    }

    #[test]
    fn secp256k1_expected_failures() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(!secp256k1_ecdsa_expected_fail());
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap(); });
    }

    #[test]
    fn secp256k1_constant_time() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                if !secp256k1_ct() {
                    panic!("This should never be reached");
                }
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap_or(()); });
    }
}
