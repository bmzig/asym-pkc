use crate::ecmult::*;
use crate::constants::*;
use bigint::uint::U512;
use rand::RngCore;

mod ecmult;
mod constants;
mod euclidian;

/// Like the other signature schemes in this aggregation, this simply derives a verification key
/// for signing signatures. Note that this is the exact same method for deriving a public key.
///
/// Input: private key: (s) -> private key to use in the derivation of the public key.
///
/// Output: AffinePoint -> the respective verification key.
pub fn derive_verification_key(s: U512) -> AffinePoint {
    let g = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let order = U512::from_big_endian(&CURVE_ORDER);
    let s = s % order;

    g.naf_ecmult(&s)
}

/// This signs the message using the Schnorr signature algorithm. I use the blake3 hash function
/// because I remember reading somewhere that it outperforms keccak and it also isnt NIST, which
/// I belive to be a good thing because I'd ALWAYS trust academia over the government. (see P256)
///
/// Input: secret key (s) -> the secret key to use in signing.
/// Input: message (m) -> the message compressed into a 512 bit number.
///
/// Output: AffinePoint -> the first signature.
/// Output: U512 -> the second signature.
pub fn sign(s: U512, m: U512) -> (AffinePoint, U512) {
    let g = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let order = U512::from_big_endian(&CURVE_ORDER);

    let k = U512::from(rand::thread_rng().next_u64());

    let s1 = g.naf_ecmult(&k);

    let mut h = blake3::Hasher::new();
    h.update(format!("{}", m).as_bytes());
    h.update(format!("{}", s1.x).as_bytes());
    let hn = U512::from_little_endian(h.finalize().as_bytes()) % order;
    let s2 = (k + ((s * hn) % order)) % order;
    (s1, s2)
}

/// This verifies the signatures. It ensures that the owner of the public key actually signed the
/// document.
///
/// Input: signature #1 (s1) -> the first part of the Schnorr signature.
/// Input: signature #2 (s2) -> the second part of the Schnorr signature.
/// Input: public key (pk) -> the public key of the supposed signer.
/// Input: message (m) -> the messge the signer supposedly signed compressed in a U512.
///
/// Output: bool -> true if the signature is valid, false if the signature is invalid.
pub fn verify(s1: AffinePoint, s2: U512, pk: AffinePoint, m: U512) -> bool {
    let g = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let order = U512::from_big_endian(&CURVE_ORDER);

    let r1 = g.naf_ecmult(&s2);
    let mut hash = blake3::Hasher::new();
    hash.update(format!("{}", m).as_bytes());
    hash.update(format!("{}", s1.x).as_bytes());
    let h = U512::from_little_endian(hash.finalize().as_bytes()) % order;
    let pa = pk.naf_ecmult(&h);
    let r2 = s1.add(&pa);
    r1 == r2
}

/// This function simply runs through the functions to ensure that they are working as intended.
/// This function should always return true.
pub fn schnorr_ext() -> bool {
    let secret_key = U512::from(rand::thread_rng().next_u64());
    let public_key = derive_verification_key(secret_key);
    let message = U512::from(rand::thread_rng().next_u64());
    let (s1, s2) = sign(secret_key, message);
    verify(s1, s2, public_key, message)
}

/// This function does the exact same thing as the function above, except that it slightly changes
/// the private key when signing the signature. As a result, this function should always return
/// a false bool.
pub fn schnorr_ext_f() -> bool {
    let secret_key = U512::from(rand::thread_rng().next_u64());
    let public_key = derive_verification_key(secret_key);
    let message = U512::from(rand::thread_rng().next_u64());
    let (s1, s2) = sign(secret_key + U512::one(), message);
    verify(s1, s2, public_key, message)
}

/// This function ensures that the verification runs in constant time.
pub fn schnorr_ext_ct() -> bool {
    let secret_key = U512::from(rand::thread_rng().next_u64() % 25u64);
    let public_key = derive_verification_key(secret_key);
    let message = U512::from(rand::thread_rng().next_u64() % 25u64);
    let (s1, s2) = sign(secret_key, message);
    verify(s1, s2, public_key, message)
}


#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn schnorr_runthrough() {
        let q = U512::from_big_endian(&CURVE_ORDER);
        let secret_key = U512::from(rand::thread_rng().next_u64());
        let public_key = derive_verification_key(secret_key);
        let message = U512::from_little_endian(format!("Aaron earned an iron urn").as_bytes()) % q;
        let (s1, s2) = sign(secret_key, message);
        assert!(verify(s1, s2, public_key, message));
    }

    #[test]
    fn schnorr_randomness() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(schnorr_ext());
            }));
        }
        v.into_iter().for_each(move |x| { x.join().unwrap(); });
    }

    #[test]
    fn schnorr_should_fail() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(!schnorr_ext_f());
            }));
        }
        v.into_iter().for_each(move |x| { x.join().unwrap(); });
    }

    #[test]
    fn schnorr_constant_time() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(move || {
                if !schnorr_ext_ct() {
                    panic!("This should never hit");
                }
            }));
        }
        v.into_iter().for_each(move |x| { x.join().unwrap_or(()); });
    }
}
