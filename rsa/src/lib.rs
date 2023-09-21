use crate::math::mod_exp;
use crate::euclidian::{gcd, modinv};
use crate::flt::flt;

use bigint::uint::U512;

mod flt;
mod math;
mod euclidian;

/// Deriving a rsa public key requires the user to have two large prime numbers and an exponent.
/// Note that the exponent doesn't necessarily have to be large, but the larger it is, the more
/// "mixed" it will become and the harder it is to decrypt the message. 
///
/// Input: secret prime #1 (q) -> first secret key for RSA encryption.
/// Input: secret prime #2 (p) -> second secret key for RSA encryption.
/// Input: public exponent (e) -> exponent to use as the second part of the public key.
///
/// Output: public keys (N, e) -> N, which is the finite field modulo, and e, the exponent used to
/// encrpt data to a user.
pub fn rsa_derive_pubkey(q: U512, p: U512, e: U512) -> (U512, U512) {
    assert!(gcd(e, (q - U512::one()) * (p - U512::one())) == U512::one(), "chosen exponent is not coprime with p-1 * q-1");
    assert!(flt(q));
    assert!(flt(p));
    ((p * q), e)
}

/// Encrypting a message in RSA is as simple as raising the plaintext to the power of the public
/// exponent and taking the modulus as determined by the recipient's public key.
///
/// Input: message (m) -> ascii encoded plaintext message to send to the recipient/holder of the
/// private keys.
/// Input: public key #1 (p1) -> recipient's field modulo (N).
/// Input: public key #2 (p2) -> recipient's public exponent (e).
///
/// Output: ciphertext (c) -> the RSA encrypted ciphertext to send to the owner of the respective
/// private keys.
pub fn rsa_encrypt(m: U512, p1: U512, p2: U512) -> U512 {
    mod_exp(m, p2, p1)
}

/// Decrypting an RSA message requires us to solve two equations: de = 1 (mod (p-1)(q-1)) for d,
/// and m = c^d (mod pq) for m. Of course, this is where it matters to have strong private keys.
/// If a user could ever reverse engineer any value, whether pq, (p-1)(q-1), etc., they can crack
/// your secret keys. RSA should be thought of as deprecated with the now standard use of ECC.
///
/// Note: The order of private keys inputed does not matter.
/// Input: ciphertext (c) -> ciphertext to decrypt.
/// Input: private key #1 (q) -> recipent's private key.
/// Input: private key #2 (p) -> recipient's second private key.
/// Input: exponent (e) -> public exponent used for encryption.
///
/// Output: message (m) -> plaintext message sent to the owner of the secret keys.
pub fn rsa_decrypt(c: U512, q: U512, p: U512, e: U512) -> U512 {
    assert!(flt(q));
    assert!(flt(p));
    let pub_key = p * q;
    let sec_exp = (q - U512::one()) * (p - U512::one());
    let dec = modinv(e, sec_exp);
    //let dec = mod_exp(e, sec_exp - U512::from(2), sec_exp);
    mod_exp(c, dec, pub_key)
}

/// RSA test basically combines all the functions for encrypting your own data and tests to make
/// sure that the RSA algorithm works as intended. It is meant to be used exclusively for testing
/// (which is why it gets a random number inputed).
pub fn rsa_test(p: U512, q: U512, e: U512, m: U512) -> bool {
    #[allow(non_snake_case)]
    let (N, e) = rsa_derive_pubkey(q, p, e);
    let c = rsa_encrypt(m, N, e);
    let m2 = rsa_decrypt(c, q, p, e);
    eprintln!("{:?}", m);
    eprintln!("{:?}", m2);
    assert!(m2 == m);
    true
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    #[test]
    fn fermats_little_theorem() {
        assert!(flt(U512::from(10093)));
        assert!(flt(U512::from(10099)));
        assert!(flt(U512::from(10103)));
        assert!(flt(U512::from(10111)));
        assert!(flt(U512::from(10133)));
        assert!(flt(U512::from(10139)));
        assert!(flt(U512::from(10141)));
        assert!(flt(U512::from(10151)));
        assert!(flt(U512::from(10159)));
        assert!(flt(U512::from(10163)));
        assert!(flt(U512::from(10169)));
        assert!(!flt(U512::from(10102)));
        assert!(!flt(U512::from(10143)));
        assert!(!flt(U512::from(10165)));
        assert!(!flt(U512::from(10137)));
        assert!(!flt(U512::from(10199)));
    }
    #[test]
    fn rsa_encryption() {
        #[allow(non_snake_case)]
        let (N, e) = rsa_derive_pubkey(U512::from(1223u64), U512::from(1987u64), U512::from(948047u64));
        let c = rsa_encrypt(U512::from(1070777u64), N, e);
        let m = rsa_decrypt(c, U512::from(1223u64), U512::from(1987u64), e);
        assert_eq!(m, U512::from(1070777u64));
        assert!(rsa_test(U512::from(1223u64), U512::from(1987u64), U512::from(948047u64), U512::from(1070777u64)));
        assert!(rsa_test(U512::from(1223u64), U512::from(1987u64), U512::from(9129874561u64), U512::from(rand::thread_rng().next_u64() % 1000000)));
        assert!(rsa_test(U512::from(1000193u64), U512::from(1000199u64), U512::from(246258617u64), U512::from(rand::thread_rng().next_u64() % 100000000)));
        assert!(rsa_test(U512::from(1000211u64), U512::from(1000213u64), U512::from(83731u64), U512::from(rand::thread_rng().next_u64() % 213546712)));
        assert!(rsa_test(U512::from(1000231u64), U512::from(1000249u64), U512::from(45641737u64), U512::from(rand::thread_rng().next_u64() % 123645321)));
        assert!(rsa_test(U512::from(542000861u64), U512::from(542000867u64), U512::from(24727u64), U512::from(rand::thread_rng().next_u64() % 138765413)));
        assert!(rsa_test(U512::from(542000929u64), U512::from(542000951u64), U512::from(948047u64), U512::from(rand::thread_rng().next_u64() % 1827635418)));
        assert!(rsa_test(U512::from(542000929u64), U512::from(1987u64), U512::from(9480473u64), U512::from(rand::thread_rng().next_u64() % 27635418)));
    }
}
