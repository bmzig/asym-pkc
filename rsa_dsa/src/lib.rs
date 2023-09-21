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

/// We sign a message with our RSA private keys to verify the authenticity of a document. Because
/// the DSA is built on RSA, it guarantees that the signer is probably legit (since if it wasn't
/// then RSA would be broken or the keys of the owner were compromised).
///
/// Input: document hash (d) -> hash of the document to sign.
/// Input: private key #1 (p) -> first private key of the signer.
/// Input: private key #2 (q) -> second private key of the signer.
/// Input: public exponent (e) -> public key for the target signer.
///
/// Output: signature (S) -> signatures of the document for people to verify.
pub fn sign(d: U512, p: U512, q: U512, e: U512) -> U512 {
    let x = modinv(e, (p - U512::one()) * (q - U512::one()));
    mod_exp(d, x, p * q)
}

/// Verifying an RSA signature is pretty straitforward because we only have one signature to verify
/// (unlike DSA, Elgamal DSA, and ECDSA). Also, the computation is actually pretty light, only
/// reqiring a few modular exponents. The complete equation is just verifying that the hash of the
/// document is equal to S^e (mod pq)
///
/// Input: signature (S) -> signature to use in verification.
/// Input: public key (N) -> supposed signer's public key.
/// Input: exponent (e) -> public exponent used for encryption.
/// Input: document_hash (d) -> hash of the document that the signer supposedly signed.
///
/// Output: bool -> true means signature is valid. False means that it is invalid.
#[allow(non_snake_case)]
pub fn verify(S: U512, N: U512, e: U512, d: U512) -> bool {
    let res = mod_exp(S, e, N);
    if res == d { return true; }
    false
}

/// RSA test tests what should be valid signatures. As such, this test should always return a true,
/// otherwise some function in the DSA is broken.
///
/// Input: private key #1 (p) -> private key to use in signing.
/// Input: private key #2 (q) -> other private key to use.
/// Input: public exponent (e) -> public key exponent with trait that GCD(e, (p-1)(q-1)) = 1.
/// Input: document hash (d) -> hash of the document to sign and verify.
#[allow(non_snake_case)]
pub fn rsa_test(p: U512, q: U512, e: U512, d: U512) -> bool {
    let (N, e) = rsa_derive_pubkey(q, p, e);
    let S = sign(d, p, q,e);
    verify(S, N, e, d)
}

/// RSA test fail is the exact same as RSA test, except the document hash is just one bit off of
/// what it should be. This is really cool because if somebody tampers with a document, the hash
/// will be different and the signature will no longer be valid, so these digital signatures
/// actually provide some pretty dang good integrity. 
///
/// Input: private key #1 (p) -> private key to use in signing.
/// Input: private key #2 (q) -> other private key to use.
/// Input: public exponent (e) -> public key exponent with trait that GCD(e, (p-1)(q-1)) = 1.
/// Input: document hash (d) -> hash of the document to sign and verify.
#[allow(non_snake_case)]
pub fn rsa_test_fail(p: U512, q: U512, e: U512, d: U512) -> bool {
    let (N, e) = rsa_derive_pubkey(q, p, e);
    let S = sign(d, p, q,e);
    verify(S, N, e, d - U512::one())
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
    #[allow(non_snake_case)]
    fn rsa_digital_signatures() {
        let (N, e) = rsa_derive_pubkey(U512::from(1223u64), U512::from(1987u64), U512::from(948047u64));
        let S = sign(U512::from(1070777u64), U512::from(1223u64), U512::from(1987u64), U512::from(948047u64));
        assert!(verify(S, N, e, U512::from(1070777u64)));
        assert!(rsa_test(U512::from(1223u64), U512::from(1987u64), U512::from(948047u64), U512::from(1070777u64)));
        assert!(rsa_test(U512::from(1223u64), U512::from(1987u64), U512::from(9129874561u64), U512::from(rand::thread_rng().next_u64() % 1000000)));
        assert!(rsa_test(U512::from(10193u64), U512::from(1000199u64), U512::from(246258617u64), U512::from(rand::thread_rng().next_u64() % 100000000)));
        assert!(rsa_test(U512::from(1120211u64), U512::from(1000213u64), U512::from(83731u64), U512::from(rand::thread_rng().next_u64() % 213546712)));
        assert!(rsa_test(U512::from(2502317u64), U512::from(1000249u64), U512::from(45641737u64), U512::from(rand::thread_rng().next_u64() % 123645321)));
        assert!(rsa_test(U512::from(33311u64), U512::from(542000867u64), U512::from(24727u64), U512::from(rand::thread_rng().next_u64() % 138765413)));
        assert!(rsa_test(U512::from(367500929u64), U512::from(542000951u64), U512::from(948047u64), U512::from(rand::thread_rng().next_u64() % 1827635418)));
        assert!(rsa_test(U512::from(37670153u64), U512::from(1987u64), U512::from(9480473u64), U512::from(rand::thread_rng().next_u64() % 27635418)));

        // Same tests as above (kinda because thread_rng is always changing the document hash
        // value) except that the tests SHOULD fail.
        assert!(!rsa_test_fail(U512::from(1223u64), U512::from(1987u64), U512::from(948047u64), U512::from(1070777u64)));
        assert!(!rsa_test_fail(U512::from(1223u64), U512::from(1987u64), U512::from(9129874561u64), U512::from(rand::thread_rng().next_u64() % 1000000)));
        assert!(!rsa_test_fail(U512::from(10193u64), U512::from(1000199u64), U512::from(246258617u64), U512::from(rand::thread_rng().next_u64() % 100000000)));
        assert!(!rsa_test_fail(U512::from(1120211u64), U512::from(1000213u64), U512::from(83731u64), U512::from(rand::thread_rng().next_u64() % 213546712)));
        assert!(!rsa_test_fail(U512::from(2502317u64), U512::from(1000249u64), U512::from(45641737u64), U512::from(rand::thread_rng().next_u64() % 123645321)));
        assert!(!rsa_test_fail(U512::from(33311u64), U512::from(542000867u64), U512::from(24727u64), U512::from(rand::thread_rng().next_u64() % 138765413)));
        assert!(!rsa_test_fail(U512::from(367500929u64), U512::from(542000951u64), U512::from(948047u64), U512::from(rand::thread_rng().next_u64() % 1827635418)));
        assert!(!rsa_test_fail(U512::from(37670153u64), U512::from(1987u64), U512::from(9480473u64), U512::from(rand::thread_rng().next_u64() % 27635418)));

    }
}
