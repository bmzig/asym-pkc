use math::mod_exp;
use rand::RngCore;
use bigint::U512;
use euclidian::gcd;

mod math;
mod euclidian;

pub const PRIME_ORDER: [u8; 32] =
    [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

pub const GENERATOR_ARRAY: [u8; 32] = 
    [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    ];
/// We're still just going to use ed25519 because its cool :D


/// derive_public_key will find a user's public key from an existing private key. Users can simply
/// generate a public key by picking a random number ranging from 
/// 0 to (252^2 + 27742317777372353535851937790883648493). This time, however, the private key will
/// be used to sign digital signatures vs sending encrypted data.
///
/// Input: private key (privkey) -> the private key of the user.
///
/// Output: user's corresponding public key.
#[allow(non_snake_case)]
pub fn derive_public_key(privkey: U512) -> U512 {
    let GENERATOR: U512 = U512::from_little_endian(&GENERATOR_ARRAY);
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&PRIME_ORDER);

    math::mod_exp(GENERATOR, privkey, BASEPOINT_ORDER)
}

/// Sign will, well, provide a digital signature for the hash of a digital file. We choose to sign
/// the hash of the document and not the entirety of the data because the hash is a concise way to
/// express the integrity of the ENTIRE document.
///
/// Input: private key (privkey) -> private key of the signer.
/// Input: hash (document_hash) -> hash of the document (any hash should do as long as it is less than 512 bits. 
///
/// Output: Tuple of two signatures. (S1, S2)
#[allow(non_snake_case, unused_assignments)]
pub fn sign(privkey: U512, document_hash: U512) -> (U512, U512) {
    let GENERATOR: U512 = U512::from_little_endian(&GENERATOR_ARRAY);
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&PRIME_ORDER);

    let mut k: U512 = U512::from(rand::thread_rng().next_u64());
    while gcd(k, BASEPOINT_ORDER - U512::one()) != U512::one() {
        k = U512::from(rand::thread_rng().next_u64());
    }

    let s1 = math::mod_exp(GENERATOR, k, BASEPOINT_ORDER);
    let inv_k = euclidian::modinv(k, BASEPOINT_ORDER - U512::one());
    let mut s2 = U512::zero();
    if (privkey * s1) % (BASEPOINT_ORDER - U512::one()) > document_hash {
        s2 = (((BASEPOINT_ORDER - U512::one()) - (((privkey * s1) % (BASEPOINT_ORDER - U512::one())) - document_hash)) * inv_k) % (BASEPOINT_ORDER - U512::one());
    }
    else {
        s2 = ((document_hash - (privkey * s1)) * inv_k) % (BASEPOINT_ORDER - U512::one());
    }
    (s1, s2)
}

/// verify takes two digital signatures of a corresponding document D and verifies that it is
/// a valid signature of the owner of the corresponding public key.
///
/// Input: signature1 (s1) -> first value of tuple returned from "sign."
/// Input: signature2 (s2) -> second value of tuple returned from "sign."
/// Input: public key (pubkey) -> public key of the supposed "signer" of the document.
///
/// Output: bool -> true if the signature is valid, false if it is invalid.
#[allow(non_snake_case)]
pub fn verify(s1: U512, s2: U512, pubkey: U512, document_hash: U512) -> bool {
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&PRIME_ORDER);
    let GENERATOR: U512 = U512::from_little_endian(&GENERATOR_ARRAY);

    let check: U512 = mod_exp(GENERATOR, document_hash, BASEPOINT_ORDER);

    let p1 = mod_exp(pubkey, s1, BASEPOINT_ORDER);
    let p2 = mod_exp(s1, s2, BASEPOINT_ORDER);
    let verif = (p1 * p2) % BASEPOINT_ORDER;
    
    check == verif
}

/// Combines all of the previous functions. Returning true means that the signature is valid.
/// Returning false means that something fishy is going on. This should be true every time.
///
/// Input: secret key (s) -> secret key to use in the Elgamal DSA.
/// Input: document hash (d) -> hash of the document to sign.
///
/// Output: bool -> should be true every time.
#[allow(non_snake_case)]
pub fn elgamal_test(s: U512, d: U512) -> bool {

    let pubkey = derive_public_key(s);
   
    let (s1, s2) = sign(s, d);
    verify(s1, s2, pubkey, d)
}

/// Combines all of the previous functions. Returning true means that the signature is valid.
/// Returning false means that something fishy is going on. This should be false every time.
///
/// Input: secret key (s) -> secret key to use in the Elgamal DSA.
/// Input: document hash (d) -> hash of the document to sign.
///
/// Output: bool -> should be false every time.
pub fn elgamal_test_fail(s: U512, d: U512) -> bool {

    let pubkey = derive_public_key(s);
   
    // Even with the private key being off by a single bit, the signing will fail.
    let (s1, s2) = sign(s - U512::one(), d);
    verify(s1, s2, pubkey, d)
}

#[cfg(test)]
mod tests {
    use crate::math::mod_exp;
    use crate::euclidian::gcd;
    use super::*;
    #[test]
    fn mod_exponentiation() {
        assert_eq!(mod_exp(U512::from(2), U512::from(127), U512::from(71)), U512::from(50));
        assert_eq!(mod_exp(U512::from(2), U512::from(511), U512::from(47298)), U512::from(1778));
        assert_eq!(mod_exp(U512::from(2), U512::from(127), U512::from(3473)), U512::from(1789));
        assert_eq!(mod_exp(U512::from(46), U512::from(3), U512::from(71)), U512::from(66));
        assert_eq!(mod_exp(U512::from(5762), U512::from(7), U512::from(33)), U512::from(26));
        assert_eq!(mod_exp(U512::from(4), U512::from(56), U512::from(941)), U512::from(469));
        assert_eq!(mod_exp(U512::from(3), U512::from(100), U512::from(77)), U512::from(67));
        assert_eq!(mod_exp(U512::from(8), U512::from(55), U512::from(8193)), U512::from(512));
        assert_eq!(mod_exp(U512::from(92), U512::from(27), U512::from(19083)), U512::from(7769));
    }
    #[test]
    fn gcds() {
        assert_eq!(gcd(U512::from(2024), U512::from(748)), U512::from(44));
        assert_eq!(gcd(U512::from(7834), U512::from(48)), U512::from(2));
        assert_eq!(gcd(U512::from(4235), U512::from(15241245)), U512::from(5));
        assert_eq!(gcd(U512::from(32764), U512::from(747)), U512::from(1));
        assert_eq!(gcd(U512::from(72941), U512::from(582717)), U512::from(1));
        assert_eq!(gcd(U512::from(40183), U512::from(45791821)), U512::from(1));
        assert_eq!(gcd(U512::from_dec_str("127098475608364526582164396391421").unwrap(), U512::from_dec_str("457912374852730972352435230953821").unwrap()), U512::from(1)); // very large
        assert_eq!(gcd(U512::from_dec_str("127098475602348752983645965238765498616528749758364526582164396391421").unwrap(), U512::from_dec_str("45791237485218247592876548236498276439730972352435230953821").unwrap()), U512::from(3)); // very large
    }
    #[test]
    fn digital_signature() {
        assert!(elgamal_test(U512::from(312847592u64), U512::from(1342u64)));
        assert!(elgamal_test(U512::from(124512454u64), U512::from(5123542u64)));
        assert!(elgamal_test(U512::from(624523u64), U512::from(4123451u64)));
        assert!(elgamal_test(U512::from(72345u64), U512::from(312341234u64)));
        assert!(elgamal_test(U512::from(2232454u64), U512::from(123412356u64)));
        assert!(elgamal_test(U512::from(2234u64), U512::from(152312453u64)));
        assert!(elgamal_test(U512::from(22345234u64), U512::from(1235421454u64)));
        assert!(elgamal_test(U512::from(2343345234u64), U512::from(123345421454u64)));

        // very large
        assert!(elgamal_test(U512::from_dec_str("2234523431927162487312376421834").unwrap(), U512::from_dec_str("17963872153742134761124512235421454").unwrap()));
        assert!(elgamal_test(U512::from_dec_str("22312124523452345243524345452341425").unwrap(), U512::from_dec_str("1252452411235421454213752452345235").unwrap()));
        assert!(elgamal_test(U512::from_dec_str("221234524521531243241132341345234").unwrap(), U512::from_dec_str("1234213542134123411245231235125421454").unwrap()));
        assert!(elgamal_test(U512::from_dec_str("12341252251245341245512212534").unwrap(), U512::from_dec_str("1237456115245235123524355642345214541251").unwrap()));

        // very large fails
        assert!(!elgamal_test_fail(U512::from_dec_str("3431927162487312376421834").unwrap(), U512::from_dec_str("3872153742134761124512235421454").unwrap()));
        assert!(!elgamal_test_fail(U512::from_dec_str("124523452345243524345452341425").unwrap(), U512::from_dec_str("2452411235421454213752452345235").unwrap()));
        assert!(!elgamal_test_fail(U512::from_dec_str("4524521531243241132341345234").unwrap(), U512::from_dec_str("3542134123411245231235125421454").unwrap()));
        assert!(!elgamal_test_fail(U512::from_dec_str("41252251245341245512212534").unwrap(), U512::from_dec_str("456115245235123524355642345214541251").unwrap()));

    }
}
