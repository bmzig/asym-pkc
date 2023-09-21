use rand::RngCore;
use bigint::U512;

mod math;
mod euclidian;

const BASEPOINT_ORDER_ARRAY: [u8; 32] = 
    [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

const GENERATOR_ARRAY: [u8; 32] = 
    [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    ];

/// For the sake of simplicity, we are going to use the ed25519 generator and prime field for the
/// key calculations.


/// derive_public_key will find a user's public key from an existing private key. Users can simply
/// generate a public key by picking a random number ranging from 
/// 0 to (252^2 + 27742317777372353535851937790883648493).
///
/// Input: private key (privkey) -> the private key of the user.
///
/// Output: user's corresponding public key.
#[allow(non_snake_case)]
pub fn derive_public_key(privkey: U512) -> U512 {
    let GENERATOR: U512 = U512::from_little_endian(&GENERATOR_ARRAY);
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&BASEPOINT_ORDER_ARRAY);

    math::mod_exp(GENERATOR, privkey, BASEPOINT_ORDER)
}

/// encrypt_elgamal will encrypt an ascii message using an existing public key. The public key must
/// have a user owning the private key or the message will be lost forever! (That being until the
/// DHP is solved). 
///
/// Input: public key (pubkey) -> public key of the message recipient.
/// Input: ascii encoded message (ascii_message) -> message to send to the owner of the respective
/// secret key.
///
/// Output: tuple containing two ciphertexts, as appropriate with elgamal encryption.
#[allow(non_snake_case)]
pub fn encrypt_elgamal(pubkey: U512, ascii_message: U512) -> (U512, U512) {
    let GENERATOR: U512 = U512::from_little_endian(&GENERATOR_ARRAY);
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&BASEPOINT_ORDER_ARRAY);
    let throwaway_key: U512  = U512::from(rand::thread_rng().next_u64());

    let c1 = math::mod_exp(GENERATOR, throwaway_key, BASEPOINT_ORDER);
    let c2 = (ascii_message * math::mod_exp(pubkey, throwaway_key, BASEPOINT_ORDER)) % BASEPOINT_ORDER;

    (c1, c2)

}

/// decrypt_elgamal takes in the two ciphertexts and, using the user's appropriate private key,
/// decrypt the ascii message.
///
/// Input: ciphertext1 (c1) -> first value of tuple returned from "elgamal_encrypt."
/// Input: ciptertext2 (c2) -> second value of tuple returned from "elgamal_encrypt."
/// Input: private key (privkey) -> user's appropriate private key. If the wrong private key is
/// used, the message will (obviously) not be encrypted.
///
/// Output: message encoded in ascii
#[allow(non_snake_case)]
pub fn decrypt_elgamal(c1: U512, c2: U512, privkey: U512) -> U512 {
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&BASEPOINT_ORDER_ARRAY);

    let y = BASEPOINT_ORDER - U512::one() - privkey;
    let x = math::mod_exp(c1, y, BASEPOINT_ORDER);
    let res = (x * c2) % BASEPOINT_ORDER;
    res

}

#[allow(non_snake_case)]
pub fn elgamal_test(s: U512, m: U512) -> bool {

    // Derive pub key
    
    let GENERATOR: U512 = U512::from_little_endian(&GENERATOR_ARRAY);
    let BASEPOINT_ORDER: U512 = U512::from_little_endian(&BASEPOINT_ORDER_ARRAY);
    let pub_key = math::mod_exp(GENERATOR, s, BASEPOINT_ORDER);

    // This could have more entropy to be safer
    
    let throwaway_key: U512  = U512::from(rand::thread_rng().next_u64());

    // Encrypt

    let c1 = math::mod_exp(GENERATOR, throwaway_key, BASEPOINT_ORDER);
    let c2 = (m * math::mod_exp(pub_key, throwaway_key, BASEPOINT_ORDER)) % BASEPOINT_ORDER;

    // Decrypt    

    let y = BASEPOINT_ORDER - U512::one() - s;
    let x = math::mod_exp(c1, y, BASEPOINT_ORDER);
    let res = (x * c2) % BASEPOINT_ORDER;

    // Verify m == m

    assert_eq!(res, m);
    true
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
    fn encrypt() {
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
    }
}
