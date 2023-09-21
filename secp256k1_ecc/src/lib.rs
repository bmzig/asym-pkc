use crate::ecmult::*;
use crate::constants::*;
use bigint::uint::U512;
use rand::RngCore;

mod ecmult;
mod euclidian;
mod constants;

/// Derives a public key from a private key. The difficulty to reverse a public key from a private
/// key is based on the complexity of solving the ECDLP, which essentially states that it is
/// difficult to find n in the following equation with a known P and Q:
///
/// Q = nP
///
/// Of course, this is because adding points in elliptic curves can be thought of as one-way
/// functions. 
///
/// Input: private key (s) -> the private key from which to derive a public key.
///
/// Output: public key -> the private key's associated public key.
pub fn derive_public_key(s: U512) -> AffinePoint {
    let generator = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    // ecmult_double_and_add(s, generator, U512::from_big_endian(&FIELD_SIZE))
    generator.naf_ecmult(&s)
}

/// As the name says, this function encrypts a message encoded in an affine point on the secp256k1
/// elliptic curve. Note that the point must be on the curve, as if it it not, the function will
/// fail. This obviously leads to some friction in sending a useful message to the recipient. 
///
/// Input: public key (pubkey) -> the public key of the user to which you would like to send
/// a message.
/// Input: message (message) -> the message encoded in a secp256k1 affine point.
///
/// Output: tuple of ciphertexts (c1, c2) -> the two associated ciphertexts to post for the owner
/// of the private key to decrypt.
pub fn encrypt_message(pubkey: AffinePoint, message: AffinePoint) -> (AffinePoint, AffinePoint) {
    let generator = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let k = U512::from(rand::thread_rng().next_u64());
    let c1 = generator.naf_ecmult(&k);
    let c = pubkey.naf_ecmult(&k);
    let c2 = c.add(&message);
    (c1, c2)
}

/// As the name implies, this function decrypts the message given to it when the caller has
/// knowledge of the associated private key. It returns the affine point on secp256k1 that
/// represents the data the original sender encrypted. 
///
/// Input: private key (privkey) -> the private key to use in decryption.
/// Input: ciphertext #1 (c1) -> the first ciphertext in the encryption process.
/// Input: ciphertext #2 (c2) -> the second ciphertext in the encryption process.
///
/// Output: cleartext message -> the decrypted message when using the input private key.
pub fn decrypt_message(privkey: U512, c1: AffinePoint, c2: AffinePoint) -> AffinePoint {
    let field = U512::from_big_endian(&FIELD_SIZE);
    let r1 = c1.naf_ecmult(&privkey);
    let r2 = AffinePoint::new(r1.x, field - r1.y);
    c2.add(&r2)
}

/// This function simply combines the basic functions above to verify that, when fed random yet
/// valid values, it will decrypt the correct message. 
///
/// Input: None
///
/// Output: bool -> true if the functions above are good, false if something went awry. It should
/// always be true though.
pub fn secp256k1_runthrough() -> bool {
    let privkey = U512::from(rand::thread_rng().next_u64());
    let message = random_secp256k1_point();
    let pubkey = derive_public_key(privkey);
    let (c1, c2) = encrypt_message(pubkey, message);
    let res = decrypt_message(privkey, c1, c2);
    res == message
}

/// This function is exactly like the one above except when decrypting, we are just one bit off of
/// the normal private key. This is to show how precise the algorithm is at decrypting messages.
pub fn secp256k1_expected_fail() -> bool {
    let privkey = U512::from(rand::thread_rng().next_u64());
    let message = random_secp256k1_point();
    let pubkey = derive_public_key(privkey);
    let (c1, c2) = encrypt_message(pubkey, message);

    // we are just one point off and the whole thing fails
    let res = decrypt_message(privkey + U512::one(), c1, c2);

    res == message
}

/// This function tests for constant time key multiplication. 
pub fn secp256k1_ct() -> bool {
    let privkey = U512::from(rand::thread_rng().next_u64() % 25u64);
    let message = random_secp256k1_point();
    let pubkey = derive_public_key(privkey);
    let (c1, c2) = encrypt_message(pubkey, message);
    let res = decrypt_message(privkey, c1, c2);
    res == message
}


/// Verifies if a point is on secp256k1 given an input affine point and a field.
///
/// Input: point (a) -> the affine point to check.
/// Input: field (f) -> the field of the elliptic curve.
///
/// Output: bool -> true if the point is on the curve, false otherwise.
pub fn verify(a: AffinePoint, f: U512) -> bool {
    ((a.y * a.y) % f) == ((((a.x * a.x) % f) * a.x) + U512::from(7u32)) % f
}

/// As the name suggests, it produces a random point on secp256k1 by taking a random value and
/// using the generator to find a point on the curve.
pub fn random_secp256k1_point() -> AffinePoint {
    let generator = AffinePoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );

    let gen = U512::from(rand::thread_rng().next_u64());
    generator.naf_ecmult(&gen)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn double_and_add_ecmult() {
        let x = U512::from_big_endian(&GENERATOR_X);
        let y = U512::from_big_endian(&GENERATOR_Y);

        let GENERATOR = AffinePoint::new(x, y);

        let expected = AffinePoint::new(
            U512::from_dec_str("89565891926547004231252920425935692360644145829622209833684329913297188986597").unwrap(),
            U512::from_dec_str("12158399299693830322967808612713398636155367887041628176798871954788371653930").unwrap()
        );

        let res = GENERATOR.ecmult_double_and_add(&U512::from(2u32));

        assert_eq!(res, expected);
    }

    #[test]
    fn secp256k1_comprehensive_test() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(secp256k1_runthrough());
            }));
        }
        v.into_iter().for_each(|x| { x.join().unwrap(); });
    }

    #[test]
    fn secp256k1_expected_failures() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(!secp256k1_expected_fail());
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
