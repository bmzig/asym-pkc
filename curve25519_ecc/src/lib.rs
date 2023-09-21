use crate::ecmult::*;
use crate::constants::*;
use bigint::uint::U512;
use rand::*;

mod ecmult;
mod euclidian;
mod constants;

/// As the name implies, this generates a curve25519 private key, which is essentially a 256 bit
/// integer. It takes in the operating system's RNG data and creates a random number modulus
/// curve25519's order, which is ~2^253
///
/// Input: randomness (rng) -> the rng data from the operating system which implements CryptoRng
/// and RngCore.
/// 
/// Output: private key -> The 512 bit representation of the secret key.
pub fn generate_curve25519_privkey<R: CryptoRng + RngCore>(rng: &mut R) -> U512 {
    let q = U512::from_big_endian(&GROUP_ORDER);
    U512::from_big_endian(&random(rng)) % q
}

/// Generates the curve25519 public key from an existing private key. It simply calculates the
/// formula P = sG. Finding the private key from the public key is called the elliptic curve discrete
/// logarithm problem.
///
/// Input: secret key (s) -> the secret key to use in public key generation.
///
/// Output: MontgomeryPoint -> the point on curve25519 which represents the public key.
pub fn derive_curve25519_pubkey(s: U512) -> MontgomeryPoint {
    let g = MontgomeryPoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );
    g.naf_ecmult(&s)
}

/// Encrypts data to a user dependent on the public key used in the data encryption. Only the user
/// with the secret key s related to the public key used will be able to decode the encrypted
/// message.
///
/// Input: randomness (rng) -> random data supplied by the operating system.
/// Input: public key (pk) -> the public key to use in the encryption process.
/// Input: message (m) -> the message to send to the user. It must be mapped to a point on
/// curve25519
///
/// Output: ciphertext1 -> the first ciphertext to send to the recipient.
/// Output: ciphertext2 -> the second ciphertext to send to the recipient.
pub fn encrypt_curve25519<R: CryptoRng + RngCore>(rng: &mut R, pk: MontgomeryPoint, m: MontgomeryPoint) -> (MontgomeryPoint, MontgomeryPoint) {
    let q = U512::from_big_endian(&GROUP_ORDER);
    let g = MontgomeryPoint::new(
        U512::from_big_endian(&GENERATOR_X),
        U512::from_big_endian(&GENERATOR_Y)
    );
    let k = U512::from_big_endian(&random(rng)) % q;
    let c1 = g.naf_ecmult(&k);
    let c2 = pk.naf_ecmult(&k);
    let c3 = m.add(&c2);
    (c1, c3)
}

/// Decrypts the ciphertext data. User calling the function must have the associated private key
/// used in the encryption process.
///
/// Input: secret key (s) -> the secret key associated with the ciphertext encryption process.
/// Input: ciphertext #1 (c1) -> the first ciphertext outputted in the encryption process.
/// Input: ciphertext #2 (c2) -> the second ciphertext outputted in the encryption process.
///
/// Output: MontgomeryPoint -> the plaintext message which was mapped to the point on the elliptic
/// curve.
pub fn decrypt_curve25519(s: U512, c1: MontgomeryPoint, c2: MontgomeryPoint) -> MontgomeryPoint {
    let f = U512::from_big_endian(&FIELD);
    let x = c1.naf_ecmult(&s);
    let z = MontgomeryPoint::new(
        x.x,
        f - x.y
    );
    c2.add(&z)
}

/// Function which fills a U512 with random bytes.
pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Function to use for testing.
pub fn curve25519_runthrough() -> bool {
    let f = U512::from_big_endian(&FIELD);
    let privkey = generate_curve25519_privkey(&mut rand::thread_rng());
    let pubkey = derive_curve25519_pubkey(privkey);
    let message = derive_curve25519_pubkey((privkey * privkey) % f);
    let (c1, c2) = encrypt_curve25519(&mut rand::thread_rng(), pubkey, message);
    let res = decrypt_curve25519(privkey, c1, c2);
    res == message
}

/// Use for testing when secret key to decrypt is one off.
pub fn curve25519_runthrough_f() -> bool {
    let f = U512::from_big_endian(&FIELD);
    let privkey = generate_curve25519_privkey(&mut rand::thread_rng());
    let pubkey = derive_curve25519_pubkey(privkey);
    let message = derive_curve25519_pubkey((privkey * privkey) % f);
    let (c1, c2) = encrypt_curve25519(&mut rand::thread_rng(), pubkey, message);
    let res = decrypt_curve25519(privkey + U512::one(), c1, c2);
    res != message
}

/// Use for testing constant time calculations. Should finish the same time that the other
/// runthrough functions finish.
pub fn curve25519_runthrough_constant_time(i: usize) -> bool {
    let f = U512::from_big_endian(&FIELD);
    let _privkey = generate_curve25519_privkey(&mut rand::thread_rng());
    let privkey = U512::from(10 + i as u32);
    let pubkey = derive_curve25519_pubkey(privkey);
    let message = derive_curve25519_pubkey((privkey * privkey) % f);
    let (c1, c2) = encrypt_curve25519(&mut rand::thread_rng(), pubkey, message);
    let res = decrypt_curve25519(privkey, c1, c2);
    res == message
}


#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn curve25519_explicit() {
        let f = U512::from_big_endian(&FIELD);
        let privkey = generate_curve25519_privkey(&mut rand::thread_rng());
        let pubkey = derive_curve25519_pubkey(privkey);
        let message = derive_curve25519_pubkey((privkey * privkey) % f);
        let (c1, c2) = encrypt_curve25519(&mut rand::thread_rng(), pubkey, message);
        let res = decrypt_curve25519(privkey, c1, c2);
        assert_eq!(res, message);
    }

    #[test]
    fn curve25519_random() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(curve25519_runthrough());
            }));
        }
        for thread in v.into_iter() {
            thread.join().unwrap();
        }
    }

    #[test]
    fn curve25519_should_fail() {
        let mut v = Vec::new();
        for _ in 0..10 {
            v.push(std::thread::spawn(|| {
                assert!(curve25519_runthrough_f());
            }));
        }
        for thread in v.into_iter() {
            thread.join().unwrap();
        }
    }

    #[test]
    fn curve25519_constant_time() {
        let mut v = Vec::new();
        for i in 0..10 {
            v.push(std::thread::spawn(move || {
                assert!(curve25519_runthrough_constant_time(i.clone()));
            }));
        }
        for thread in v.into_iter() {
            thread.join().unwrap();
        }
    }
}
