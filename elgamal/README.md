# Elgamal Cryptography

Although coming a few years after the discovery of RSA, the [Elgamal public-key private-key encryption method](https://en.wikipedia.org/wiki/ElGamal_encryption) is thought to be the first implementation of pairing-based public-key cryptography since Whitfield Diffie and Martin Hellman's groundbreaking [New Directions in Cryptography](https://www.cs.jhu.edu/~rubin/courses/sp03/papers/diffie.hellman.pdf) paper.

Appropriately, Elgamal encryption guarantees the same security of a Diffie-Hellman shared secret key exchange. Note that this guarantee is different from the DLP (Discrete log problem), and should be regarded as a less-secure yet still valid form of public key cryptography. 

# Code

The code in this library contains the [Eulcidian Algorithm](https://en.wikipedia.org/wiki/Euclidean_algorithm) for finding the greatest common divisor of two numbers, as well as a basic modular exponentiation function. I felt that creating an algorithm which found primitive roots for prime-order fields was unnecessary, as all cryptographic protocols just use existing, agreed-upon curves and respective generator points (in this one, I used ed-25519 because, Monero). This may be implemented in the future, though. 

It would have been possible to fork the U256 or U512 library from bigint but I didn't feel like it was necessary, especially since it's only Elgamal encryption and not points on an elliptic curve. I chose to use U512 for the sake of a more "cryptographically secure" implementation of Elgamal. Of course, this won't really matter in the long run, as if DHP is ever cracked, then the entropy between U256 and U512 would be trivial for a codebreaker. 

This implementation is obviously barebones. For example, we use thread rng over the battle-tested [ChaCha RNG Core](https://www.cryptography-primer.info/algorithms/chacha/). Nevertheless, this implementation will certainly work for tasks such as sending messages to your friends. Another potential weakness (besides by obvious inexperience with cryptographic implementations) is that the derivation of the public key is not in constant time, which could (maybe?) make the private key exposable through a side-channel attack.
