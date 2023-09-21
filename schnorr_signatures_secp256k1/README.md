# The Schnorr Signature Scheme

Schnorr signatures are one of the most common signature schemes today because of their quick computation and relatively small signatures. There are several different implemetations of using Schnorr Signature schemes with the ECDLP. On [Wikipedia's Definition](https://en.wikipedia.org/wiki/Schnorr_signature), they use the DLP instead of the elliptic curve analog. The algorithm I used for secp256k1 came from [this post](https://crypto.stackexchange.com/questions/50221/schnorr-digital-signature), but there are numerous other "correct" signature methods that can be found either on other's implementations of [secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/blob/master/src/schnorr.rs) or on other [forum posts](https://crypto.stackexchange.com/questions/34863/ec-schnorr-signature-multiple-standard/50202#50202).

The update from the double-and-add algorithm to the NAF algorithm made the tests ~1.5s faster... JK I needed to make them constant time so NAF does nothing without the sliding window. 