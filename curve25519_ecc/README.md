# Curve25519

Curve25519 is the foundation for most modern ECC implementations. It is birationally equivalent to the twisted edwards curve used in the ed25519 signature scheme. This implementation simply outlines an encryption mechanism for curve25519. Messages must be mapped to a specific point on the curve, so the actual use case is somewhat questionable. Like the other implementations in this library, this is an experimental build and therefore lacks the standard structure that most curve25519 implementations have. Nevertheless, I plan on updating this to match the composability of a standard ed25519 library.

### The Curve

Curve 25519 is a [Montgomery Curve](https://en.wikipedia.org/wiki/Montgomery_curve), different from the normal Weierstrass variants, as its curve equation follows a different fundamental formula, that being 

`B^2y = x^3 + Ax^2 + x`

Curve25519's equation is y^2 = x^3 + 486662x^2 + x, aka with B = 1 and A = 486662. Point addition operates as normal.

