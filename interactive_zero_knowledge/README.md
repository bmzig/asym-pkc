# Interactive Zero-Knowledge Proofs

A zero-knowledge proof is the ability for a prover to convince a verifier that a specific fact is true without giving the verifier any information that would let the verifier convince other people that the fact is true. An interactive zero-knowledge proof is much simpler than a non-interactive counterpart since we have the ability to freely challenge the prover until the verifier is sufficiently convinced. Abstractly speaking, a good zero-knowledge proof is one where the proof y has some property P which satisfies the following two conditions.

1. Completeness: If y does have property P, then the verifier should always accept the prover's response as being valid.

2. Soundness: If y does not have property P, then there should only be a very small possibility that the verifier accepts all of the prover's responses as being valid.

Interactive zero-knowledge is scratching the surface of zero-knowledge as a whole. Theoretically, a proof which is 1) non-interactive, and 2) does not require a trusted setup to be valid is a more practical and versatile proof. I fully plan on exploring the non-interactive zk proofs in other repositories, but for now, this is the only implementation for this current repository.

# This example

While I already elaborate how this example works in the comments of the `src/lib.rs` file, basically, you can think of it as a prover convincing a verifier that she knows some value 'y' which is a square modulus of a secret value 'x.' The verifier randomly challenges the prover, and if the prover can successfully pass 100 rounds of interaction, then the verifier is sufficiently convinced that the prover does indeed hold knowledge of the above statement.
