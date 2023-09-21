use bigint::uint::U512;
use rand::RngCore;

/// This is an example of an interactive zero-knowledge proof. There is the prover who has the goal
/// to sufficiently convince the verifier that they have knowledge of something without revealing
/// any information that would help the verifier prove to other people that he himself has
/// knowledge of the underlying thing himself. In this basic example, we explore the zero-knowledge proof
/// of a prover who is trying to convince the prover that they have a value y which is a square
/// moduluo N. You can also think of this as the prover keeping a secret value "x" which, when
/// squared, yields y. All the prover wishes to convey to the verifier is that "x" exists and she
/// has knowledge of it. 
///
/// Input: secret key 1 (p) -> large prime which serves as first secret key.
/// Input: secret key 2 (q) -> large prime which serves as second secret key.
/// Input: secret value (x) -> the value of which the prover wishes to prove existence.
///
/// Output: bool -> This proof is executed with 100 rounds. If any of the rounds fail, then the
/// proof is invalid, and the function returns false. If the 100 rounds are all verified, then the
/// proof is valid and "convince" returns true.
#[allow(non_snake_case)]
pub fn convince(p: U512, q: U512, x: U512) -> bool {
    let N = p * q;
    let y = (x * x) % N;
    for _ in 0..100 {
        let r = U512::from(rand::thread_rng().next_u64());

        // Important! This is the value which is regarded as the "commitment" for the
        // zero-knowledge proof. UNDER NORMAL CIRCUMSTANCES, THIS IS IMMEDIATELY GIVEN TO THE
        // VERIFIER BEFORE RECEIVING A CHALLENGE. Since this is a basic implementation, I just
        // hardcoded it to make sure that you can't change "nr."
        let nr = (r * r) % N;
        //

        let rand = simulate_challenge();
        let z;
        if rand == U512::zero() { z = r % N; }
        else { z = (r * x) % N; }
        if !verify(z, N, nr, y, rand) { return false; }
    }
    true
}

/// This function is for challenging the prover to provide sufficient values when prompted. It will
/// either return a 1 or a 0 wrapped in a U512 depending on thread rng.
///
/// Input: None
///
/// Output: 1 or 0 -> determined by thread_rng
fn simulate_challenge() -> U512 {
    U512::from(rand::thread_rng().next_u32() % 2)
}

/// This is the verification function, which essentially "remembers" the challenge that the
/// verifier sent to the prover, and attempts to prove that the value returned by the prover
/// matches accordingly with the expected value type. If the value the challenger (aka verifier)
/// sent to the prover was 0, then the verifier expects a number z^2 to be equal to the commitment
/// the verifier originally sent (see the text above). Otherwise, the verifier expects the value to
/// be some integer y provided by the prover multiplied by the commitment. 
///
/// Input: processed value (z) -> The value processed by the prover based on the challenge
/// that was sent by the verifier.
/// Input: public modulus (N) -> The public modulus for computation. Equal to p * q.
/// Input: commitment (s) -> The commitment previously sent to the verifier before the challenge.
/// Input: public "shadow" value (y) -> Value provided by the prover to mask the true value for x.
/// Input: previous challenge (challenge) -> The value that the verifier formerly sent to the
/// prover.
#[allow(non_snake_case)]
pub fn verify(z: U512, N: U512, s: U512, y: U512, challenge: U512) -> bool {
    let ch = (z * z) % N;
    if challenge == U512::zero() { return ch == s; }
    ch == ((y * s) % N)
}

#[cfg(test)]
mod tests {
/* Primes to use
4598933
4598939
4598941
4598963
4598977
4598983
4598999
4599019
4599059
4599071

345679
345689
345701
345707
345727
345731
*/
    use super::*;
    #[test]
    fn zero_knowledge_completeness() {
        assert!(convince(U512::from(4598933u64), U512::from(4598939u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(4598941u64), U512::from(4598963u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(4598977u64), U512::from(4598983u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(4598999u64), U512::from(4599019u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(4599059u64), U512::from(4599071u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(345679u64), U512::from(345689u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(345701u64), U512::from(345707u64), U512::from(rand::thread_rng().next_u64())));
        assert!(convince(U512::from(345727u64), U512::from(345731u64), U512::from(rand::thread_rng().next_u64())));
    }
}
