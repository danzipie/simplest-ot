use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ring::aead::*;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::error::Unspecified;

struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);
        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}
pub struct Receiver {
    n: u32,
    b: RistrettoBasepointTable,
    rng: SystemRandom,
    k: ring::digest::Digest,
    keys: Vec<OpeningKey<CounterNonceSequence>>
}

impl Receiver {

    // construct a receiver
    pub fn new(n: u32, b: RistrettoBasepointTable) -> Receiver {
        let rng = SystemRandom::new();
        let k: digest::Digest = digest::digest(&digest::SHA256, b"");
        let empty_keys: Vec<OpeningKey<CounterNonceSequence>> = Vec::new();
        Receiver { n: n, b: b, rng: rng, k: k, keys: empty_keys}
    }

    // returns the encryption key 'k' based on secret parameter x and external param S
    pub fn choose(&mut self, c_index: u32, s: RistrettoPoint) -> Result<RistrettoPoint, Unspecified> {
        assert!(c_index < self.n);
        let c = Scalar::from(c_index);
        let mut random_value = [0; 32];
        self.rng.fill(&mut random_value).unwrap();
        let x = Scalar::from_bytes_mod_order(random_value); // sample random value
        let r = c * s + &x * &self.b;
        let args = &x * s;
        let args = args.compress();
        self.k = digest::digest(&digest::SHA256, args.as_bytes()); // key derivation
        for p in 0..self.n {
            let unbound_key = UnboundKey::new(&AES_256_GCM, &self.k.as_ref())?;
            let nonce_sequence = CounterNonceSequence(p);
            self.keys.push(OpeningKey::new(unbound_key, nonce_sequence));
        }
        Ok(r)
    }

    // decrypts all messages. only one is expected to succeed
    pub fn decrypt(&mut self, mut in_out: Vec<Vec<u8>>) {
        for p in 0..in_out.len() {
            match self.keys[p].open_in_place(Aad::empty(), &mut in_out[p]) {
                Ok(v) => {
                    println!("Success {:?}", v);
                },
                Err(_e) => println!("Impossible to decrypt")
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use rand::rngs::OsRng;

    #[test]
    fn receiver_can_choose() {
        let mut receiver = Receiver::new(2, RISTRETTO_BASEPOINT_TABLE.clone());
        let mut rng = OsRng;
        let s = RistrettoPoint::random(&mut rng);
        let _ = receiver.choose(1, s);
    }

    #[test]
    #[should_panic]
    fn index_too_high() {
        let mut receiver = Receiver::new(2, RISTRETTO_BASEPOINT_TABLE.clone());
        let mut rng = OsRng;
        let s = RistrettoPoint::random(&mut rng);
        let _ = receiver.choose(3, s);
    }
}
