use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ring::aead::*;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

pub struct Receiver {
    n: u32,
    b: RistrettoBasepointTable,
    rng: SystemRandom,
    k: ring::digest::Digest,
    key: LessSafeKey
}

impl Receiver {

    // construct a receiver
    pub fn new(n: u32, b: RistrettoBasepointTable) -> Receiver {
        let rng = SystemRandom::new();
        let k = digest::digest(&digest::SHA256, b"");
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap());
        Receiver { n: n, b: b, rng: rng, k: k, key: key}
    }

    // returns the encryption key 'k' based on secret parameter x and external param S
    pub fn choose(&mut self, c_index: u32, s: RistrettoPoint) -> RistrettoPoint {
        assert!(c_index < self.n);
        let c = Scalar::from(c_index);
        let mut random_value = [0; 32];
        self.rng.fill(&mut random_value).unwrap();
        let x = Scalar::from_bytes_mod_order(random_value); // sample random value
        let r = c * s + &x * &self.b;
        let args = &x * s;
        let args = args.compress();
        self.k = digest::digest(&digest::SHA256, args.as_bytes()); // key derivation
        self.key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &self.k.as_ref()).unwrap());
        r
    }

    // decrypts all messages. only one is expected to succeed
    pub fn decrypt(&self, mut in_out: Vec<Vec<u8>>) {
        let nonce_bytes: [u8; 12] = [0; 12];
        for p in 0..in_out.len() {
            println!("{:?}", nonce_bytes);

            let nonce_r = Nonce::assume_unique_for_key(nonce_bytes);
            match self.key.open_in_place(nonce_r, Aad::empty(), &mut in_out[p]) {
                Ok(v) => println!("Success {:?}", v),
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
        receiver.choose(1, s);
    }

    #[test]
    #[should_panic]
    fn index_too_high() {
        let mut receiver = Receiver::new(2, RISTRETTO_BASEPOINT_TABLE.clone());
        let mut rng = OsRng;
        let s = RistrettoPoint::random(&mut rng);
        receiver.choose(3, s);
    }
}
