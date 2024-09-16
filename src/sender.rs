use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ring::aead::*;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use std::io::{BufRead, BufReader, Error, Read};

pub struct Sender {
    n: u32,
    b: RistrettoBasepointTable,
    rng: SystemRandom,
    y: Scalar
}

impl Sender {

    // construct a Sender
    pub fn new(n: u32, b: RistrettoBasepointTable) -> Sender {
        let rng = SystemRandom::new();
        Sender { n: n, b: b, rng: rng, y: Scalar::ONE }
    }

    // select private parameter y and return S = y * B
    pub fn setup(&mut self) -> RistrettoPoint {
        let mut random_value = [0; 32];
        self.rng.fill(&mut random_value).unwrap();
        let y = Scalar::from_bytes_mod_order(random_value); // sample random value
        self.y = y;
        &y * &self.b
    }

    // derive and return the n encryption keys
    pub fn derive_keys(&mut self, s: RistrettoPoint, r: RistrettoPoint) -> Vec<ring::digest::Digest> {
        let t = &self.y * s;
        let mut k = Vec::new();
        for idx in 0u32..self.n {
            let j = Scalar::from(idx);
            let args = &self.y * r - &j * t;
            let sol = digest::digest(&digest::SHA256, args.compress().as_bytes());
            k.push(sol);
        }
        k
    }

    pub fn encrypt(&self, k_s: Vec<ring::digest::Digest>, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut in_out = Vec::new();
        for p in 0..k_s.len() { // encrypt each message with different key
            let k = k_s[p].as_ref();
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap());
            let nonce_bytes = [0; 12]; // todo: generate random
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let in_out_t = messages[p].clone();
            in_out.push(in_out_t);
            let _len = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out[p]).unwrap();
        }
        in_out
    }

    // read each line of input file and returns a vector of Strings
    pub fn read_message<R: Read>(io: R) -> Result<Vec<Vec<u8>>, Error> {
        let br = BufReader::new(io);
        let lines = br.lines()
            .map(|line| Vec::from(line.unwrap()))
            .collect::<Vec<_>>();
        Ok(lines)
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

    #[test]
    fn receiver_can_choose() {
        let mut sender = Sender::new(2, RISTRETTO_BASEPOINT_TABLE.clone());
        sender.setup();
    }
}
