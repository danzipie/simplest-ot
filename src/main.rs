use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ring::aead::*;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

/**
 * Oblivious Transfer sender and receiver based on Chou-Orlandi OT
 */

pub struct Sender {
    n: u32,
    b: RistrettoBasepointTable,
    rng: SystemRandom,
    y: Scalar
}

pub struct Receiver {
    n: u32,
    b: RistrettoBasepointTable,
    rng: SystemRandom,
    k: ring::digest::Digest,
    key: LessSafeKey
}

impl Sender {

    // construct a Sender
    fn new(n: u32, b: RistrettoBasepointTable) -> Sender {
        let rng = SystemRandom::new();
        Sender { n: n, b: b, rng: rng, y: Scalar::one() }
    }

    // select private parameter y and return S = y * B
    fn setup(&mut self) -> RistrettoPoint {
        let mut random_value = [0; 32];
        self.rng.fill(&mut random_value).unwrap();
        let y = Scalar::from_bits(random_value); // sample random value
        self.y = y;
        &y * &self.b
    }

    // derive and return the n encryption keys
    fn derive_keys(&mut self, s: RistrettoPoint, r: RistrettoPoint) -> Vec<ring::digest::Digest> {
        // @TODO check if r in field
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

    fn encrypt(&self, k_s: Vec<ring::digest::Digest>, messages: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut in_out = Vec::new();
        for p in 0..k_s.len() { // encrypt each message with different key
            let k = k_s[p].as_ref();
            let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &k).unwrap());
            let nonce_bytes = [0; 12]; // todo: generate random
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            print!("Nonce is: ");
            println!("{:?}", nonce_bytes);
            let in_out_t = messages[p].clone();
            in_out.push(in_out_t);
            print!("Encrypting: ");
            println!("{:?}", in_out[p]);
            let _len = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out[p]).unwrap();
            print!("Encrypted: ");
            println!("{:?}", in_out[p]);
        }
        in_out
    }
}

impl Receiver {

    fn new(n: u32, b: RistrettoBasepointTable) -> Receiver {
        let rng = SystemRandom::new();
        let k = digest::digest(&digest::SHA256, b"");
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap());
        Receiver { n: n, b: b, rng: rng, k: k, key: key}
    }

    // returns the encryption key 'k' based on secret parameter x and external param S
    fn choose(&mut self, c: Scalar, s: RistrettoPoint) -> RistrettoPoint {
        let random_value = [0; 32];
        let x = Scalar::from_bits(random_value); // sample random value
        let r = c * s + &x * &self.b;
        let args = &x * s;
        let args = args.compress();
        self.k = digest::digest(&digest::SHA256, args.as_bytes()); // key derivation
        self.key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &self.k.as_ref()).unwrap());
        r
    }

    // decrypts all messages. only one is expected to succeed
    fn decrypt(&self, mut in_out: Vec<Vec<u8>>) {
        for p in 0..in_out.len() {
            let nonce_bytes = [0; 12]; // todo: generate random
            let nonce_r = Nonce::assume_unique_for_key(nonce_bytes);
            match self.key.open_in_place(nonce_r, Aad::empty(), &mut in_out[p]) {
                Ok(v) => println!("{:?}", v),
                Err(e) => println!("Impossible to decrypt")
            }
        }
    }

}

fn main() {

    println!("Initiating protocol");

    const N: u32 = 2; // number of alternative messages
    const L: u32 = 128;

    let mut sender = Sender::new(N, RISTRETTO_BASEPOINT_TABLE);
    let s = sender.setup();

    // S --- s ---> R
    let c = Scalar::one(); // choose which info to be received ( @TODO: input of the program)
    let mut receiver = Receiver::new(N, RISTRETTO_BASEPOINT_TABLE);
    let r = receiver.choose(c, s);

    // R --- r ---> S
    let k_s = sender.derive_keys(s, r);

    // transfer phase
    let messages = vec![b"one".to_vec(), b"two".to_vec()];
    let encrypted_messages = sender.encrypt(k_s, messages);
    receiver.decrypt(encrypted_messages);
}
