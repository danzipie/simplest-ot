use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{RistrettoBasepointTable, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ring::aead::*;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};

/**
 * Oblivious Transfer sender and receiver
 * based on Chou-Orlandi OT
 * https://eprint.iacr.org/eprint-bin/getfile.pl?entry=2015/267&version=20180529:135402&file=267.pdf
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

    fn new(n: u32, b: RistrettoBasepointTable) -> Sender {
        println!("Initialize y");
        let rng = SystemRandom::new();
        Sender { n: n, b: b, rng: rng, y: Scalar::one() }
    }

    // output S
    fn setup(&mut self) -> RistrettoPoint {
        let mut random_value = [0; 32];
        self.rng.fill(&mut random_value).unwrap();
        let y = Scalar::from_bits(random_value); // sample random value
        self.y = y;
        &y * &self.b
    }

    fn derive_keys(&mut self, s: RistrettoPoint, r: RistrettoPoint) -> Vec<ring::digest::Digest> {
        // @TODO check if r in field
        let t = &self.y*s;
        //let k: [<u8>, n];
        let mut k = Vec::new();
        for idx in 0u32..self.n {
            let j = Scalar::from(idx);
            let args = &self.y * r - &j * t;
            let sol = digest::digest(&digest::SHA256, args.compress().as_bytes());
            k.push(sol);
        }
        k
    }

    fn encrypt(&self) -> Vec<u8> {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap());
        let mut nonce_bytes = [0; 12]; // todo: generate random
        let mut nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let content = b"content to encrypt".to_vec();
        let mut in_out = content.clone();
        let len = key.seal_in_place(nonce, Aad::empty(), &mut in_out).unwrap();
        println!("{:?}", content);
        in_out
    }
}

impl Receiver {

    fn new(n: u32, b: RistrettoBasepointTable) -> Receiver {
        println!("Initialize receiver");
        let rng = SystemRandom::new();
        let k = digest::digest(&digest::SHA256, b"");
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0u8; 32]).unwrap());
        Receiver { n: n, b: b, rng: rng, k: k, key: key}
    }

    // returns the encryption key 'k'
    fn choose(&mut self, c: Scalar, s: RistrettoPoint) -> RistrettoPoint {
        let mut random_value = [0; 32];
        let x = Scalar::from_bits(random_value); // sample random value
        let r = c * s + &x * &self.b;
        let args = &x * s;
        let args = args.compress();
        self.k = digest::digest(&digest::SHA256, args.as_bytes()); // key derivation
        r
    }

    fn decrypt(&self, mut in_out: Vec<u8>) {
        println!("{:?}", in_out);
        let mut nonce_bytes = [0; 12]; // todo: generate random
        let mut nonce_r = Nonce::assume_unique_for_key(nonce_bytes);
        let res = self.key.open_in_place(nonce_r, Aad::empty(), &mut in_out);
        println!("{:?}", res);
    }

}

fn main() {

    println!("Initiating protocol");

    const n: u32 = 2; // number of alternative messages
    const l: u32 = 128;

    let mut sender = Sender::new(n, RISTRETTO_BASEPOINT_TABLE);
    let s = sender.setup();
    println!("{:?}", s);

    // S --- s ---> R
    let c = Scalar::one(); // choose which info to be received ( @TODO: input of the program)
    let mut receiver = Receiver::new(n, RISTRETTO_BASEPOINT_TABLE);
    let r = receiver.choose(c, s);

    // R --- r ---> S
    let k_s = sender.derive_keys(s, r);

    // transfer phase
    let mut encrypted_message = sender.encrypt();
    receiver.decrypt(encrypted_message);
}
