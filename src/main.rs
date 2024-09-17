use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use std::fs::File;
use std::io::Error;
use std::convert::TryInto;
use rand::Rng;

mod receiver;
mod sender;

/**
 * Oblivious Transfer sender and receiver based on Chou-Orlandi OT
 */
fn main() -> Result<(), Error> {

    println!("Initiating protocol");

    let messages = sender::Sender::read_message(File::open("./res/example_input.txt")?).unwrap();
    let n: u32 = messages.len().try_into().unwrap();
    println!("n: {:?}", n);

    // construct sender and receiver
    let mut sender = sender::Sender::new(n, RISTRETTO_BASEPOINT_TABLE.clone());
    let mut receiver = receiver::Receiver::new(n, RISTRETTO_BASEPOINT_TABLE.clone());

    // S --- s ---> R
    let s = sender.setup();

    println!("Receiver choosing a random index");
    let mut rng = rand::thread_rng();
    let c = rng.gen_range(0..=n-1);

    let r = receiver.choose(c, s);

    // R --- r ---> S
    let k_s = sender.derive_keys(s, r.unwrap());

    // transfer phase
    let encrypted_messages = sender.encrypt(k_s, messages);
    println!("Receiver decypting");
    receiver.decrypt(encrypted_messages.unwrap());

    Ok(())
}
