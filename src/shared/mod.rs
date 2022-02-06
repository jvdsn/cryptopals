use rand::RngCore;

pub mod aes;
pub mod conversion;
pub mod key_value;
pub mod mersenne_twister;
pub mod padding;
pub mod xor;

#[must_use]
pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0; count];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
