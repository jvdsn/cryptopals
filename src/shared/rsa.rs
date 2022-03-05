use crate::shared::mod_inv;
use num_bigint::{BigUint, ToBigInt};
use std::ops::Sub;
use std::str::FromStr;

#[must_use]
pub fn generate_keypair(bit_size: u64) -> ((BigUint, BigUint), (BigUint, BigUint)) {
    assert_eq!(bit_size, 1024);
    // Apparently there's no real pure Rust libraries to generate random primes??...
    let p = &BigUint::from_str("9902478688314345424239631829098064031372511021415073888934444987805904619070767824954564980642642554558422713147827332946886953946202126417051242267443733").unwrap();
    let q = &BigUint::from_str("9023289800571256384296979170278503137808766752150078076803904588875045578444674044397684797154640374473290798963775917093544857834628721547751219278749279").unwrap();
    let n = p * q;
    let phi = p.sub(1u8) * q.sub(1u8);
    let e = BigUint::from(3u8);
    let d = mod_inv(&e.to_bigint().unwrap(), &phi).unwrap();
    ((n.clone(), e), (n, d))
}

#[must_use]
pub fn encrypt(m: &BigUint, public_key: &(BigUint, BigUint)) -> BigUint {
    let (n, e) = public_key;
    m.modpow(e, n)
}

#[must_use]
pub fn decrypt(c: &BigUint, private_key: &(BigUint, BigUint)) -> BigUint {
    let (n, d) = private_key;
    c.modpow(d, n)
}
