use crate::shared::mod_inv;
use num_bigint::{BigUint, ToBigInt};
use std::ops::Sub;

#[must_use]
pub fn generate_keypair(p: &BigUint, q: &BigUint) -> ((BigUint, BigUint), (BigUint, BigUint)) {
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
