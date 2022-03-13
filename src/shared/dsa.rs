use crate::shared::{mod_inv, mod_sub};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;

#[must_use]
pub fn generate_keypair(p: &BigUint, q: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let x = rand::thread_rng().gen_biguint_range(&BigUint::one(), q);
    let y = g.modpow(&x, p);
    (x, y)
}

#[must_use]
pub fn sign(p: &BigUint, q: &BigUint, g: &BigUint, x: &BigUint, m: &BigUint) -> (BigUint, BigUint) {
    assert!(m < q);
    let k = &rand::thread_rng().gen_biguint_range(&BigUint::one(), q);
    // Normally we should check that r and s are not zero here, but then challenge 45 doesn't work...
    let r = g.modpow(k, p).mod_floor(q);
    let s = (mod_inv(k, q).unwrap() * (m + x * &r)).mod_floor(q);
    (r, s)
}

#[must_use]
pub fn verify(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
    m: &BigUint,
    r: &BigUint,
    s: &BigUint,
) -> bool {
    // Normally we should check that r and s are not zero here, but then challenge 45 doesn't work...
    assert!(m < q);
    let w = &mod_inv(s, q).unwrap();
    let u1 = &(m * w).mod_floor(q);
    let u2 = &(r * w).mod_floor(q);
    let v = &(g.modpow(u1, p) * y.modpow(u2, p)).mod_floor(q);
    v == r
}

#[must_use]
pub fn find_x(q: &BigUint, m: &BigUint, k: &BigUint, r: &BigUint, s: &BigUint) -> BigUint {
    assert!(m < q);
    (mod_inv(r, q).unwrap() * mod_sub(&(s * k), m, q)).mod_floor(q)
}
