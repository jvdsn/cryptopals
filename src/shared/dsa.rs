use crate::shared::sha1::SHA1;
use crate::shared::{mod_inv, mod_sub};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};

pub fn generate_keypair(p: &BigUint, q: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let x = rand::thread_rng().gen_biguint_range(&BigUint::one(), q);
    let y = g.modpow(&x, p);
    (x, y)
}

pub fn sign(p: &BigUint, q: &BigUint, g: &BigUint, x: &BigUint, msg: &[u8]) -> (BigUint, BigUint) {
    assert!(q.bits() >= 160);
    let mut hash = [0; 20];
    SHA1::default().hash(msg, &mut hash);
    let h = &BigUint::from_bytes_be(&hash);
    loop {
        let k = &rand::thread_rng().gen_biguint_range(&BigUint::one(), q);
        let r = g.modpow(k, p).mod_floor(q);
        if !r.is_zero() {
            let s = (mod_inv(k, q).unwrap() * (h + x * &r)).mod_floor(q);
            if !s.is_zero() {
                return (r, s);
            }
        }
    }
}

pub fn verify(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
    y: &BigUint,
    msg: &[u8],
    r: &BigUint,
    s: &BigUint,
) -> bool {
    if r.is_zero() || r >= q || s.is_zero() || s >= q {
        return false;
    }

    assert!(q.bits() >= 160);
    let mut hash = [0; 20];
    SHA1::default().hash(msg, &mut hash);
    let h = &BigUint::from_bytes_be(&hash);
    let w = &mod_inv(s, q).unwrap();
    let u1 = &(h * w).mod_floor(q);
    let u2 = &(r * w).mod_floor(q);
    let v = &(g.modpow(u1, p) * y.modpow(u2, p)).mod_floor(q);
    v == r
}

pub fn find_x(q: &BigUint, h: &BigUint, k: &BigUint, r: &BigUint, s: &BigUint) -> BigUint {
    (mod_inv(r, q).unwrap() * mod_sub(&(s * k), h, q)).mod_floor(q)
}
