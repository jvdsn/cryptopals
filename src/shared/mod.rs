use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Signed, Zero};

pub mod aes;
pub mod conversion;
pub mod dh;
pub mod hmac;
pub mod key_value;
pub mod md4;
pub mod mersenne_twister;
pub mod padding;
pub mod rsa;
pub mod sha1;
pub mod sha256;
pub mod xor;

#[must_use]
pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut r_prev, mut r) = (a.clone(), b.clone());
    let (mut s_prev, mut s) = (BigInt::one(), BigInt::zero());
    let (mut t_prev, mut t) = (BigInt::zero(), BigInt::one());
    while !r.is_zero() {
        let q = &r_prev / &r;
        let tmp = &r_prev - &q * &r;
        r_prev = r;
        r = tmp;
        let tmp = &s_prev - &q * &s;
        s_prev = s;
        s = tmp;
        let tmp = &t_prev - &q * &t;
        t_prev = t;
        t = tmp;
    }

    (r_prev, s_prev, t_prev)
}

#[must_use]
pub fn mod_inv(a: &BigInt, n: &BigUint) -> Option<BigUint> {
    let n_ = n.to_bigint().unwrap();
    let (r, _, mut t) = egcd(&n_, a);
    if r.is_one() {
        if t.is_negative() {
            t += n_;
        }
        Option::Some(t.to_biguint().unwrap())
    } else {
        Option::None
    }
}
