use crate::shared::mod_inv;
use crate::shared::padding::{pad_pkcs1_5, unpad_pkcs1_5};
use crate::shared::sha1::SHA1;
use num_bigint::BigUint;
use std::ops::Sub;

pub const SHA1_ASN1_ID: &[u8; 15] = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";

#[must_use]
pub fn generate_keypair(p: &BigUint, q: &BigUint) -> ((BigUint, BigUint), (BigUint, BigUint)) {
    let n = p * q;
    let phi = p.sub(1u8) * q.sub(1u8);
    let e = BigUint::from(3u8);
    let d = mod_inv(&e, &phi).unwrap();
    ((n.clone(), e), (n, d))
}

#[must_use]
pub fn encrypt(public_key: &(BigUint, BigUint), m: &BigUint) -> BigUint {
    let (n, e) = public_key;
    m.modpow(e, n)
}

#[must_use]
pub fn decrypt(private_key: &(BigUint, BigUint), c: &BigUint) -> BigUint {
    let (n, d) = private_key;
    c.modpow(d, n)
}

#[must_use]
pub fn encrypt_padded(public_key: &(BigUint, BigUint), msg: &[u8]) -> Vec<u8> {
    let (n, _) = public_key;
    let k = usize::try_from((n.bits() + 7) / 8).unwrap();
    assert!(msg.len() <= k - 3 - 8);

    let m = BigUint::from_bytes_be(&pad_pkcs1_5(msg, 0x02, k));
    let c = encrypt(public_key, &m);
    c.to_bytes_be()
}

#[must_use]
pub fn decrypt_padded(private_key: &(BigUint, BigUint), ct: &[u8]) -> Option<Vec<u8>> {
    let (n, _) = private_key;
    let k = usize::try_from((n.bits() + 7) / 8).unwrap();
    assert!(ct.len() <= k);

    let c = BigUint::from_bytes_be(ct);
    let m = decrypt(private_key, &c);
    let mut msg = m.to_bytes_be();
    if msg.len() != k - 1 {
        return None;
    }

    msg.insert(0, 0x00);
    unpad_pkcs1_5(&msg, 0x02, true)
}

#[must_use]
pub fn sign(private_key: &(BigUint, BigUint), msg: &[u8]) -> Vec<u8> {
    let (n, _) = private_key;
    let k = usize::try_from((n.bits() + 7) / 8).unwrap();

    let mut hash = [0; 20];
    SHA1::default().hash(msg, &mut hash);
    let mut data = [0; 35];
    data[0..15].copy_from_slice(SHA1_ASN1_ID);
    data[15..35].copy_from_slice(&hash);
    let c = BigUint::from_bytes_be(&pad_pkcs1_5(&data, 0x01, k));
    let s = decrypt(private_key, &c);
    s.to_bytes_be()
}

#[must_use]
pub fn verify(public_key: &(BigUint, BigUint), msg: &[u8], sig: &[u8]) -> bool {
    let (n, _) = public_key;
    let k = usize::try_from((n.bits() + 7) / 8).unwrap();

    let mut hash = [0; 20];
    SHA1::default().hash(msg, &mut hash);
    let mut data = [0; 35];
    data[0..15].copy_from_slice(SHA1_ASN1_ID);
    data[15..35].copy_from_slice(&hash);
    let s = BigUint::from_bytes_be(sig);
    let c = encrypt(public_key, &s);
    let mut bytes = c.to_bytes_be();
    if bytes.len() != k - 1 {
        return false;
    }

    bytes.insert(0, 0x00);
    // We use a vulnerable padding implementation here!
    unpad_pkcs1_5(&bytes, 0x01, false)
        .filter(|d| d == &data)
        .is_some()
}
