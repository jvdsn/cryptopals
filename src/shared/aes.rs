use crate::shared::padding::{pad_pkcs7, unpad_pkcs7};
use crate::shared::random_bytes;
use crate::shared::xor::xor;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::Rng;
use std::collections::HashSet;

#[must_use]
pub fn random_key() -> Vec<u8> {
    random_bytes(16)
}

pub fn ecb_encrypt(key: &[u8], pt: &[u8], ct: &mut [u8]) {
    assert_eq!(key.len(), 16);
    assert_eq!(pt.len() % 16, 0);
    assert_eq!(ct.len(), pt.len());
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut i = 0;
    while i < pt.len() {
        let pt_block = &pt[i..i + 16];
        let mut ct_block = GenericArray::clone_from_slice(pt_block);
        aes128.encrypt_block(&mut ct_block);
        ct[i..i + 16].copy_from_slice(ct_block.as_slice());
        i += 16;
    }
}

pub fn ecb_decrypt(key: &[u8], ct: &[u8], pt: &mut [u8]) {
    assert_eq!(key.len(), 16);
    assert_eq!(ct.len() % 16, 0);
    assert_eq!(pt.len(), ct.len());
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut i = 0;
    while i < ct.len() {
        let ct_block = &ct[i..i + 16];
        let mut pt_block = GenericArray::clone_from_slice(ct_block);
        aes128.decrypt_block(&mut pt_block);
        pt[i..i + 16].copy_from_slice(pt_block.as_slice());
        i += 16;
    }
}

#[must_use]
pub fn is_ecb(ct: &[u8]) -> bool {
    let blocks_set: HashSet<&[u8]> = ct.chunks_exact(16).collect();
    blocks_set.len() < ct.len() / 16
}

pub fn cbc_encrypt(key: &[u8], iv: &[u8], pt: &[u8], ct: &mut [u8]) {
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert_eq!(pt.len() % 16, 0);
    assert_eq!(ct.len(), pt.len());
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut i = 0;
    while i < pt.len() {
        let pt_block = &pt[i..i + 16];
        let prev_ct_block = if i < 16 { iv } else { &ct[i - 16..i] };
        let ct_block = xor(pt_block, prev_ct_block);
        let mut ct_block = GenericArray::clone_from_slice(&ct_block);
        aes128.encrypt_block(&mut ct_block);
        ct[i..i + 16].copy_from_slice(ct_block.as_slice());
        i += 16;
    }
}

pub fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8], pt: &mut [u8]) {
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    assert_eq!(ct.len() % 16, 0);
    assert_eq!(pt.len(), ct.len());
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut i = 0;
    while i < ct.len() {
        let ct_block = &ct[i..i + 16];
        let mut pt_block = GenericArray::clone_from_slice(ct_block);
        aes128.decrypt_block(&mut pt_block);
        let prev_ct_block = if i < 16 { iv } else { &ct[i - 16..i] };
        let pt_block = xor(pt_block.as_slice(), prev_ct_block);
        pt[i..i + 16].copy_from_slice(pt_block.as_slice());
        i += 16;
    }
}

fn ctr_keystream(aes128: Aes128, nonce: u64) -> impl Iterator<Item = u8> {
    (0u64..).flat_map(move |count| {
        let mut keystream_block = GenericArray::default();
        let (left, right) = keystream_block.split_at_mut(8);
        left.copy_from_slice(&nonce.to_le_bytes());
        right.copy_from_slice(&count.to_le_bytes());
        aes128.encrypt_block(&mut keystream_block);
        keystream_block
    })
}

pub fn ctr_encrypt(key: &[u8], nonce: u64, pt: &[u8], ct: &mut [u8]) {
    assert_eq!(key.len(), 16);
    assert_eq!(ct.len(), pt.len());
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    ctr_keystream(aes128, nonce)
        .take(pt.len())
        .enumerate()
        .for_each(|(i, k)| ct[i] = pt[i] ^ k);
}

pub fn ctr_decrypt(key: &[u8], nonce: u64, ct: &[u8], pt: &mut [u8]) {
    ctr_encrypt(key, nonce, ct, pt)
}

#[must_use]
pub fn encrypt_ecb_or_cbc(pt: &[u8]) -> (Vec<u8>, bool) {
    let key = random_key();
    let mut rng = rand::thread_rng();
    let mut prefix = random_bytes(rng.gen_range(5..=10));
    let mut suffix = random_bytes(rng.gen_range(5..=10));
    let mut unpadded = Vec::with_capacity(prefix.len() + pt.len() + suffix.len());
    unpadded.append(&mut prefix);
    unpadded.extend_from_slice(pt);
    unpadded.append(&mut suffix);
    let padded = pad_pkcs7(&unpadded, 16);
    let mut ct = vec![0; padded.len()];
    if rng.gen::<bool>() {
        ecb_encrypt(&key, &padded, &mut ct);
        (ct, true)
    } else {
        let iv = random_bytes(16);
        cbc_encrypt(&key, &iv, &padded, &mut ct);
        (ct, false)
    }
}

#[must_use]
pub fn ecb_oracle(key: &[u8], pt: &[u8], unknown: &[u8]) -> Vec<u8> {
    let mut unpadded = Vec::with_capacity(pt.len() + unknown.len());
    unpadded.extend_from_slice(pt);
    unpadded.extend_from_slice(unknown);
    let padded = pad_pkcs7(&unpadded, 16);
    let mut ct = vec![0; padded.len()];
    ecb_encrypt(key, &padded, &mut ct);
    ct
}

#[must_use]
pub fn ecb_oracle_harder(key: &[u8], random_prefix: &[u8], pt: &[u8], unknown: &[u8]) -> Vec<u8> {
    let mut unpadded = Vec::with_capacity(random_prefix.len() + pt.len() + unknown.len());
    unpadded.extend_from_slice(random_prefix);
    unpadded.extend_from_slice(pt);
    unpadded.extend_from_slice(unknown);
    let padded = pad_pkcs7(&unpadded, 16);
    let mut ct = vec![0; padded.len()];
    ecb_encrypt(key, &padded, &mut ct);
    ct
}

#[must_use]
pub fn padding_oracle(key: &[u8], iv: &[u8], ct: &[u8]) -> bool {
    let mut pt = vec![0; ct.len()];
    cbc_decrypt(key, iv, ct, &mut pt);
    unpad_pkcs7(&pt, 16).is_some()
}
