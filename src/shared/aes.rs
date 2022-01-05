use crate::shared::padding::pad_pkcs7;
use crate::shared::random_bytes;
use crate::shared::xor::xor;
use aes::cipher::generic_array::GenericArray;
use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use rand::Rng;
use std::collections::HashSet;

pub fn random_key() -> Vec<u8> {
    random_bytes(16)
}

pub fn ecb_encrypt(pt: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(pt.len() % 16, 0);
    assert_eq!(key.len(), 16);
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut ct = Vec::with_capacity(pt.len());
    let mut i = 0;
    while i < pt.len() {
        let pt_block = &pt[i..i + 16];
        let mut ct_block = GenericArray::clone_from_slice(pt_block);
        aes128.encrypt_block(&mut ct_block);
        ct.extend_from_slice(ct_block.as_slice());
        i += 16;
    }
    ct
}

pub fn ecb_decrypt(ct: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(ct.len() % 16, 0);
    assert_eq!(key.len(), 16);
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut pt = Vec::with_capacity(ct.len());
    let mut i = 0;
    while i < ct.len() {
        let ct_block = &ct[i..i + 16];
        let mut pt_block = GenericArray::clone_from_slice(ct_block);
        aes128.decrypt_block(&mut pt_block);
        pt.extend_from_slice(pt_block.as_slice());
        i += 16;
    }
    pt
}

pub fn is_ecb(ct: &[u8]) -> bool {
    let blocks_set: HashSet<&[u8]> = ct.chunks_exact(16).collect();
    blocks_set.len() < ct.len() / 16
}

pub fn cbc_encrypt(pt: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(pt.len() % 16, 0);
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut ct = Vec::with_capacity(pt.len());
    let mut i = 0;
    while i < pt.len() {
        let pt_block = &pt[i..i + 16];
        let prev_ct_block = if i < 16 { iv } else { &ct[i - 16..i] };
        let ct_block = xor(pt_block, prev_ct_block);
        let mut ct_block = GenericArray::clone_from_slice(&ct_block);
        aes128.encrypt_block(&mut ct_block);
        ct.extend_from_slice(ct_block.as_slice());
        i += 16;
    }
    ct
}

pub fn cbc_decrypt(ct: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(ct.len() % 16, 0);
    assert_eq!(key.len(), 16);
    assert_eq!(iv.len(), 16);
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    let mut pt = Vec::with_capacity(ct.len());
    let mut i = 0;
    while i < ct.len() {
        let ct_block = &ct[i..i + 16];
        let mut pt_block = GenericArray::clone_from_slice(ct_block);
        aes128.decrypt_block(&mut pt_block);
        let prev_ct_block = if i < 16 { iv } else { &ct[i - 16..i] };
        let pt_block = xor(pt_block.as_slice(), prev_ct_block);
        pt.extend_from_slice(&pt_block);
        i += 16;
    }
    pt
}

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
    if rng.gen::<bool>() {
        (ecb_encrypt(&padded, &key), true)
    } else {
        let iv = random_bytes(16);
        (cbc_encrypt(&padded, &key, &iv), false)
    }
}

pub fn ecb_oracle(pt: &[u8], unknown: &[u8], key: &[u8]) -> Vec<u8> {
    let mut unpadded = Vec::with_capacity(pt.len() + unknown.len());
    unpadded.extend_from_slice(pt);
    unpadded.extend_from_slice(unknown);
    let padded = pad_pkcs7(&unpadded, 16);
    ecb_encrypt(&padded, key)
}

pub fn ecb_oracle_harder(random_prefix: &[u8], pt: &[u8], unknown: &[u8], key: &[u8]) -> Vec<u8> {
    let mut unpadded = Vec::with_capacity(random_prefix.len() + pt.len() + unknown.len());
    unpadded.extend_from_slice(random_prefix);
    unpadded.extend_from_slice(pt);
    unpadded.extend_from_slice(unknown);
    let padded = pad_pkcs7(&unpadded, 16);
    ecb_encrypt(&padded, key)
}
