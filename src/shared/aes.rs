use aes::cipher::generic_array::GenericArray;
use aes::{Aes128, BlockDecrypt, BlockEncrypt, NewBlockCipher};
use std::collections::HashSet;

pub fn ecb_encrypt(pt: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert_eq!(pt.len() % 16, 0);
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    pt.chunks(16)
        .flat_map(|pt_block| {
            let mut ct_block = GenericArray::clone_from_slice(pt_block);
            aes128.encrypt_block(&mut ct_block);
            ct_block.into_iter()
        })
        .collect()
}

pub fn ecb_decrypt(ct: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert_eq!(ct.len() % 16, 0);
    let aes128 = Aes128::new(GenericArray::from_slice(key));
    ct.chunks(16)
        .flat_map(|ct_block| {
            let mut pt_block = GenericArray::clone_from_slice(ct_block);
            aes128.decrypt_block(&mut pt_block);
            pt_block.into_iter()
        })
        .collect()
}

pub fn is_ecb(ct: &[u8]) -> bool {
    let blocks_set: HashSet<&[u8]> = ct.chunks_exact(16).collect();
    blocks_set.len() < ct.len() / 16
}
