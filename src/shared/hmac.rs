use crate::shared::xor::xor;

pub fn hmac<F>(key: &[u8], msg: &[u8], mac: &mut [u8], hash: F)
where
    F: Fn(&[u8], &mut [u8]),
{
    let mut block_sized_key = [0; 64];
    if key.len() <= 64 {
        block_sized_key[0..key.len()].copy_from_slice(key);
    } else {
        hash(key, &mut block_sized_key[0..20]);
    }

    let mut o_msg = [0x5c; 84];
    xor(&mut o_msg[0..64], &block_sized_key);
    let mut i_msg = vec![0x36; 64];
    xor(&mut i_msg[0..64], &block_sized_key);
    i_msg.extend_from_slice(msg);
    hash(&i_msg, &mut o_msg[64..84]);
    hash(&o_msg, mac);
}
