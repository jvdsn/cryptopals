use crate::shared::xor::xor;

pub fn hmac<F, const L: usize>(key: &[u8], msg: &[u8], mac: &mut [u8; L], h: F)
where
    F: Fn(&[u8], &mut [u8; L]),
{
    let mut hash = [0; L];
    let mut block_sized_key = [0; 64];
    if key.len() <= 64 {
        block_sized_key[0..key.len()].copy_from_slice(key);
    } else {
        h(key, &mut hash);
        block_sized_key[0..L].copy_from_slice(&hash);
    }

    let mut i_msg = vec![0x36; 64];
    xor(&mut i_msg[0..64], &block_sized_key);
    i_msg.extend_from_slice(msg);
    h(&i_msg, &mut hash);

    // TODO: change this to an array with size [64 + L].
    let mut o_msg = vec![0x5c; 64];
    xor(&mut o_msg[0..64], &block_sized_key);
    o_msg.extend_from_slice(&hash);
    h(&o_msg, mac);
}
