use rand::Rng;

#[must_use]
pub fn pad_pkcs7(unpadded: &[u8], block_length: usize) -> Vec<u8> {
    let padding_length = block_length - (unpadded.len() % block_length);
    let padding_byte = u8::try_from(padding_length).unwrap();
    let mut padded = Vec::with_capacity(unpadded.len() + padding_length);
    padded.extend_from_slice(unpadded);
    padded.extend_from_slice(&vec![padding_byte; padding_length]);
    padded
}

#[must_use]
pub fn unpad_pkcs7(padded: &[u8], block_length: usize) -> Option<Vec<u8>> {
    if padded.len() % block_length != 0 {
        return None;
    }

    let padding_byte = padded[padded.len() - 1];
    let padding_length = usize::from(padding_byte);
    if padding_length == 0 || padding_length > block_length || padded.len() < padding_length {
        return None;
    }

    let unpadded_len = padded.len() - padding_length;
    if padded.iter().skip(unpadded_len).any(|&p| p != padding_byte) {
        return None;
    }
    Some(padded[0..unpadded_len].to_vec())
}

#[must_use]
pub fn pad_pkcs1_5(data: &[u8], block_type: u8, k: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut padded = Vec::with_capacity(k);
    padded.push(0x00);
    padded.push(block_type);
    let ps_len = k - data.len() - 3;
    match block_type {
        0x01 => padded.extend_from_slice(&vec![0xFF; ps_len]),
        0x02 => (0..ps_len).for_each(|_| padded.push(rng.gen_range(0x01..=0xFF))),
        // We don't support block type 0x00.
        _ => panic!("{}", format!("Unknown block type {block_type}")),
    }
    padded.push(0x00);
    padded.extend_from_slice(data);
    padded
}

#[must_use]
pub fn unpad_pkcs1_5(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 3 || padded[0] != 0x00 || (padded[1] != 0x01 && padded[1] != 0x02) {
        return None;
    }

    let mut i = 2;
    while padded[i] != 0 {
        // A good implementation should check that each byte is 0xFF...
        // if (padded[1] == 0x01 && padded[i] != 0xFF) || (padded.len() == i + 1) {
        if padded.len() == i + 1 {
            return None;
        }
        i += 1;
    }

    i += 1;
    Some(padded[i..].to_vec())
}
