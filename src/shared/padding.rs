use std::iter::repeat;

#[must_use]
pub fn pad_pkcs7(unpadded: &[u8], block_length: usize) -> Vec<u8> {
    let padding_length = block_length - (unpadded.len() % block_length);
    let padding_byte = u8::try_from(padding_length).unwrap();
    unpadded
        .iter()
        .copied()
        .chain(repeat(padding_byte).take(padding_length))
        .collect()
}

#[must_use]
pub fn unpad_pkcs7(padded: &[u8], block_length: usize) -> Option<Vec<u8>> {
    if padded.len() % block_length != 0 {
        return None;
    }

    padded.last().and_then(|&padding_byte| {
        let padding_length = usize::from(padding_byte);
        if padding_length == 0
            || padded
                .iter()
                .rev()
                .take(padding_length)
                .filter(|&&b| b == padding_byte)
                .count()
                < padding_length
        {
            None
        } else {
            Some(
                padded
                    .iter()
                    .copied()
                    .take(padded.len() - padding_length)
                    .collect(),
            )
        }
    })
}
