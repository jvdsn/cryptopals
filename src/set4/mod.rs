#[cfg(test)]
mod tests {
    use crate::shared::aes::{ctr_decrypt, ctr_edit, ctr_encrypt, ecb_decrypt, random_key};
    use crate::shared::conversion::base64_to_bytes;
    use std::fs::read_to_string;

    #[test]
    fn test_challenge_25() {
        let key = b"YELLOW SUBMARINE";
        let ct = base64_to_bytes(
            &read_to_string("src/set1/challenge7.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap();
        let mut pt = vec![0; ct.len()];
        ecb_decrypt(key, &ct, &mut pt);

        let key = random_key();
        let nonce = 0;
        let mut ct = vec![0; pt.len()];
        ctr_encrypt(&key, nonce, &pt, &mut ct);
        let mut pt = vec![0; ct.len()];
        ctr_edit(&key, nonce, &mut pt, 0, &ct);
        assert!(String::from_utf8(pt)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell \n"));
    }

    #[test]
    fn test_challenge_26() {
        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        let key = random_key();
        let nonce = 0;
        let encrypt = |pt: &[u8]| {
            if pt.contains(&b';') || pt.contains(&b'=') {
                return None;
            }

            let mut unpadded = Vec::with_capacity(prefix.len() + pt.len() + suffix.len());
            unpadded.extend_from_slice(prefix);
            unpadded.extend_from_slice(pt);
            unpadded.extend_from_slice(suffix);
            let mut ct = vec![0; unpadded.len()];
            ctr_encrypt(&key, nonce, &unpadded, &mut ct);
            Some(ct)
        };
        let decrypt = |ct: &[u8]| {
            let mut pt = vec![0; ct.len()];
            ctr_decrypt(&key, nonce, &ct, &mut pt);
            // We need from_utf8_lossy here because the second block will be scrambled.
            String::from_utf8_lossy(&pt).contains(";admin=true;")
        };

        let mut ct = encrypt(b"?admin?true").unwrap();
        let actual_pt = b"?admin?true";
        let target_pt = b";admin=true";
        (0..actual_pt.len()).for_each(|i| ct[prefix.len() + i] ^= actual_pt[i] ^ target_pt[i]);
        assert!(decrypt(&ct));
    }
}
