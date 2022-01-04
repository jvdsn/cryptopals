#[cfg(test)]
mod tests {
    use crate::shared::aes::{cbc_decrypt, ecb_oracle, encrypt_ecb_or_cbc, is_ecb, random_key};
    use crate::shared::conversion::base64_to_bytes;
    use crate::shared::padding::pad_pkcs7;
    use std::fs::read_to_string;

    #[test]
    fn test_challenge_9() {
        let bytes = b"YELLOW SUBMARINE";
        assert_eq!(pad_pkcs7(bytes, 20), b"YELLOW SUBMARINE\x04\x04\x04\x04")
    }

    #[test]
    fn test_challenge_10() {
        let ct = base64_to_bytes(
            &read_to_string("src/set2/challenge10.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap();
        let key = b"YELLOW SUBMARINE";
        let iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let pt = cbc_decrypt(&ct, key, iv);
        assert!(String::from_utf8(pt)
            .unwrap()
            .starts_with("I'm back and I'm ringin' the bell \n"));
    }

    #[test]
    fn test_challenge_11() {
        // 11 characters to fill the first block if the random prefix is only 5 bytes.
        // 32 characters to get the next two blocks without random bytes.
        let pt = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let (ct, ecb) = encrypt_ecb_or_cbc(pt);
        assert_eq!(is_ecb(&ct), ecb)
    }

    #[test]
    fn test_challenge_12() {
        let unknown = base64_to_bytes(
            &read_to_string("src/set2/challenge12.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap();
        let key = random_key();
        // Discovering block size.
        let mut block_size = 1;
        let mut pt = vec![0, 0];
        let mut ct = ecb_oracle(&pt, &unknown, &key);
        while ct[0..block_size] != ct[block_size..2 * block_size] {
            block_size += 1;
            pt.push(0);
            pt.push(0);
            ct = ecb_oracle(&pt, &unknown, &key);
        }
        assert_eq!(block_size, 16);

        let mut recovered = Vec::new();
        loop {
            let padding_len = (block_size - 1) - (recovered.len() % block_size);
            let mut pt = Vec::with_capacity(padding_len + recovered.len() + 1 + padding_len);
            (0..padding_len).for_each(|_| pt.push(0));
            pt.extend(&recovered);
            pt.push(0);
            (0..padding_len).for_each(|_| pt.push(0));
            let byte_index = padding_len + recovered.len();
            let end1 = padding_len + recovered.len() + 1;
            let end2 = end1 + padding_len + recovered.len() + 1;
            let byte = (0..=255).find(|&b| {
                pt[byte_index] = b;
                ct = ecb_oracle(&pt, &unknown, &key);
                ct[end1 - block_size..end1] == ct[end2 - block_size..end2]
            });
            if byte.is_some() {
                recovered.push(byte.unwrap());
                continue;
            }

            // This last byte will always be a padding byte.
            recovered.pop();
            break;
        }

        let recovered = String::from_utf8(recovered).unwrap();
        assert!(recovered.starts_with("Rollin' in my 5.0\n"));
        assert!(recovered.ends_with("Did you stop? No, I just drove by\n"));
    }
}
