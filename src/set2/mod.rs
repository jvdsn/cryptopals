#[cfg(test)]
mod tests {
    use crate::shared::aes::{
        cbc_decrypt, cbc_encrypt, ecb_decrypt, ecb_encrypt, ecb_oracle, ecb_oracle_harder,
        encrypt_ecb_or_cbc, is_ecb, random_key,
    };
    use crate::shared::conversion::base64_to_bytes;
    use crate::shared::key_value::parse_key_value;
    use crate::shared::padding::{pad_pkcs7, unpad_pkcs7};
    use crate::shared::random_bytes;
    use crate::shared::xor::xor;
    use rand::Rng;
    use std::fs::read_to_string;
    use std::iter::repeat;

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
                let ct = ecb_oracle(&pt, &unknown, &key);
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

    #[test]
    fn test_challenge_13() {
        let map = parse_key_value("foo=bar&baz=qux&zap=zazzle");
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("foo").unwrap(), "bar");
        assert_eq!(map.get("baz").unwrap(), "qux");
        assert_eq!(map.get("zap").unwrap(), "zazzle");

        let key = random_key();
        let ct1 = ecb_encrypt(
            &pad_pkcs7(b"email=AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b&uid=10&role=user", 16),
            &key,
        );
        let ct2 = ecb_encrypt(
            &pad_pkcs7(b"email=evil@evil.com&uid=10&role=user", 16),
            &key,
        );
        let mut ct = Vec::with_capacity(ct2.len());
        ct.extend_from_slice(&ct2[0..16]);
        ct.extend_from_slice(&ct2[16..32]);
        ct.extend_from_slice(&ct1[16..32]);
        let pt = unpad_pkcs7(&ecb_decrypt(&ct, &key), 16).unwrap();
        let map = parse_key_value(&String::from_utf8(pt).unwrap());
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("email").unwrap(), "evil@evil.com");
        assert_eq!(map.get("uid").unwrap(), "10");
        assert_eq!(map.get("role").unwrap(), "admin");
    }

    #[test]
    fn test_challenge_14() {
        let unknown = base64_to_bytes(
            &read_to_string("src/set2/challenge12.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap();
        let key = random_key();
        let mut rng = rand::thread_rng();
        let random_prefix = random_bytes(rng.gen_range(0..16));
        // Assuming block size is already known.
        let block_size = 16;
        // Discovering random prefix length.
        let check: Vec<u8> = repeat(1).take(2 * block_size).collect();
        let mut prefix_padding: Vec<u8> = repeat(0).take(block_size).collect();
        while prefix_padding.len() > 0 {
            let mut pt = Vec::with_capacity(check.len() + prefix_padding.len());
            pt.extend_from_slice(&prefix_padding);
            pt.extend_from_slice(&check);
            let ct = ecb_oracle_harder(&random_prefix, &pt, &unknown, &key);
            if ct[block_size..2 * block_size] == ct[2 * block_size..3 * block_size] {
                break;
            }
            prefix_padding.pop();
        }
        assert_eq!(random_prefix.len() + prefix_padding.len(), block_size);

        let mut recovered = Vec::new();
        loop {
            let padding_len = (block_size - 1) - (recovered.len() % block_size);
            let mut pt = Vec::with_capacity(
                prefix_padding.len() + padding_len + recovered.len() + 1 + padding_len,
            );
            pt.extend(&prefix_padding);
            (0..padding_len).for_each(|_| pt.push(0));
            pt.extend(&recovered);
            pt.push(0);
            (0..padding_len).for_each(|_| pt.push(0));
            let byte_index = prefix_padding.len() + padding_len + recovered.len();
            let end1 = block_size + padding_len + recovered.len() + 1;
            let end2 = end1 + padding_len + recovered.len() + 1;
            let byte = (0..=255).find(|&b| {
                pt[byte_index] = b;
                let ct = ecb_oracle_harder(&random_prefix, &pt, &unknown, &key);
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

    #[test]
    fn test_challenge_15() {
        assert_eq!(
            unpad_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04", 16),
            Some(Vec::from("ICE ICE BABY"))
        );
        assert_eq!(unpad_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05", 16), None);
        assert_eq!(unpad_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04", 16), None);
    }

    #[test]
    fn test_challenge_16() {
        let key = random_key();
        let iv = random_bytes(16);
        let ct1 = cbc_encrypt(
            &pad_pkcs7(b"comment1=cooking%20MCs;userdata=?admin?true;comment2=%20like%20a%20pound%20of%20bacon", 16),
            &key,
            &iv
        );
        let actual_pt = b"?admin?true;comm";
        let target_pt = b";admin=true;comm";
        let mut ct2 = Vec::with_capacity(ct1.len());
        ct2.extend_from_slice(&ct1[0..16]);
        ct2.extend_from_slice(&xor(&ct1[16..32], &xor(actual_pt, target_pt)));
        ct2.extend_from_slice(&ct1[32..96]);
        let pt = unpad_pkcs7(&cbc_decrypt(&ct2, &key, &iv), 16).unwrap();
        // We need from_utf8_lossy here because the second block will be scrambled.
        assert!(String::from_utf8_lossy(&pt).contains(";admin=true;"));
    }
}
