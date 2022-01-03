#[cfg(test)]
mod tests {
    use crate::shared::aes::{cbc_decrypt, encrypt_ecb_or_cbc, is_ecb};
    use crate::shared::conversion::{base64_to_bytes, bytes_to_hex};
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
}
