#[cfg(test)]
mod tests {
    use crate::shared::aes::cbc_decrypt;
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
}
