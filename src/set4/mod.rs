#[cfg(test)]
mod tests {
    use crate::shared::aes::{ctr_edit, ctr_encrypt, ecb_decrypt, random_key};
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
}
