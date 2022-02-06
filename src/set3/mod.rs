#[cfg(test)]
mod tests {
    use crate::shared::aes::{cbc_decrypt, cbc_encrypt, padding_oracle, random_key};
    use crate::shared::conversion::base64_to_bytes;
    use crate::shared::padding::{pad_pkcs7, unpad_pkcs7};
    use crate::shared::random_bytes;
    use crate::shared::xor::xor;

    #[test]
    fn test_challenge_17() {
        fn attack_block<F>(padding_oracle: F, iv: &[u8], ct: &[u8]) -> Vec<u8>
        where
            F: Fn(&[u8], &[u8]) -> bool,
        {
            let mut r = Vec::new();
            for i in (0..16).rev() {
                let s = vec![u8::try_from(16 - i).unwrap(); 16 - i];
                let b = (0..=255)
                    .find(|&b| {
                        let mut iv_ = vec![0; i];
                        iv_.push(s[0] ^ b);
                        iv_.extend(xor(&s[1..], &r));
                        padding_oracle(&iv_, ct)
                    })
                    .expect(&format!(
                        "Unable to find decryption for {s:?}, {iv:?}, and {ct:?}"
                    ));
                r.insert(0, b);
            }
            xor(iv, &r)
        }

        let pts = vec![
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];

        for pt in pts {
            let pt = base64_to_bytes(pt).unwrap();
            let padded = pad_pkcs7(&pt, 16);
            let key = random_key();
            let iv = random_bytes(16);
            let ct = cbc_encrypt(&key, &iv, &padded);

            let mut pt_ = attack_block(|iv, ct| padding_oracle(&key, iv, ct), &iv, &ct[0..16]);
            for i in (16..ct.len()).step_by(16) {
                pt_.extend(attack_block(
                    |iv, ct| padding_oracle(&key, iv, ct),
                    &ct[i - 16..i],
                    &ct[i..i + 16],
                ))
            }

            assert_eq!(pt_, padded);
        }
    }
}
