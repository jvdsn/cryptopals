#[cfg(test)]
mod tests {
    use crate::shared::aes::{cbc_decrypt, cbc_encrypt, ctr_decrypt, ctr_encrypt};
    use crate::shared::conversion::base64_to_bytes;
    use crate::shared::mersenne_twister::{clone_mt19937, encrypt, MersenneTwister};
    use crate::shared::padding::{pad_pkcs7, unpad_pkcs7};
    use crate::shared::xor::{break_xor_with_key, xor};
    use rand::{Rng, RngCore};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn test_challenge_17() {
        fn attack_block<F>(padding_oracle: F, iv: &[u8; 16], ct: &[u8], pt: &mut [u8])
        where
            F: Fn(&[u8; 16], &[u8]) -> bool,
        {
            (0..16).rev().for_each(|i| {
                let mut s = vec![u8::try_from(16 - i).unwrap(); 16 - i];
                xor(&mut s[1..], &pt[i + 1..]);
                let b = (0..=255)
                    .find(|&b| {
                        let mut iv_ = [0; 16];
                        iv_[i] = s[0] ^ b;
                        iv_[i + 1..].copy_from_slice(&s[1..]);
                        padding_oracle(&iv_, ct)
                    })
                    .expect(&format!(
                        "Unable to find decryption for {s:?}, {iv:?}, and {ct:?}"
                    ));
                pt[i] = b;
            });
            xor(pt, iv);
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

        let mut rng = rand::thread_rng();
        pts.iter().for_each(|pt| {
            let pt = pad_pkcs7(&base64_to_bytes(pt).unwrap(), 16);
            let mut key = [0; 16];
            rng.fill_bytes(&mut key);
            let mut iv = [0; 16];
            rng.fill_bytes(&mut iv);
            let mut ct = vec![0; pt.len()];
            cbc_encrypt(&key, &iv, &pt, &mut ct);

            let padding_oracle = |iv: &[u8; 16], ct: &[u8]| {
                let mut pt = vec![0; ct.len()];
                cbc_decrypt(&key, iv, ct, &mut pt);
                unpad_pkcs7(&pt, 16).is_some()
            };

            let mut pt_ = vec![0; ct.len()];
            attack_block(padding_oracle, &iv, &ct[0..16], &mut pt_[0..16]);
            let mut iv_ = [0; 16];
            (16..ct.len()).step_by(16).for_each(|i| {
                iv_.copy_from_slice(&ct[i - 16..i]);
                attack_block(padding_oracle, &iv_, &ct[i..i + 16], &mut pt_[i..i + 16])
            });

            assert_eq!(pt_, pt);
        });
    }

    #[test]
    fn test_challenge_18() {
        let key = b"YELLOW SUBMARINE";
        let nonce = 0;
        let ct = base64_to_bytes(
            "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
        )
        .unwrap();
        let mut pt = vec![0; ct.len()];
        ctr_decrypt(key, nonce, &ct, &mut pt);
        assert_eq!(
            String::from_utf8(pt).unwrap(),
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        );
    }

    #[test]
    fn test_challenge_19() {
        let mut rng = rand::thread_rng();
        let mut key = [0; 16];
        rng.fill_bytes(&mut key);
        let nonce = 0;
        let pts: Vec<Vec<u8>> = BufReader::new(File::open("src/set3/challenge19.txt").unwrap())
            .lines()
            .filter_map(|line| line.ok())
            .filter_map(|line| base64_to_bytes(&line))
            .collect();
        let cts: Vec<Vec<u8>> = pts
            .iter()
            .map(|pt| {
                let mut ct = vec![0; pt.len()];
                ctr_encrypt(&key, nonce, pt, &mut ct);
                ct
            })
            .collect();

        let min_length = pts.iter().map(|pt| pt.len()).min().unwrap();
        let ct = cts
            .iter()
            .map(|ct| &ct[0..min_length])
            .fold(Vec::new(), |mut accum, ct| {
                accum.extend_from_slice(ct);
                accum
            });

        let key_ = break_xor_with_key(&ct, min_length).unwrap();
        let mut pt = cts[0][0..min_length].to_owned();
        xor(&mut pt, &key_);
        // We ignore case here because "I have met them at c" is as likely as "i have met them at c"
        assert!(String::from_utf8(pt)
            .unwrap()
            .eq_ignore_ascii_case("i have met them at c"));
    }

    #[test]
    fn test_challenge_20() {
        let mut rng = rand::thread_rng();
        let mut key = [0; 16];
        rng.fill_bytes(&mut key);
        let nonce = 0;
        let pts: Vec<Vec<u8>> = BufReader::new(File::open("src/set3/challenge20.txt").unwrap())
            .lines()
            .filter_map(|line| line.ok())
            .filter_map(|line| base64_to_bytes(&line))
            .collect();
        let cts: Vec<Vec<u8>> = pts
            .iter()
            .map(|pt| {
                let mut ct = vec![0; pt.len()];
                ctr_encrypt(&key, nonce, pt, &mut ct);
                ct
            })
            .collect();

        let min_length = pts.iter().map(|pt| pt.len()).min().unwrap();
        let ct = cts
            .iter()
            .map(|ct| &ct[0..min_length])
            .fold(Vec::new(), |mut accum, ct| {
                accum.extend_from_slice(ct);
                accum
            });

        let key_ = break_xor_with_key(&ct, min_length).unwrap();
        let mut pt = cts[0][0..min_length].to_owned();
        xor(&mut pt, &key_);
        assert_eq!(
            String::from_utf8(pt).unwrap(),
            "I'm rated \"R\"...this is a warning, ya better void / P"
        );
    }

    #[test]
    fn test_challenge_21() {
        let mut mt = MersenneTwister::new_mt19937();
        assert_eq!(mt.next(), None);

        mt.seed(1812433253, 0);
        assert_eq!(mt.next().unwrap(), 2357136044);
        assert_eq!(mt.next().unwrap(), 2546248239);
        assert_eq!(mt.next().unwrap(), 3071714933);
        assert_eq!(mt.next().unwrap(), 3626093760);
    }

    #[test]
    fn test_challenge_22() {
        let mut mt = MersenneTwister::new_mt19937();
        let millis = 1644182174875u64;
        mt.seed(1812433253, millis as u32);

        let output = mt.next();
        let mut candidate = 1644182188326u64;
        loop {
            mt.seed(1812433253, candidate as u32);
            if mt.next() == output {
                assert_eq!(candidate, millis);
                break;
            }
            if candidate < millis {
                assert!(false);
                break;
            }
            candidate -= 1;
        }
    }

    #[test]
    fn test_challenge_23() {
        let mut mt = MersenneTwister::new_mt19937();
        mt.seed(1812433253, 0);

        let n = 624;
        let y = (0..n).map(|_| mt.next().unwrap()).collect::<Vec<u32>>();
        let mut mt_ = clone_mt19937(&y);
        (0..n).for_each(|_| assert_eq!(mt_.next(), mt.next()))
    }

    #[test]
    fn test_challenge_24() {
        // Make the key quite small so this test passes faster.
        let key = 1234;
        let mut rng = rand::thread_rng();
        let mut pt = vec![0; rng.gen_range(0..16)];
        rng.fill_bytes(&mut pt);
        pt.extend_from_slice(b"AAAAAAAAAAAAAA");
        let mut ct = vec![0; pt.len()];
        encrypt(key, &pt, &mut ct);

        let prefix_len = ct.len() - 14;
        let mut pt = vec![0; prefix_len];
        pt.extend_from_slice(b"AAAAAAAAAAAAAA");
        let mut ct_ = vec![0; pt.len()];
        assert!((0..=65535).any(|k| {
            encrypt(k, &pt, &mut ct_);
            ct_[prefix_len..] == ct[prefix_len..]
        }));
    }
}
