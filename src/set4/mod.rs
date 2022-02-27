#[cfg(test)]
mod tests {
    use crate::shared::aes::{
        cbc_decrypt, cbc_encrypt, ctr_decrypt, ctr_edit, ctr_encrypt, ecb_decrypt, random_key,
    };
    use crate::shared::conversion::base64_to_bytes;
    use crate::shared::hmac::hmac;
    use crate::shared::md4::{md4_mac, MD4};
    use crate::shared::padding::{pad_pkcs7, unpad_pkcs7};
    use crate::shared::random_bytes;
    use crate::shared::sha1::{sha1_mac, SHA1};
    use crate::shared::xor::xor;
    use rand::Rng;
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

    #[test]
    fn test_challenge_27() {
        let key = random_key();
        let iv = key.clone();
        let encrypt = |pt: &[u8]| {
            let pt = pad_pkcs7(&pt, 16);
            let mut ct = vec![0; pt.len()];
            cbc_encrypt(&key, &iv, &pt, &mut ct);
            ct
        };
        let decrypt = |ct: &[u8]| {
            let mut pt = vec![0; ct.len()];
            cbc_decrypt(&key, &iv, &ct, &mut pt);
            let pt = unpad_pkcs7(&pt, 16).unwrap();
            pt
        };

        let ct1 = encrypt(&[0; 48]);
        let mut ct2 = Vec::with_capacity(ct1.len());
        ct2.extend_from_slice(&ct1[0..16]);
        ct2.extend_from_slice(&[0; 16]);
        ct2.extend_from_slice(&ct1);
        let pt = decrypt(&ct2);
        let mut recovered_key = pt[0..16].to_owned();
        xor(&mut recovered_key, &pt[32..48]);
        assert_eq!(recovered_key, key);
    }

    #[test]
    fn test_challenge_28() {
        let key = random_bytes(rand::thread_rng().gen_range(0..16));
        let msg1 = b"Lorem ipsum";
        let msg2 = b"Lorem_ipsum";
        let mut mac1 = [0; 20];
        sha1_mac(&key, msg1, &mut mac1);
        let mut mac2 = [0; 20];
        sha1_mac(&key, msg1, &mut mac2);
        assert_eq!(mac1, mac2);
        sha1_mac(&key, msg2, &mut mac2);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_challenge_29() {
        let key = random_bytes(rand::thread_rng().gen_range(0..16));
        let msg1 = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mut mac1 = [0; 20];
        sha1_mac(&key, msg1, &mut mac1);

        assert!((0..16).any(|key_len| {
            let mut l = 8 * u64::try_from(key_len + msg1.len()).unwrap();
            let rl = (key_len + msg1.len()) % 64;
            let mut padding = Vec::new();
            padding.push(0x80);
            if rl > 64 - 1 - 8 {
                padding.extend_from_slice(&vec![0; 128 - rl - 1 - 8]);
            } else {
                padding.extend_from_slice(&vec![0; 64 - rl - 1 - 8]);
            }
            padding.extend_from_slice(&l.to_be_bytes());
            l += 8 * u64::try_from(padding.len()).unwrap();

            let msg2 = b";admin=true";
            l += 8 * u64::try_from(msg2.len()).unwrap();
            let mut mac2 = [0; 20];
            let mut h = [0; 5];
            mac1.chunks_exact(4)
                .enumerate()
                .for_each(|(i, c)| h[i] = u32::from_be_bytes(c.try_into().unwrap()));
            let mut sha1 = SHA1::with(h);
            sha1.hash_with_l(msg2, l, &mut mac2);

            let mut msg = Vec::with_capacity(msg1.len() + padding.len() + msg2.len());
            msg.extend_from_slice(msg1);
            msg.extend_from_slice(&padding);
            msg.extend_from_slice(msg2);
            let mut mac = [0; 20];
            sha1_mac(&key, &msg, &mut mac);

            return mac2 == mac;
        }));
    }

    #[test]
    fn test_challenge_30() {
        let key = random_bytes(rand::thread_rng().gen_range(0..16));
        let msg1 = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mut mac1 = [0; 16];
        md4_mac(&key, msg1, &mut mac1);

        assert!((0..16).any(|key_len| {
            let mut b = 8 * u64::try_from(key_len + msg1.len()).unwrap();
            let rl = (key_len + msg1.len()) % 64;
            let mut padding = Vec::new();
            padding.push(0x80);
            if rl > 64 - 1 - 8 {
                padding.extend_from_slice(&vec![0; 128 - rl - 1 - 8]);
            } else {
                padding.extend_from_slice(&vec![0; 64 - rl - 1 - 8]);
            }
            padding.extend_from_slice(&b.to_le_bytes());
            b += 8 * u64::try_from(padding.len()).unwrap();

            let msg2 = b";admin=true";
            b += 8 * u64::try_from(msg2.len()).unwrap();
            let mut mac2 = [0; 16];
            let mut md4 = MD4::with(
                u32::from_le_bytes(mac1[0..4].try_into().unwrap()),
                u32::from_le_bytes(mac1[4..8].try_into().unwrap()),
                u32::from_le_bytes(mac1[8..12].try_into().unwrap()),
                u32::from_le_bytes(mac1[12..16].try_into().unwrap()),
            );
            md4.hash_with_b(msg2, b, &mut mac2);

            let mut msg = Vec::with_capacity(msg1.len() + padding.len() + msg2.len());
            msg.extend_from_slice(msg1);
            msg.extend_from_slice(&padding);
            msg.extend_from_slice(msg2);
            let mut mac = [0; 16];
            md4_mac(&key, &msg, &mut mac);

            return mac2 == mac;
        }));
    }

    #[test]
    fn test_challenge_31() {
        let key = random_key();
        let insecure_compare = |a: &[u8], b: &[u8]| {
            // HTTP overhead: 40-60 ms
            let mut time = rand::thread_rng().gen_range(40..60);
            if a.len() != b.len() {
                return (false, time);
            }

            for (i, j) in a.iter().zip(b.iter()) {
                if i != j {
                    return (false, time);
                }
                time += 50;
            }
            (true, time)
        };

        let verify = |msg: &[u8], mac: &[u8]| {
            let mut computed_mac = [0; 20];
            hmac(&key, msg, &mut computed_mac, |key, mac| {
                SHA1::default().hash(key, mac)
            });
            insecure_compare(mac, &computed_mac)
        };

        let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true";
        let mut mac = [0; 20];
        (0..20).for_each(|i| {
            let (b, _) = (0..=255)
                .map(|b| {
                    mac[i] = b;
                    let (_, time) = verify(msg, &mac);
                    (b, time)
                })
                .max_by_key(|(_, time)| *time)
                .unwrap();
            mac[i] = b;
        });
        assert!(verify(msg, &mac).0);
    }

    #[test]
    fn test_challenge_32() {
        let key = random_key();
        let insecure_compare = |a: &[u8], b: &[u8]| {
            // HTTP overhead: 40-60 ms
            let mut time = rand::thread_rng().gen_range(40..60);
            if a.len() != b.len() {
                return (false, time);
            }

            for (i, j) in a.iter().zip(b.iter()) {
                if i != j {
                    return (false, time);
                }
                time += 5;
            }
            (true, time)
        };

        let verify = |msg: &[u8], mac: &[u8]| {
            let mut computed_mac = [0; 20];
            hmac(&key, msg, &mut computed_mac, |key, mac| {
                SHA1::default().hash(key, mac)
            });
            insecure_compare(mac, &computed_mac)
        };

        let msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon;admin=true";
        let mut mac = [0; 20];
        (0..20).for_each(|i| {
            let (b, _) = (0..=255)
                .map(|b| {
                    mac[i] = b;
                    let mut time = 0;
                    (0..50).for_each(|_| time += verify(msg, &mac).1);
                    (b, time)
                })
                .max_by_key(|(_, time)| *time)
                .unwrap();
            mac[i] = b;
        });
        assert!(verify(msg, &mac).0);
    }
}
