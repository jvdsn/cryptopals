#[cfg(test)]
pub mod tests {
    use crate::shared::conversion::hex_to_bytes;
    use crate::shared::sha1::SHA1;
    use crate::shared::{dsa, mod_inv, mod_sub, rsa};
    use num_bigint::BigUint;
    use num_integer::Integer;
    use num_traits::{Num, One, Zero};
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::str::FromStr;

    #[test]
    fn test_challenge_41() {
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit";
        let m = BigUint::from_bytes_be(message);
        // Apparently there's no real pure Rust libraries to generate random primes??...
        let p = &BigUint::from_str("9902478688314345424239631829098064031372511021415073888934444987805904619070767824954564980642642554558422713147827332946886953946202126417051242267443733").unwrap();
        let q = &BigUint::from_str("9023289800571256384296979170278503137808766752150078076803904588875045578444674044397684797154640374473290798963775917093544857834628721547751219278749279").unwrap();
        let (public_key, private_key) = rsa::generate_keypair(p, q);
        let c = rsa::encrypt(&public_key, &m);

        let (n, e) = public_key;
        let c_ = (BigUint::from(2u8).modpow(&e, &n) * c).mod_floor(&n);
        let m_ = rsa::decrypt(&private_key, &c_);
        let m = (m_ * mod_inv(&BigUint::from(2u8), &n).unwrap()).mod_floor(&n);
        assert_eq!(m.to_bytes_be(), message);
    }

    #[test]
    fn test_challenge_42() {
        // We need a message with an odd SHA-1 hash.
        let message = b"hi mom!!!";
        // Apparently there's no real pure Rust libraries to generate random primes??...
        let p = &BigUint::from_str("9902478688314345424239631829098064031372511021415073888934444987805904619070767824954564980642642554558422713147827332946886953946202126417051242267443733").unwrap();
        let q = &BigUint::from_str("9023289800571256384296979170278503137808766752150078076803904588875045578444674044397684797154640374473290798963775917093544857834628721547751219278749279").unwrap();
        let (public_key, private_key) = rsa::generate_keypair(p, q);

        let mut sig = [0; 128];
        rsa::sign(&private_key, message, &mut sig);
        assert!(rsa::verify(&public_key, message, &sig));

        let mut hash = [0; 20];
        SHA1::default().hash(message, &mut hash);
        let mut data = [0; 35];
        data[0..15].copy_from_slice(rsa::SHA1_ASN1_ID);
        data[15..35].copy_from_slice(&hash);
        let suffix = BigUint::from_bytes_be(&data);
        assert!(!suffix.is_even());
        let mut s = BigUint::one();
        for i in 0..288 {
            if s.pow(3).bit(i) != suffix.bit(i) {
                s.set_bit(i, true);
            }
        }

        // Most of c is randomly generated...
        let c = hex_to_bytes("0001ff4a5cf727f546010e5a7d86356c1139f7dd9b5817939c30edb390c713785ce88268b10473ca2eca46fe22f6b3117364997f0f6dc3ce4c1b8efb65bfba72b692d2de5a3bfeeae1ac3b37a8866f423ed0ccbbe9ccc2b79c66e8ac95fe818a8833819602d5cdd4fbb882c1b0be3c4fc06fa4ceffe731a9998d773d28dfc286").unwrap();
        let suffix = s.to_bytes_be();
        let mut sig = BigUint::from_bytes_be(&c).nth_root(3).to_bytes_be();
        let sig_len = sig.len();
        sig[sig_len - suffix.len()..sig_len].copy_from_slice(&suffix);
        assert!(rsa::verify(&public_key, message, &sig));
    }

    #[test]
    fn test_challenge_43() {
        let p_hex = b"\
        800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1";
        let q_hex = b"f4f47f05794b256174bba6e9b396a7707e563c5b";
        let g_hex = b"\
        5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
        9fc95302291";
        let y_hex = b"\
        84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4\
        abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004\
        e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed\
        1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b\
        bb283e6633451e535c45513b2d33c99ea17";
        let m_hex = b"d2d0714f014a9784047eaeccf956520045c45265";

        let _p = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let q = &BigUint::parse_bytes(q_hex, 16).unwrap();
        let _g = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let _y = &BigUint::parse_bytes(y_hex, 16).unwrap();
        let m = &BigUint::parse_bytes(m_hex, 16).unwrap();

        let r = &BigUint::from_str("548099063082341131477253921760299949438196259240").unwrap();
        let s = &BigUint::from_str("857042759984254168557880549501802188789837994940").unwrap();
        let target_hash = hex_to_bytes("0954edd5e0afe5542a4adf012611a91912a3ec16").unwrap();
        assert!((0..=65535).any(|k: u16| {
            let x = dsa::find_x(q, m, &BigUint::from(k), r, s);
            let mut hash = [0; 20];
            SHA1::default().hash(x.to_str_radix(16).as_bytes(), &mut hash);
            target_hash == hash
        }));
    }

    #[test]
    fn test_challenge_44() {
        let p_hex = b"\
        800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1";
        let q_hex = b"f4f47f05794b256174bba6e9b396a7707e563c5b";
        let g_hex = b"\
        5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
        9fc95302291";
        let y_hex = b"\
        2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
        13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
        5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
        f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
        f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
        2971c3de5084cce04a2e147821";

        let _p = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let q = &BigUint::parse_bytes(q_hex, 16).unwrap();
        let _g = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let _y = &BigUint::parse_bytes(y_hex, 16).unwrap();

        let mut m = Vec::new();
        let mut r = Vec::new();
        let mut s = Vec::new();
        BufReader::new(File::open("src/set6/challenge44.txt").unwrap())
            .lines()
            .filter_map(|line| line.ok())
            .for_each(|line| {
                let value: String = line.chars().skip(3).collect();
                if line.starts_with("m: ") {
                    m.push(BigUint::from_str_radix(&value, 16).unwrap());
                }
                if line.starts_with("r: ") {
                    r.push(BigUint::from_str(&value).unwrap());
                }
                if line.starts_with("s: ") {
                    s.push(BigUint::from_str(&value).unwrap());
                }
            });

        let target_hash = hex_to_bytes("ca8f6f7c66fa362d40760d135b763eb8527d3d52").unwrap();
        assert!((0..m.len()).any(|i| {
            (i + 1..m.len()).filter(|&j| m[i] != m[j]).any(|j| {
                let k = (mod_inv(&mod_sub(&s[i], &s[j], q), q).unwrap() * mod_sub(&m[i], &m[j], q))
                    .mod_floor(q);
                let x = dsa::find_x(q, &m[i], &BigUint::from(k), &r[i], &s[i]);
                let mut hash = [0; 20];
                SHA1::default().hash(x.to_str_radix(16).as_bytes(), &mut hash);
                println!("{x}");
                return target_hash == hash;
            })
        }));
    }

    #[test]
    fn test_challenge_45() {
        let p_hex = b"\
        800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1";
        let q_hex = b"f4f47f05794b256174bba6e9b396a7707e563c5b";
        let x_hex = b"f1b733db159c66bce071d21e044a48b0e4c1665a";
        let y_hex = b"\
        2d026f4bf30195ede3a088da85e398ef869611d0f68f07\
        13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8\
        5519b1c23cc3ecdc6062650462e3063bd179c2a6581519\
        f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430\
        f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3\
        2971c3de5084cce04a2e147821";
        let m_hex = b"d2d0714f014a9784047eaeccf956520045c45265";

        let p = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let q = &BigUint::parse_bytes(q_hex, 16).unwrap();
        let x = &BigUint::parse_bytes(x_hex, 16).unwrap();
        let y = &BigUint::parse_bytes(y_hex, 16).unwrap();
        let m = &BigUint::parse_bytes(m_hex, 16).unwrap();

        let g = &BigUint::zero();
        let (ref r, ref s) = dsa::sign(p, q, g, x, m);
        assert!(dsa::verify(p, q, g, y, m, r, s));
        assert!(dsa::verify(p, q, g, y, &(m + BigUint::one()), r, s));

        let g = &BigUint::one();
        let r = &y.mod_floor(q);
        let s = r;
        assert!(dsa::verify(p, q, g, y, m, r, s));
        assert!(dsa::verify(p, q, g, y, &(m + BigUint::one()), r, s));
    }
}
