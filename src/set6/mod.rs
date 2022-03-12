#[cfg(test)]
pub mod tests {
    use crate::shared::conversion::hex_to_bytes;
    use crate::shared::rsa::{sign, verify, SHA1_ASN1_ID};
    use crate::shared::sha1::SHA1;
    use crate::shared::{mod_inv, rsa};
    use num_bigint::{BigInt, BigUint};
    use num_integer::Integer;
    use num_traits::One;
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
        let m = (m_ * mod_inv(&BigInt::from(2u8), &n).unwrap()).mod_floor(&n);
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
        sign(&private_key, message, &mut sig);
        assert!(verify(&public_key, message, &sig));

        let mut hash = [0; 20];
        SHA1::default().hash(message, &mut hash);
        let mut data = [0; 35];
        data[0..15].copy_from_slice(SHA1_ASN1_ID);
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
        assert!(verify(&public_key, message, &sig));
    }
}
