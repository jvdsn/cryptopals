#[cfg(test)]
pub mod tests {
    use crate::shared::{mod_inv, rsa};
    use num_bigint::{BigInt, BigUint};
    use num_integer::Integer;
    use std::str::FromStr;

    #[test]
    fn challenge41() {
        let message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
        let m = BigUint::from_bytes_be(message.as_bytes());
        // Apparently there's no real pure Rust libraries to generate random primes??...
        let p = &BigUint::from_str("9902478688314345424239631829098064031372511021415073888934444987805904619070767824954564980642642554558422713147827332946886953946202126417051242267443733").unwrap();
        let q = &BigUint::from_str("9023289800571256384296979170278503137808766752150078076803904588875045578444674044397684797154640374473290798963775917093544857834628721547751219278749279").unwrap();
        let (public_key, private_key) = rsa::generate_keypair(p, q);
        let c = rsa::encrypt(&m, &public_key);

        let (n, e) = public_key;
        let c_ = (BigUint::from(2u8).modpow(&e, &n) * c).mod_floor(&n);
        let m_ = rsa::decrypt(&c_, &private_key);
        let m = (m_ * mod_inv(&BigInt::from(2u8), &n).unwrap()).mod_floor(&n);
        assert_eq!(String::from_utf8(m.to_bytes_be()).unwrap(), message);
    }
}
