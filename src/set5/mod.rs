#[cfg(test)]
mod tests {
    use crate::shared::dh;
    use crate::shared::dh::{simplified_srp, srp};
    use crate::shared::hmac::hmac;
    use crate::shared::rsa;
    use crate::shared::sha256::SHA256;
    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use std::ops::Sub;

    #[allow(non_snake_case)]
    #[test]
    fn test_challenge_33() {
        let p_hex = b"\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff";
        let g_hex = b"2";
        let p = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let g = &BigUint::parse_bytes(g_hex, 16).unwrap();

        let (ref a, ref A) = dh::generate_keypair(p, g);
        let (ref b, ref B) = dh::generate_keypair(p, g);
        let s1 = dh::derive_shared(p, a, B);
        let s2 = dh::derive_shared(p, b, A);
        assert_eq!(s1, s2);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_challenge_34() {
        let p_hex = b"\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff";
        let g_hex = b"2";

        // Initialization
        let Ap = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let Ag = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let (ref Aa, ref AA) = dh::generate_keypair(Ap, Ag);

        // A->M
        let Mp = Ap;
        let Mg = Ag;
        let _AB = AA;

        // M->B
        let Bp = Mp;
        let Bg = Mg;
        let BA = Mp;
        let (ref Bb, ref BB) = dh::generate_keypair(&Bp, &Bg);

        // B->M
        let _MB = BB;

        // M->A
        let AB = Mp;

        let As = dh::derive_shared(Ap, Aa, AB);
        let Bs = dh::derive_shared(Bp, Bb, BA);
        assert!(As.is_zero());
        assert!(Bs.is_zero());
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_challenge_35() {
        let p_hex = b"\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff";
        let g_hex = b"2";

        let Ap = &BigUint::parse_bytes(p_hex, 16).unwrap();
        let Ag = &BigUint::parse_bytes(g_hex, 16).unwrap();

        let protocol = |g: &BigUint| {
            // A -> M
            let Mp = Ap;
            let _Mg = Ag;

            // M -> B
            let Bp = Mp;
            let Bg = g;

            // A -> B
            let (ref Aa, ref AA) = dh::generate_keypair(Ap, Ag);
            let BA = AA;

            // B -> A
            let (ref Bb, ref BB) = dh::generate_keypair(Bp, Bg);
            let AB = BB;

            let As = dh::derive_shared(Ap, Aa, AB);
            let Bs = dh::derive_shared(Bp, Bb, BA);
            (As, Bs)
        };

        let (As, _Bs) = protocol(&BigUint::one());
        assert!(As.is_one());
        let (As, _Bs) = protocol(Ap);
        assert!(As.is_zero());
        let (As, _Bs) = protocol(&Ap.sub(1u8));
        assert!(As.is_one() || As == Ap.sub(1u8));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_challenge_36() {
        let N_hex = b"\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff";
        let g_hex = b"2";
        let k_hex = b"3";

        let N = &BigUint::parse_bytes(N_hex, 16).unwrap();
        let g = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let k = &BigUint::parse_bytes(k_hex, 16).unwrap();
        let mut Cmac = [0; 32];
        let mut Smac = [0; 32];
        srp(
            N,
            g,
            k,
            false,
            &mut [0; 32],
            &mut Cmac,
            &mut [0; 32],
            &mut Smac,
        );
        assert_eq!(Cmac, Smac);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_challenge_37() {
        let N_hex = b"\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff";
        let g_hex = b"2";
        let k_hex = b"3";

        let N = &BigUint::parse_bytes(N_hex, 16).unwrap();
        let g = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let k = &BigUint::parse_bytes(k_hex, 16).unwrap();
        let mut SK = [0; 32];
        srp(
            N,
            g,
            k,
            true,
            &mut [0; 32],
            &mut [0; 32],
            &mut SK,
            &mut [0; 32],
        );
        let mut zero_hash = [0; 32];
        SHA256::default().hash(&BigUint::zero().to_bytes_be(), &mut zero_hash);
        assert_eq!(SK, zero_hash);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_challenge_38() {
        let N_hex = b"\
        ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
        e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
        3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
        6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
        24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
        c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
        bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
        fffffffffffff";
        let g_hex = b"2";

        let N = &BigUint::parse_bytes(N_hex, 16).unwrap();
        let g = &BigUint::parse_bytes(g_hex, 16).unwrap();
        let mut Cmac = [0; 32];
        let mut Smac = [0; 32];
        simplified_srp(N, g, &mut [0; 16], &mut Cmac, &mut Smac);
        assert_eq!(Cmac, Smac);

        let mut Ssalt = [0; 16];
        let (ref Sb, ref SA, ref Su) = simplified_srp(N, g, &mut Ssalt, &mut Cmac, &mut [0; 32]);
        let SN = N;
        let Sg = g;

        let dictionary: [&[u8]; 4] = [b"password1", b"password2", b"password3", b"password"];
        assert!(dictionary.into_iter().any(|P| {
            let mut hash = [0; 32];
            SHA256::default().hash(&[&Ssalt, P].concat(), &mut hash);
            let Sx = &BigUint::from_bytes_be(&hash);
            let Sv = &Sg.modpow(Sx, SN);

            let SS = (SA * Sv.modpow(&Su, SN)).modpow(&Sb, SN);
            let mut SK = [0; 32];
            SHA256::default().hash(&SS.to_bytes_be(), &mut SK);

            hmac(&SK, &Ssalt, &mut Smac, |msg, hash| {
                SHA256::default().hash(msg, hash);
            });

            Smac == Cmac
        }));
    }

    #[test]
    fn test_challenge_39() {
        let message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
        let (public_key, private_key) = rsa::generate_keypair(1024);
        let m = BigUint::from_bytes_be(message.as_bytes());
        let c = rsa::encrypt(&m, &public_key);
        let m = rsa::decrypt(&c, &private_key);
        assert_eq!(String::from_utf8(m.to_bytes_be()).unwrap(), message);
    }
}
