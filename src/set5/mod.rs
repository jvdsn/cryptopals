#[cfg(test)]
mod tests {
    use crate::shared::dh::{simplified_srp, srp};
    use crate::shared::hmac::hmac;
    use crate::shared::rsa;
    use crate::shared::sha256::SHA256;
    use crate::shared::{dh, mod_inv};
    use num_bigint::{BigUint, ToBigInt};
    use num_integer::Integer;
    use num_traits::{One, Zero};
    use std::ops::Sub;
    use std::str::FromStr;

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
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit";
        let m = BigUint::from_bytes_be(message);
        // Apparently there's no real pure Rust libraries to generate random primes??...
        let p = &BigUint::from_str("9902478688314345424239631829098064031372511021415073888934444987805904619070767824954564980642642554558422713147827332946886953946202126417051242267443733").unwrap();
        let q = &BigUint::from_str("9023289800571256384296979170278503137808766752150078076803904588875045578444674044397684797154640374473290798963775917093544857834628721547751219278749279").unwrap();
        let (public_key, private_key) = rsa::generate_keypair(p, q);
        let c = rsa::encrypt(&public_key, &m);
        let m = rsa::decrypt(&private_key, &c);
        assert_eq!(m.to_bytes_be(), message);
    }

    #[test]
    fn test_challenge_40() {
        let message = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit";
        let m = BigUint::from_bytes_be(message);
        // Apparently there's no real pure Rust libraries to generate random primes??...
        let p0 = &BigUint::from_str("9902478688314345424239631829098064031372511021415073888934444987805904619070767824954564980642642554558422713147827332946886953946202126417051242267443733").unwrap();
        let q0 = &BigUint::from_str("9023289800571256384296979170278503137808766752150078076803904588875045578444674044397684797154640374473290798963775917093544857834628721547751219278749279").unwrap();
        let p1 = &BigUint::from_str("11274983038895115121293116870192254883468059626563068837945742093801526722162538837580229240054792262576510430845352465935843147772922402832853959860669771").unwrap();
        let q1 = &BigUint::from_str("7262594005020769019931822832663446500662485538381898929588200396322418810779276174809382812951073349907424874728035382013137196078489330189449393145355503").unwrap();
        let p2 = &BigUint::from_str("12913543998799265969823239687498071641165862012531925177661036260568473452380829657935448074759790583333391776955901364246374511636780811502839627485014289").unwrap();
        let q2 = &BigUint::from_str("9545889585983283723785056542372918092517768841049236382780906557531644288178748339341312152025004910555059160421572735766889349024115657853149560419070863").unwrap();
        let (public_key0, _) = rsa::generate_keypair(p0, q0);
        let (public_key1, _) = rsa::generate_keypair(p1, q1);
        let (public_key2, _) = rsa::generate_keypair(p2, q2);
        let c0 = rsa::encrypt(&public_key0, &m);
        let c1 = rsa::encrypt(&public_key1, &m);
        let c2 = rsa::encrypt(&public_key2, &m);
        let (n0, _) = public_key0;
        let (n1, _) = public_key1;
        let (n2, _) = public_key2;
        let n012 = &n0 * &n1 * &n2;
        let ms0 = &n1 * &n2;
        let ms1 = &n0 * &n2;
        let ms2 = &n0 * &n1;
        let result = ((&c0 * &ms0 * mod_inv(&ms0.to_bigint().unwrap(), &n0).unwrap())
            .mod_floor(&n012)
            + (&c1 * &ms1 * mod_inv(&ms1.to_bigint().unwrap(), &n1).unwrap()).mod_floor(&n012)
            + (&c2 * &ms2 * mod_inv(&ms2.to_bigint().unwrap(), &n2).unwrap()).mod_floor(&n012))
        .mod_floor(&n012);
        let m = result.nth_root(3);
        assert_eq!(m.to_bytes_be(), message);
    }
}
