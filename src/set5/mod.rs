#[cfg(test)]
mod tests {
    use crate::shared::dh::{derive_shared, generate_keypair, srp};
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

        let (ref a, ref A) = generate_keypair(p, g);
        let (ref b, ref B) = generate_keypair(p, g);
        let s1 = derive_shared(p, a, B);
        let s2 = derive_shared(p, b, A);
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
        let (ref Aa, ref AA) = generate_keypair(Ap, Ag);

        // A->M
        let Mp = Ap;
        let Mg = Ag;
        let _AB = AA;

        // M->B
        let Bp = Mp;
        let Bg = Mg;
        let BA = Mp;
        let (ref Bb, ref BB) = generate_keypair(&Bp, &Bg);

        // B->M
        let _MB = BB;

        // M->A
        let AB = Mp;

        let As = derive_shared(Ap, Aa, AB);
        let Bs = derive_shared(Bp, Bb, BA);
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
            let (ref Aa, ref AA) = generate_keypair(Ap, Ag);
            let BA = AA;

            // B -> A
            let (ref Bb, ref BB) = generate_keypair(Bp, Bg);
            let AB = BB;

            let As = derive_shared(Ap, Aa, AB);
            let Bs = derive_shared(Bp, Bb, BA);
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

        let N = &BigUint::parse_bytes(N_hex, 16).unwrap();
        let (CS, SS) = srp(N, false);
        assert_eq!(CS, SS);
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

        let N = &BigUint::parse_bytes(N_hex, 16).unwrap();
        let (_, SS) = srp(N, true);
        assert!(SS.is_zero());
    }
}
