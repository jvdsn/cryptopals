#[cfg(test)]
mod tests {
    use crate::shared::dh;
    use num_bigint::BigUint;
    use num_traits::Zero;

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
        let p = BigUint::parse_bytes(p_hex, 16).unwrap();
        let g = BigUint::parse_bytes(g_hex, 16).unwrap();

        let (a, A) = dh::generate_keypair(&p, &g);
        let (b, B) = dh::generate_keypair(&p, &g);
        let s1 = dh::derive_shared(&p, &a, &B);
        let s2 = dh::derive_shared(&p, &b, &A);
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
        let Ap = BigUint::parse_bytes(p_hex, 16).unwrap();
        let Ag = BigUint::parse_bytes(g_hex, 16).unwrap();
        let (Aa, AA) = dh::generate_keypair(&Ap, &Ag);

        // A->M
        let Mp = Ap.clone();
        let Mg = Ag.clone();
        let _AB = AA.clone();

        // M->B
        let Bp = Mp.clone();
        let Bg = Mg.clone();
        let BA = Mp.clone();
        let (Bb, BB) = dh::generate_keypair(&Bp, &Bg);

        // B->M
        let _MB = BB.clone();

        // M->A
        let AB = Mp.clone();

        let As = dh::derive_shared(&Ap, &Aa, &AB);
        let Bs = dh::derive_shared(&Bp, &Bb, &BA);
        assert!(As.is_zero());
        assert!(Bs.is_zero());
    }
}
