use crate::shared::random_bytes;
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::Zero;
use sha2::digest::Digest;
use sha2::Sha256;

pub fn generate_keypair(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let private = rand::thread_rng().gen_biguint_below(p);
    let public = g.modpow(&private, p);
    (private, public)
}

pub fn derive_shared(p: &BigUint, our_private: &BigUint, peer_public: &BigUint) -> BigUint {
    peer_public.modpow(our_private, p)
}

#[allow(non_snake_case)]
pub fn srp(N: &BigUint, send_A_0: bool) -> (BigUint, BigUint) {
    let g_hex = b"2";
    let k_hex = b"2";
    let P = b"password";

    let CN = N;
    let Cg = &BigUint::parse_bytes(g_hex, 16).unwrap();
    let Ck = &BigUint::parse_bytes(k_hex, 16).unwrap();
    let (ref Ca, mut CA) = generate_keypair(N, Cg);
    if send_A_0 {
        CA.set_zero();
    }
    let CA = &CA;

    let SN = N;
    let Sg = &BigUint::parse_bytes(g_hex, 16).unwrap();
    let Sk = &BigUint::parse_bytes(k_hex, 16).unwrap();
    let (ref Sb, ref SB) = generate_keypair(N, Cg);

    let Ssalt = &random_bytes(16);
    let mut sha256 = Sha256::new();
    sha256.update(Ssalt);
    sha256.update(P);
    let Sx = &BigUint::from_bytes_be(sha256.finalize().as_slice());
    let Sv = &Sg.modpow(Sx, SN);
    let SB = &(Sk * Sv + SB);

    let SA = CA;

    let Csalt = Ssalt;
    let CB = SB;

    let mut sha256 = Sha256::new();
    sha256.update(&SA.to_bytes_be());
    sha256.update(&SB.to_bytes_be());
    let Su = &BigUint::from_bytes_be(sha256.finalize().as_slice());

    let mut sha256 = Sha256::new();
    sha256.update(&CA.to_bytes_be());
    sha256.update(&CB.to_bytes_be());
    let Cu = &BigUint::from_bytes_be(sha256.finalize().as_slice());

    let mut sha256 = Sha256::new();
    sha256.update(Csalt);
    sha256.update(P);
    let Cx = &BigUint::from_bytes_be(sha256.finalize().as_slice());
    let CS = (CB.to_bigint().unwrap() - (Ck * Cg.modpow(Cx, CN)).to_bigint().unwrap())
        .mod_floor(&CN.to_bigint().unwrap())
        .to_biguint()
        .unwrap()
        .modpow(&(Ca + Cu * Cx), CN);

    let SS = (SA * Sv.modpow(Su, SN)).modpow(Sb, SN);

    (CS, SS)
}
