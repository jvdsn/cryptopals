use crate::shared::sha256::SHA256;
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::Zero;
use rand::RngCore;

#[must_use]
pub fn generate_keypair(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let private = rand::thread_rng().gen_biguint_below(p);
    let public = g.modpow(&private, p);
    (private, public)
}

#[must_use]
pub fn derive_shared(p: &BigUint, our_private: &BigUint, peer_public: &BigUint) -> BigUint {
    peer_public.modpow(our_private, p)
}

#[allow(non_snake_case)]
pub fn srp(N: &BigUint, send_A_0: bool, CK: &mut [u8; 32], SK: &mut [u8; 32]) {
    let mut rng = rand::thread_rng();
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

    let mut Ssalt = [0; 16];
    rng.fill_bytes(&mut Ssalt);
    let Ssalt: &[u8] = &Ssalt;
    let mut hash = [0; 32];
    SHA256::default().hash(&[Ssalt, P].concat(), &mut hash);
    let Sx = &BigUint::from_bytes_be(&hash);
    let Sv = &Sg.modpow(Sx, SN);
    let SB = &(Sk * Sv + SB);

    let SA = CA;

    let Csalt = Ssalt;
    let CB = SB;

    let mut hash = [0; 32];
    SHA256::default().hash(&[SA.to_bytes_be(), SB.to_bytes_be()].concat(), &mut hash);
    let Su = &BigUint::from_bytes_be(&hash);

    let mut hash = [0; 32];
    SHA256::default().hash(&[CA.to_bytes_be(), CB.to_bytes_be()].concat(), &mut hash);
    let Cu = &BigUint::from_bytes_be(&hash);

    let mut hash = [0; 32];
    SHA256::default().hash(&[Csalt, P].concat(), &mut hash);
    let Cx = &BigUint::from_bytes_be(&hash);
    let CS = (CB.to_bigint().unwrap() - (Ck * Cg.modpow(Cx, CN)).to_bigint().unwrap())
        .mod_floor(&CN.to_bigint().unwrap())
        .to_biguint()
        .unwrap()
        .modpow(&(Ca + Cu * Cx), CN);
    SHA256::default().hash(&CS.to_bytes_be(), CK);

    let SS = (SA * Sv.modpow(Su, SN)).modpow(Sb, SN);
    SHA256::default().hash(&SS.to_bytes_be(), SK);
}
