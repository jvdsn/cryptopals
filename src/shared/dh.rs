use crate::shared::hmac::hmac;
use crate::shared::mod_sub;
use crate::shared::sha256::SHA256;
use num_bigint::{BigUint, RandBigInt};
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
#[allow(clippy::too_many_arguments)]
pub fn srp(
    N: &BigUint,
    g: &BigUint,
    k: &BigUint,
    send_A_0: bool,
    CK: &mut [u8; 32],
    Cmac: &mut [u8; 32],
    SK: &mut [u8; 32],
    Smac: &mut [u8; 32],
) {
    let mut rng = rand::thread_rng();
    let P = b"password";

    let CN = N;
    let Cg = g;
    let Ck = k;
    let (ref Ca, mut CA) = generate_keypair(N, Cg);
    if send_A_0 {
        CA.set_zero();
    }
    let CA = &CA;

    let SN = N;
    let Sg = g;
    let Sk = k;
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
    let CS = mod_sub(CB, &(Ck * Cg.modpow(Cx, CN)), CN).modpow(&(Ca + Cu * Cx), CN);
    SHA256::default().hash(&CS.to_bytes_be(), CK);

    let SS = (SA * Sv.modpow(Su, SN)).modpow(Sb, SN);
    SHA256::default().hash(&SS.to_bytes_be(), SK);

    hmac(CK, Csalt, Cmac, |msg, hash| {
        SHA256::default().hash(msg, hash);
    });

    hmac(SK, Ssalt, Smac, |msg, hash| {
        SHA256::default().hash(msg, hash);
    });
}

#[allow(non_snake_case)]
pub fn simplified_srp(
    N: &BigUint,
    g: &BigUint,
    Ssalt: &mut [u8; 16],
    Cmac: &mut [u8; 32],
    Smac: &mut [u8; 32],
) -> (BigUint, BigUint, BigUint) {
    let mut rng = rand::thread_rng();
    let P = b"password";

    let CN = N;
    let Cg = g;
    let (ref Ca, CA) = generate_keypair(N, Cg);

    let SN = N;
    let Sg = g;
    let (Sb, ref SB) = generate_keypair(N, Cg);

    rng.fill_bytes(Ssalt);
    let Ssalt: &[u8] = &*Ssalt;
    let mut hash = [0; 32];
    SHA256::default().hash(&[Ssalt, P].concat(), &mut hash);
    let Sx = &BigUint::from_bytes_be(&hash);
    let Sv = &Sg.modpow(Sx, SN);

    let SA = &CA;

    let Csalt = Ssalt;
    let CB = &SB;

    let Su = rng.gen_biguint(128);

    let Cu = &Su;

    let mut hash = [0; 32];
    SHA256::default().hash(&[Csalt, P].concat(), &mut hash);
    let Cx = &BigUint::from_bytes_be(&hash);
    let CS = CB.modpow(&(Ca + Cu * Cx), CN);
    let mut CK = [0; 32];
    SHA256::default().hash(&CS.to_bytes_be(), &mut CK);

    let SS = (SA * Sv.modpow(&Su, SN)).modpow(&Sb, SN);
    let mut SK = [0; 32];
    SHA256::default().hash(&SS.to_bytes_be(), &mut SK);

    hmac(&CK, Csalt, Cmac, |msg, hash| {
        SHA256::default().hash(msg, hash);
    });

    hmac(&SK, Ssalt, Smac, |msg, hash| {
        SHA256::default().hash(msg, hash);
    });

    // We can't return SA here, but it's the same as CA.
    (Sb, CA, Su)
}
