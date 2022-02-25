use num_bigint::{BigUint, RandBigInt};

pub fn generate_keypair(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();
    let private = rng.gen_biguint_below(p);
    let public = g.modpow(&private, p);
    (private, public)
}

pub fn derive_shared(p: &BigUint, our_private: &BigUint, peer_public: &BigUint) -> BigUint {
    peer_public.modpow(our_private, p)
}
