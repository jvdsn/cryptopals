pub struct SHA256 {
    k: [u32; 64],
    h: [u32; 8],
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ ((!x) & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn bsig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn bsig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn ssig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn ssig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

impl SHA256 {
    #[must_use]
    pub fn with(h: [u32; 8]) -> Self {
        let mut k = [0; 64];
        k[0..4].copy_from_slice(&[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]);
        k[4..8].copy_from_slice(&[0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5]);
        k[8..12].copy_from_slice(&[0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3]);
        k[12..16].copy_from_slice(&[0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174]);
        k[16..20].copy_from_slice(&[0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc]);
        k[20..24].copy_from_slice(&[0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da]);
        k[24..28].copy_from_slice(&[0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7]);
        k[28..32].copy_from_slice(&[0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967]);
        k[32..36].copy_from_slice(&[0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13]);
        k[36..40].copy_from_slice(&[0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85]);
        k[40..44].copy_from_slice(&[0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3]);
        k[44..48].copy_from_slice(&[0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070]);
        k[48..52].copy_from_slice(&[0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5]);
        k[52..56].copy_from_slice(&[0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3]);
        k[56..60].copy_from_slice(&[0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208]);
        k[60..64].copy_from_slice(&[0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
        Self { k, h }
    }

    fn process(&mut self, m: &[u32; 16]) {
        let mut w = [0; 64];
        // Step 1
        w[0..16].copy_from_slice(m);
        (16..64).for_each(|t| {
            w[t] = ssig1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(ssig0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        });

        // Step 2
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // Step 3
        (0..64).for_each(|t| {
            let t1 = h
                .wrapping_add(bsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(self.k[t])
                .wrapping_add(w[t]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        });

        // Step 4
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut m = [0; 16];
        block
            .chunks_exact(4)
            .enumerate()
            .for_each(|(i, b)| m[i] = u32::from_be_bytes(b.try_into().unwrap()));
        self.process(&m);
    }

    fn process_last(&mut self, rem: &[u8], l: u64) {
        let rl = rem.len();
        let mut block = [0; 64];
        block[0..rl].copy_from_slice(rem);
        block[rl] = 0x80;
        if rl > 64 - 1 - 8 {
            self.process_block(&block);
            block = [0; 64];
        }
        block[56..64].copy_from_slice(&l.to_be_bytes());
        self.process_block(&block);
    }

    pub fn hash_with_l(&mut self, msg: &[u8], l: u64, hash: &mut [u8; 32]) {
        // Processing M(i)
        let iter = msg.chunks_exact(64);
        let rem = iter.remainder();
        iter.for_each(|block| self.process_block(block));

        // Message padding
        self.process_last(rem, l);

        // Computing H0 H1 H2 H3 H4 H5 H6 H7
        self.h
            .iter()
            .enumerate()
            .for_each(|(i, hi)| hash[4 * i..4 * i + 4].copy_from_slice(&hi.to_be_bytes()));
    }

    pub fn hash(&mut self, msg: &[u8], hash: &mut [u8; 32]) {
        let l = 8 * u64::try_from(msg.len()).unwrap();
        self.hash_with_l(msg, l, hash);
    }
}

impl Default for SHA256 {
    fn default() -> Self {
        Self::with([
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ])
    }
}
