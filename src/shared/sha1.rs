pub struct SHA1 {
    k: [u32; 80],
    h: [u32; 5],
}

#[inline(always)]
fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
    match t {
        0..=19 => (b & c) | ((!b) & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        60..=79 => b ^ c ^ d,
        _ => unreachable!(),
    }
}

impl SHA1 {
    #[must_use]
    pub fn with(h: [u32; 5]) -> Self {
        let mut k = [0; 80];
        k[0..20].copy_from_slice(&[0x5A827999; 20]);
        k[20..40].copy_from_slice(&[0x6ED9EBA1; 20]);
        k[40..60].copy_from_slice(&[0x8F1BBCDC; 20]);
        k[60..80].copy_from_slice(&[0xCA62C1D6; 20]);
        Self { k, h }
    }

    fn process(&mut self, m: [u32; 16]) {
        let mut w = [0; 80];
        // Step a
        w[0..16].copy_from_slice(&m);

        // Step b
        (16..80).for_each(|t| w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1));

        // Step c
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        // Step d
        (0..80).for_each(|t| {
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f(t, b, c, d))
                .wrapping_add(e)
                .wrapping_add(w[t])
                .wrapping_add(self.k[t]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        });

        // Step e
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut m = [0; 16];
        block
            .chunks_exact(4)
            .enumerate()
            .for_each(|(i, b)| m[i] = u32::from_be_bytes(b.try_into().unwrap()));
        self.process(m);
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

    pub fn hash_with_l(&mut self, msg: &[u8], l: u64, hash: &mut [u8]) {
        assert_eq!(hash.len(), 20);

        // Processing M(i)
        let iter = msg.chunks_exact(64);
        let rem = iter.remainder();
        iter.for_each(|block| self.process_block(block));

        // Message padding
        self.process_last(rem, l);

        // Computing H0 H1 H2 H3 H4
        self.h
            .iter()
            .enumerate()
            .for_each(|(i, hi)| hash[4 * i..4 * i + 4].copy_from_slice(&hi.to_be_bytes()));
    }

    pub fn hash(&mut self, msg: &[u8], hash: &mut [u8]) {
        let l = 8 * u64::try_from(msg.len()).unwrap();
        self.hash_with_l(msg, l, hash);
    }
}

impl Default for SHA1 {
    fn default() -> Self {
        Self::with([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0])
    }
}

pub fn sha1_mac(key: &[u8], msg: &[u8], mac: &mut [u8]) {
    SHA1::default().hash(&[key, msg].concat(), mac);
}
