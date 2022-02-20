pub struct MD4 {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

#[inline(always)]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((!x) & z)
}

#[inline(always)]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline(always)]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

impl MD4 {
    #[must_use]
    pub fn with(a: u32, b: u32, c: u32, d: u32) -> Self {
        Self { a, b, c, d }
    }

    fn process(&mut self, x: [u32; 16]) {
        let mut a = self.a;
        let mut b = self.b;
        let mut c = self.c;
        let mut d = self.d;

        // Round 1
        let r = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32| {
            a.wrapping_add(f(b, c, d)).wrapping_add(x[k]).rotate_left(s)
        };
        [0, 4, 8, 12].into_iter().for_each(|i| {
            a = r(a, b, c, d, i, 3);
            d = r(d, a, b, c, i + 1, 7);
            c = r(c, d, a, b, i + 2, 11);
            b = r(b, c, d, a, i + 3, 19);
        });

        // Round 2
        let r = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32| {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(0x5A827999)
                .rotate_left(s)
        };
        [0, 1, 2, 3].into_iter().for_each(|i| {
            a = r(a, b, c, d, i, 3);
            d = r(d, a, b, c, i + 4, 5);
            c = r(c, d, a, b, i + 8, 9);
            b = r(b, c, d, a, i + 12, 13);
        });

        // Round 3
        let r = |a: u32, b: u32, c: u32, d: u32, k: usize, s: u32| {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(x[k])
                .wrapping_add(0x6ED9EBA1)
                .rotate_left(s)
        };
        [0, 2, 1, 3].into_iter().for_each(|i| {
            a = r(a, b, c, d, i, 3);
            d = r(d, a, b, c, i + 8, 9);
            c = r(c, d, a, b, i + 4, 11);
            b = r(b, c, d, a, i + 12, 15);
        });

        self.a = self.a.wrapping_add(a);
        self.b = self.b.wrapping_add(b);
        self.c = self.c.wrapping_add(c);
        self.d = self.d.wrapping_add(d);
    }

    fn process_block(&mut self, block: &[u8]) {
        let mut m = [0; 16];
        block
            .chunks_exact(4)
            .enumerate()
            .for_each(|(i, b)| m[i] = u32::from_le_bytes(b.try_into().unwrap()));
        self.process(m);
    }

    fn process_last(&mut self, rem: &[u8], b: u64) {
        let rl = rem.len();
        let mut block = [0; 64];
        block[0..rl].copy_from_slice(rem);
        block[rl] = 0x80;
        if rl > 64 - 1 - 8 {
            self.process_block(&block);
            block = [0; 64];
        }
        block[56..64].copy_from_slice(&b.to_le_bytes());
        self.process_block(&block);
    }

    pub fn hash_with_b(&mut self, msg: &[u8], b: u64, hash: &mut [u8]) {
        assert_eq!(hash.len(), 16);

        // Processing X(i)
        let iter = msg.chunks_exact(64);
        let rem = iter.remainder();
        iter.for_each(|block| self.process_block(block));

        // Message padding
        self.process_last(rem, b);

        // Computing A B C D
        hash[0..4].copy_from_slice(&self.a.to_le_bytes());
        hash[4..8].copy_from_slice(&self.b.to_le_bytes());
        hash[8..12].copy_from_slice(&self.c.to_le_bytes());
        hash[12..16].copy_from_slice(&self.d.to_le_bytes());
    }

    pub fn hash(&mut self, msg: &[u8], hash: &mut [u8]) {
        let b = 8 * u64::try_from(msg.len()).unwrap();
        self.hash_with_b(msg, b, hash);
    }
}

impl Default for MD4 {
    fn default() -> Self {
        Self::with(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    }
}

pub fn md4_mac(key: &[u8], msg: &[u8], mac: &mut [u8]) {
    let mut new_msg = Vec::with_capacity(key.len() + msg.len());
    new_msg.extend_from_slice(key);
    new_msg.extend_from_slice(msg);

    let mut md4 = MD4::default();
    md4.hash(&new_msg, mac);
}
