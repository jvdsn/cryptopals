pub struct MersenneTwister {
    w: u32,
    n: usize,
    m: usize,
    a: u32,
    b: u32,
    c: u32,
    s: u32,
    t: u32,
    u: u32,
    d: u32,
    l: u32,
    mt: Vec<u32>,
    index: usize,
    lower_mask: u32,
    upper_mask: u32,
}

impl MersenneTwister {
    #[must_use]
    pub fn new(
        n: usize,
        m: usize,
        r: u32,
        a: u32,
        b: u32,
        c: u32,
        s: u32,
        t: u32,
        u: u32,
        d: u32,
        l: u32,
    ) -> Self {
        let lower_mask = (1 << r) - 1;
        let upper_mask = !lower_mask;
        Self {
            w: 32,
            n,
            m,
            a,
            b,
            c,
            s,
            t,
            u,
            d,
            l,
            mt: vec![0; n],
            index: n + 1,
            lower_mask,
            upper_mask,
        }
    }

    #[must_use]
    pub fn new_mt19937() -> Self {
        Self::new(
            624,
            397,
            31,
            0x9908_B0DF,
            0x9D2C_5680,
            0xEFC6_0000,
            7,
            15,
            11,
            0xFFFF_FFFF,
            18,
        )
    }

    pub fn seed(&mut self, f: u32, seed: u32) {
        self.index = self.n;
        self.mt[0] = seed;
        for i in 1..self.n {
            self.mt[i] = f
                .wrapping_mul(self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2)))
                .wrapping_add(u32::try_from(i).unwrap());
        }
    }

    pub fn next(&mut self) -> Option<u32> {
        if self.index >= self.n {
            if self.index > self.n {
                return None;
            }
            self.twist();
        }

        let mut y = self.mt[self.index];
        y ^= (y >> self.u) & self.d;
        y ^= (y << self.s) & self.b;
        y ^= (y << self.t) & self.c;
        y ^= y >> self.l;
        self.index += 1;
        Some(y)
    }

    fn twist(&mut self) {
        for i in 0..self.n {
            let x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.n] & self.lower_mask);
            let mut xa = x >> 1;
            if x % 2 != 0 {
                xa ^= self.a;
            }
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xa;
        }
        self.index = 0;
    }
}

fn reverse_left(y: u32, shift: u32, mask: u32) -> u32 {
    let w = 32;
    let mut y_ = 0;
    (shift..w)
        .step_by(usize::try_from(shift).unwrap())
        .for_each(|i| {
            let m = 2u32.pow(i) - 1;
            y_ = (y ^ ((y_ << shift) & mask)) & m;
        });
    y_ = y ^ ((y_ << shift) & mask);
    y_
}

fn reverse_right(y: u32, shift: u32, mask: u32) -> u32 {
    let w = 32;
    let mut y_ = 0;
    (shift..w)
        .step_by(usize::try_from(shift).unwrap())
        .for_each(|i| {
            let m = (2u32.pow(i) - 1) << (w - i);
            y_ = (y ^ ((y_ >> shift) & mask)) & m;
        });
    y_ = y ^ ((y_ >> shift) & mask);
    y_
}

#[must_use]
pub fn clone_mt19937(y: &[u32]) -> MersenneTwister {
    let mut mt = MersenneTwister::new_mt19937();
    assert_eq!(y.len(), mt.n);
    mt.index = 0;
    while mt.index < mt.n {
        let mut yi = y[mt.index];
        yi = reverse_right(yi, mt.l, 0xFFFF_FFFF);
        yi = reverse_left(yi, mt.t, mt.c);
        yi = reverse_left(yi, mt.s, mt.b);
        yi = reverse_right(yi, mt.u, mt.d);
        mt.mt[mt.index] = yi;
        mt.index += 1;
    }
    mt
}
