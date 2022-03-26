use num_bigint::BigUint;
use num_integer::Integer;
use std::ops::{Add, Mul};

#[derive(Clone)]
pub struct Interval {
    pub a: BigUint,
    pub b: BigUint,
}

impl Interval {
    #[must_use]
    pub fn new(a: BigUint, b: BigUint) -> Self {
        Interval { a, b }
    }

    #[must_use]
    pub fn overlaps(&self, other: &Interval) -> bool {
        self.a <= other.b && other.a <= self.b
    }

    pub fn merge(&mut self, other: Interval) {
        if other.a < self.a {
            self.a = other.a;
        }
        if other.b > self.b {
            self.b = other.b;
        }
    }

    pub fn narrow(&mut self, a: BigUint, b: BigUint) {
        if a > self.a {
            self.a = a;
        }
        if b < self.b {
            self.b = b;
        }
    }
}

#[allow(non_snake_case)]
pub fn insert(M: &mut Vec<Interval>, interval: Interval) {
    if let Some(i) = M.iter_mut().find(|i| i.overlaps(&interval)) {
        i.merge(interval);
    } else {
        M.push(interval);
    }
}

#[allow(non_snake_case)]
#[must_use]
pub fn step_2a<F>(padding_oracle: F, n: &BigUint, e: &BigUint, c0: &BigUint, B: &BigUint) -> BigUint
where
    F: Fn(&BigUint) -> bool,
{
    let mut s = n.div_ceil(&(B * 3u8));
    while !padding_oracle(&c0.mul(s.modpow(e, n)).mod_floor(n)) {
        s = s.add(1u8);
    }
    s
}

#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn step_2c<F>(
    padding_oracle: F,
    n: &BigUint,
    e: &BigUint,
    c0: &BigUint,
    B: &BigUint,
    s: &BigUint,
    a: &BigUint,
    b: &BigUint,
) -> BigUint
where
    F: Fn(&BigUint) -> bool,
{
    let mut r = ((b * s - B * 2u8) * 2u8).div_ceil(n);
    loop {
        let left = (B * 2u8 + &r * n).div_ceil(b);
        let right = (B * 3u8 + &r * n).div_floor(a);
        let mut s = left;
        while s <= right {
            if padding_oracle(&(c0 * s.modpow(e, n)).mod_floor(n)) {
                return s;
            }
            s = s.add(1u8);
        }
        r = r.add(1u8);
    }
}

#[allow(non_snake_case)]
#[must_use]
pub fn step_3(n: &BigUint, B: &BigUint, s: &BigUint, M: &[Interval]) -> Vec<Interval> {
    let mut M_ = Vec::new();
    M.iter().for_each(|i| {
        let left = (&i.a * s - B * 3u8 + 1u8).div_ceil(n);
        let right = (&i.b * s - B * 2u8).div_floor(n);
        let mut r = left;
        while r <= right {
            let mut interval = i.clone();
            interval.narrow(
                (B * 2u8 + &r * n).div_ceil(s),
                (B * 3u8 - 1u8 + &r * n).div_floor(s),
            );
            insert(&mut M_, interval);
            r = r.add(1u8);
        }
    });
    M_
}
