use std::ops::Add;

#[allow(clippy::approx_constant)]
const LETTER_FREQUENCIES: [f64; 26] = [
    8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61, 6.95, 7.68,
    1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07,
];
const N: f64 = 182_303.0;

#[must_use]
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

#[must_use]
pub fn xor_with_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    (0..bytes.len())
        .map(|i| bytes[i] ^ key[i % key.len()])
        .collect()
}

#[must_use]
pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    xor(a, b).iter().map(|x| x.count_ones()).fold(0, u32::add)
}

#[must_use]
pub fn score(pt: &[u8], floor: f64) -> Option<f64> {
    // ASCII graphic and whitespace only.
    if !pt
        .iter()
        .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        return None;
    }

    Some(pt.iter().fold(0.0, |score, b| {
        if b.is_ascii_alphabetic() {
            let b = b.to_ascii_lowercase();
            let i = b - (b'a');
            assert!(i <= 26);
            score + LETTER_FREQUENCIES[usize::from(i)].log10()
        } else {
            score + floor
        }
    }))
}

#[must_use]
pub fn frequency_analysis(ct: &[u8]) -> Option<(f64, u8, Vec<u8>)> {
    let floor = (0.01 / N).log10();
    (0..=255)
        .map(|key| (key, xor_with_key(ct, &[key])))
        .filter_map(|(key, pt)| score(&pt, floor).map(|score| (score, key, pt)))
        .max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap())
}

#[must_use]
pub fn guess_key_sizes(ct: &[u8], max_key_size: usize) -> Vec<usize> {
    let mut key_sizes = (2..=max_key_size)
        .map(|key_size| {
            let mut distance = 0;
            let mut i = 0;
            while (i + 2) * key_size < ct.len() {
                distance += hamming_distance(
                    &ct[i * key_size..(i + 1) * key_size],
                    &ct[(i + 1) * key_size..(i + 2) * key_size],
                );
                i += 2;
            }

            let normalized_distance =
                f64::from(distance) / f64::from(u32::try_from(i / 2 * key_size).unwrap());
            (key_size, normalized_distance)
        })
        .collect::<Vec<(usize, f64)>>();
    key_sizes.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap());
    key_sizes
        .into_iter()
        .map(|(key_size, _)| key_size)
        .collect()
}

#[must_use]
pub fn transpose(ct: &[u8], key_size: usize, offset: usize) -> Vec<u8> {
    let mut transposed = Vec::new();
    let mut i = 0;
    while i + offset < ct.len() {
        transposed.push(ct[i + offset]);
        i += key_size;
    }
    transposed
}

#[must_use]
pub fn break_xor_with_key(ct: &[u8], max_key_size: usize) -> Option<Vec<u8>> {
    guess_key_sizes(ct, max_key_size)
        .into_iter()
        .find_map(|key_size| {
            let mut key = Vec::with_capacity(key_size);
            for offset in 0..key_size {
                let transposed = transpose(ct, key_size, offset);
                match frequency_analysis(&transposed) {
                    Some((_, k, _)) => key.push(k),
                    None => return None,
                }
            }
            Some(key)
        })
}
