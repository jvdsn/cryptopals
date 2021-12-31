const LETTER_FREQUENCIES: [f64; 26] = [
    8.12, 1.49, 2.71, 4.32, 12.02, 2.30, 2.03, 5.92, 7.31, 0.10, 0.69, 3.98, 2.61, 6.95, 7.68,
    1.82, 0.11, 6.02, 6.28, 9.10, 2.88, 1.11, 2.09, 0.17, 2.11, 0.07,
];
const N: f64 = 182_303.0;

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn xor_with_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    (0..bytes.len())
        .map(|i| bytes[i] ^ key[i % key.len()])
        .collect()
}

pub fn score(pt: &[u8], floor: f64) -> Option<f64> {
    // ASCII graphic and whitespace only.
    if !pt
        .iter()
        .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        return None;
    }

    let score = pt.iter().fold(0.0, |score, b| {
        if b.is_ascii_alphabetic() {
            let b = b.to_ascii_lowercase();
            let i = b - (b'a');
            assert!(i <= 26);
            score + LETTER_FREQUENCIES[usize::from(i)].log10()
        } else {
            score + floor
        }
    });

    Some(score)
}

pub fn frequency_analysis(ct: &[u8]) -> Option<(f64, u8, Vec<u8>)> {
    let floor = (0.01 / N).log10();
    (0..=255)
        .map(|key| (key, xor_with_key(ct, &[key])))
        .filter_map(|(key, pt)| score(&pt, floor).map(|score| (score, key, pt)))
        .max_by(|(a, _, _), (b, _, _)| a.partial_cmp(b).unwrap())
}
