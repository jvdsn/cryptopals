const HEX_ENCODE: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

const HEX_DECODE: [u8; 256] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10, 11, 12, 13, 14, 15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10, 11, 12, 13, 14, 15, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

const BASE64_ENCODE: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

const BASE64_DECODE: [u8; 256] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 62, 0xFF, 0xFF, 0xFF, 63, 52,
    53, 54, 55, 56, 57, 58, 59, 60, 61, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(2 * bytes.len());
    let mut iter = bytes.iter();
    let mut i = 0;
    while i < bytes.len() {
        i += 1;
        let b = iter.next().unwrap();
        (0..2).for_each(|j| {
            hex.push(HEX_ENCODE[usize::try_from((b >> ((1 - j) * 4)) % 16).unwrap()]);
        });
    }
    hex
}

#[must_use]
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut iter = hex.bytes();
    let mut i = 0;
    while i < hex.len() {
        let mut byte = 0;
        for j in 0..2 {
            i += 1;
            match iter.next() {
                Some(b) => {
                    let b = HEX_DECODE[usize::try_from(b).unwrap()];
                    if b == 0xFF {
                        // The character is an invalid hex character.
                        return None;
                    }
                    byte += b << ((1 - j) * 4);
                }
                // Not enough characters in the hex string.
                None => return None,
            }
        }
        bytes.push(byte);
    }
    Some(bytes)
}

#[must_use]
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let mut base64 = String::with_capacity(4 * ((bytes.len() + 2) / 3));
    let mut iter = bytes.iter();
    let mut i = 0;
    while i < bytes.len() {
        let mut triple = 0;
        let mut j = 0;
        while j < 3 {
            i += 1;
            match iter.next() {
                Some(&b) => triple += u32::from(b) << ((2 - j) * 8),
                // Break early to allow for padding.
                None => break,
            }
            j += 1;
        }

        let mut k = 0;
        while k < j + 1 {
            base64.push(BASE64_ENCODE[usize::try_from((triple >> ((3 - k) * 6)) % 64).unwrap()]);
            k += 1;
        }
        while k < 4 {
            base64.push('=');
            k += 1;
        }
        if j != 3 {
            // Break early because the string is padded.
            break;
        }
    }

    base64
}

#[must_use]
pub fn base64_to_bytes(base64: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(3 * (base64.len() / 4));
    let mut iter = base64.bytes();
    let mut i = 0;
    while i < base64.len() {
        let mut triple = 0;
        let mut k = 0;
        while k < 4 {
            i += 1;
            match iter.next() {
                Some(b) => {
                    if b == b'=' {
                        // The character is a padding character, so assume we're at the end.
                        break;
                    }
                    let b = BASE64_DECODE[usize::try_from(b).unwrap()];
                    if b == 0xFF {
                        // The character is an invalid hex character.
                        return None;
                    }
                    triple += u32::from(b) << ((3 - k) * 6);
                }
                // Not enough characters in the base64 string.
                None => return None,
            }
            k += 1;
        }

        let mut j = 0;
        while j < k - 1 {
            bytes.push(u8::try_from((triple >> ((2 - j) * 8)) % 256).unwrap());
            j += 1;
        }
        if j != 3 {
            // Break early because we found the padding.
            break;
        }
    }

    Some(bytes)
}
