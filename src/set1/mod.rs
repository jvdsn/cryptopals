#[cfg(test)]
mod tests {
    use crate::shared::conversion::{base64_to_bytes, bytes_to_base64, bytes_to_hex, hex_to_bytes};
    use crate::shared::xor::{frequency_analysis, xor};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    #[test]
    fn test_challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let bytes = hex_to_bytes(hex).unwrap();
        let base64 = bytes_to_base64(&bytes);
        assert_eq!(
            base64,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );

        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let bytes = base64_to_bytes(base64).unwrap();
        let hex = bytes_to_hex(&bytes);
        assert_eq!(
            hex,
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        );
    }

    #[test]
    fn test_challenge_2() {
        let a = hex_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
        let b = hex_to_bytes("686974207468652062756c6c277320657965").unwrap();
        assert_eq!(
            bytes_to_hex(&xor(&a, &b)),
            "746865206b696420646f6e277420706c6179"
        );
    }

    #[test]
    fn test_challenge_3() {
        let ct =
            hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();
        let (_, _, pt) = frequency_analysis(&ct).unwrap();
        assert_eq!(pt, b"Cooking MC's like a pound of bacon")
    }

    #[test]
    fn test_challenge_4() {
        assert!(
            BufReader::new(File::open("src/set1/challenge4.txt").unwrap())
                .lines()
                .filter_map(|line| line.ok())
                .filter_map(|line| frequency_analysis(&hex_to_bytes(&line).unwrap()))
                .any(|(_, _, pt)| pt == b"Now that the party is jumping\n")
        );
    }
}
