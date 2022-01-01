#[cfg(test)]
mod tests {
    use crate::shared::aes::ecb_decrypt;
    use crate::shared::conversion::{base64_to_bytes, bytes_to_base64, bytes_to_hex, hex_to_bytes};
    use crate::shared::xor::{
        break_xor_with_key, frequency_analysis, hamming_distance, xor, xor_with_key,
    };
    use std::fs::{read_to_string, File};
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

    #[test]
    fn test_challenge_5() {
        let pt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key = b"ICE";
        let ct = bytes_to_hex(&xor_with_key(pt, key));
        assert_eq!(
            ct,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }

    #[test]
    fn test_challenge_6() {
        let a = b"this is a test";
        let b = b"wokka wokka!!!";
        assert_eq!(hamming_distance(a, b), 37);

        let ct = base64_to_bytes(
            &read_to_string("src/set1/challenge6.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap();
        assert_eq!(
            break_xor_with_key(&ct, 40).unwrap(),
            b"Terminator X: Bring the noise"
        );
    }

    #[test]
    fn test_challenge_7() {
        let ct = base64_to_bytes(
            &read_to_string("src/set1/challenge7.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap();
        let key = b"YELLOW SUBMARINE";
        let pt = ecb_decrypt(&ct, key);
        assert!(pt
            .into_iter()
            .map(char::from)
            .collect::<String>()
            .starts_with("I'm back and I'm ringin' the bell \n"),)
    }
}
