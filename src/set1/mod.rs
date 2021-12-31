#[cfg(test)]
mod tests {
    use crate::shared::conversion::{base64_to_bytes, bytes_to_base64, bytes_to_hex, hex_to_bytes};

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
}
