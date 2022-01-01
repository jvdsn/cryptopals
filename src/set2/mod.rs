#[cfg(test)]
mod tests {
    use crate::shared::padding::pad_pkcs7;

    #[test]
    fn test_challenge_9() {
        let bytes = b"YELLOW SUBMARINE";
        assert_eq!(pad_pkcs7(bytes, 20), b"YELLOW SUBMARINE\x04\x04\x04\x04")
    }
}
