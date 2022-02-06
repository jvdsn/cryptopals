use std::collections::HashMap;

#[must_use]
pub fn parse_key_value(input: &str) -> HashMap<String, String> {
    input
        .split('&')
        .map(|s| {
            let index = s.chars().position(|c| c == '=').unwrap();
            (s[..index].to_owned(), s[index + 1..].to_owned())
        })
        .collect()
}
