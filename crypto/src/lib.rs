pub mod decrypt;
pub mod encrpt;
pub mod hash;

use rand::rngs::OsRng;
use rand::Rng;

/// Generate random string with thread-local cryptographically-secure PRNG seeded from the system's entropy pool.
pub fn random_string(length: usize) -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&"
        .chars()
        .collect();
    let mut result = String::with_capacity(length);
    let mut rng = OsRng;

    for _ in 0..length {
        result.push(chars[rng.gen_range(0..62)]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_string() {
        let str = random_string(20);
        assert_eq!(str.len(), 20);
        assert_eq!(
            regex::Regex::new(
                r"[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_%?!&]*"
            )
            .unwrap()
            .find_iter(&str)
            .count(),
            1
        );
    }
}
