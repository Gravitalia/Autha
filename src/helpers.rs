use argon2::{self, Config, ThreadMode, Variant, Version};
use regex::Regex;

pub fn random_string() -> String {
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".chars().collect();
    let mut result = String::new();

    unsafe {
        for _ in 0..9 {
            result.push(
                *chars.get_unchecked(fastrand::usize(0..62))
            );
        }
    }

    result
}

pub fn hash(password: &[u8]) -> String {
    argon2::hash_encoded(
        password,
        random_string().as_bytes(),
        &Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: 32768,
            time_cost: 7,
            lanes: 8,
            thread_mode: ThreadMode::Parallel,
            secret: "QXAwOSjEPui2WxEyH5P38b4icbwFYx4Sd23gbOsDooOZbYTsSYsdsA0Mu_wXQ3LWacGrzs1xX7iXEoh9Z4Z8tVIuwlzo5bIGWJJcY_".as_bytes(),
            ad: &[],
            hash_length: 32
        }
    ).unwrap()
}

#[test]
fn test_hash() {
    assert!(Regex::new(r"[$]argon2(i)?(d)?[$]v=[0-9]{1,2}[$]m=[0-9]+,t=[0-9]{1,},p=[0-9]{1,}[$].*").unwrap().is_match(&hash("password".as_bytes())));
}