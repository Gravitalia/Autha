use argon2::{self, Config, ThreadMode, Variant, Version};

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

pub fn psw_hash(password: &[u8]) -> String {
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 32768,
        time_cost: 3,
        lanes: 8,
        thread_mode: ThreadMode::Parallel,
        secret: "QXAwOSjEPui2WxEyH5P38b4icbwFYx4Sd23gbOsDooOZbYTsSYsdsA0Mu_wXQ3LWacGrzs1xX7iXEoh9Z4Z8tVIuwlzo5bIGWJJcY_".as_bytes(),
        ad: &[],
        hash_length: 32
    };

    argon2::hash_encoded(password, random_string().as_bytes(), &config).unwrap()
}