pub mod cassandra;
pub mod mem;

/// Tries to find a user in cache or use Cassandra database
pub fn get_user(vanity: String) -> Result<crate::model::user::User, String> {
    match mem::get(vanity.clone()).unwrap() {
        Some(data) => {
            Ok(serde_json::from_str(&data[..]).unwrap())
        },
        None => {
            let cassandra = match cassandra::query("SELECT username, avatar, bio, verified, deleted, flags FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]) {
                Ok(x) => x.get_body().unwrap().as_cols().unwrap().rows_content.clone(),
                Err(_) => {
                    return Err("Cassandra error".to_string());
                }
            };

            if cassandra.is_empty() {
                Ok(crate::model::user::User {
                    username: "".to_string(),
                    vanity:  "".to_string(),
                    avatar: None,
                    bio: None,
                    verified: false,
                    deleted: false,
                    flags: 0,
                })
            } else {
                Ok(crate::model::user::User {
                    username: std::str::from_utf8(&cassandra[0][0].clone().into_plain().unwrap()[..]).unwrap().to_string(),
                    vanity,
                    avatar: if cassandra[0][1].clone().into_plain().is_none() { None } else { let res = std::str::from_utf8(&cassandra[0][1].clone().into_plain().unwrap()[..]).unwrap_or("").to_string(); if res.is_empty() { None } else { Some(res) } },
                    bio: if cassandra[0][2].clone().into_plain().is_none() { None } else { let res = std::str::from_utf8(&cassandra[0][2].clone().into_plain().unwrap()[..]).unwrap_or("").to_string(); if res.is_empty() { None } else { Some(res) } },
                    verified: cassandra[0][3].clone().into_plain().unwrap()[..] != [0],
                    deleted: cassandra[0][4].clone().into_plain().unwrap()[..] != [0],
                    flags: u32::from_be_bytes((&cassandra[0][5].clone().into_plain().unwrap()[..])[..4].try_into().unwrap()),
                })
            }
        }
    }
}