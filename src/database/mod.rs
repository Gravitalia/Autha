pub mod cassandra;
pub mod mem;

/// Tries to find a user in cache or use Cassandra database
pub async fn get_user(vanity: String) -> crate::router::model::User {
    match mem::get(vanity.clone()).unwrap() {
        Some(data) => {
            serde_json::from_str(&data[..]).unwrap()
        },
        None => {
            let cassandra = cassandra::query("SELECT username, avatar, bio, verified, deleted, flags FROM accounts.users WHERE vanity = ?", vec![vanity.clone()]).await.rows.unwrap();

            if cassandra.is_empty() {
                crate::router::model::User {
                    username: "".to_string(),
                    vanity:  "".to_string(),
                    avatar: None,
                    bio: None,
                    verified: false,
                    deleted: false,
                    flags: 0,
                }
            } else {
                crate::router::model::User {
                    username: cassandra[0].columns[0].as_ref().unwrap().as_text().unwrap().to_string(),
                    vanity,
                    avatar: if cassandra[0].columns[1].is_none() { None } else { Some(cassandra[0].columns[1].as_ref().unwrap().as_text().unwrap().to_string()) },
                    bio: if cassandra[0].columns[2].is_none() { None } else { Some(cassandra[0].columns[2].as_ref().unwrap().as_text().unwrap().to_string()) },
                    verified: if cassandra[0].columns[3].is_none() { false } else { cassandra[0].columns[3].as_ref().unwrap().as_boolean().unwrap() },
                    deleted: cassandra[0].columns[4].as_ref().unwrap().as_boolean().unwrap(),
                    flags: cassandra[0].columns[5].as_ref().unwrap().as_int().unwrap() as u32,
                }
            }
        }
    }
}