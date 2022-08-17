mod model;

pub fn create(body: model::Create) -> String {
    println!("{}", body.username);
    "test".to_string()
}