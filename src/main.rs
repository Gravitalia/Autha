use warp::Filter;
mod router;
mod helpers;
mod database;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let routes = warp::path!("create").and(warp::post()).and(warp::body::json()).and(warp::header("sec")).map(router::create::create);

    database::cassandra::init().await;
    database::cassandra::tables().await;

    warp::serve(routes)
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}