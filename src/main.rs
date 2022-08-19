use warp::Filter;
mod router;
mod helpers;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let routes = warp::path!("create").and(warp::post()).and(warp::body::json()).and(warp::header("sec")).map(router::create);

    warp::serve(routes)
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}