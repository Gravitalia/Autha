use warp::Filter;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let routes = warp::path("").map(|| "test");

    warp::serve(warp::any().and(warp::options()).map(|| "OK").or(warp::head().map(|| "OK"))).or(routes)
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}