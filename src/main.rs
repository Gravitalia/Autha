use warp::Filter;
mod router;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let routes = warp::path!("create").and(warp::post()).map(router::create);

    warp::serve(routes)
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}