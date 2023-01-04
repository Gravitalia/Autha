mod model;
mod router;
use warp::{Filter, reject::Reject};

#[derive(Debug)]
struct UnknownError;
impl Reject for UnknownError {}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let routes = warp::path("create").and(warp::post()).and(warp::body::json()).and(warp::header("cf-turnstile-token")).and_then(|body: model::Body::Create, _cf_token: String| async {
        match router::create::create(body).await {
            Ok(r) => {
                Ok(r)
            },
            Err(_) => {
                Err(warp::reject::custom(UnknownError))
            }
        }
    });

    warp::serve(warp::any().and(warp::options()).map(|| "OK").or(warp::head().map(|| "OK"))).or(routes)
    .run((
        [127, 0, 0, 1],
        dotenv::var("PORT").expect("Missing env `PORT`").parse::<u16>().unwrap(),
    ))
    .await;
}