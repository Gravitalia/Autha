use crate::helpers::random_string;
use crate::{
    database::{
        mem::{del, get, set, MemPool, SetValue::Characters},
        scylla::{create_oauth, query},
    },
    helpers,
};
use anyhow::{anyhow, Result};
use warp::reply::{Json, WithStatus};

// Set rust queries
const GET_BOT: &str = "SELECT flags, deleted, redirect_url, client_secret FROM accounts.bots WHERE id = ?;";
const GET_OAUTH: &str =
    "SELECT id, bot_id FROM accounts.oauth WHERE user_id = ?";

/// Handle post request for /oauth
pub async fn post(
    memcached: MemPool,
    body: crate::model::body::OAuth,
    token: String,
) -> Result<WithStatus<Json>> {
    let middelware_res = crate::router::middleware(Some(token), "Invalid")
        .await
        .unwrap_or_else(|_| "Invalid".to_string());

    let vanity = if middelware_res != "Invalid" && middelware_res != "Suspended"
    {
        middelware_res.to_lowercase()
    } else {
        return Ok(warp::reply::with_status(
            warp::reply::json(&crate::model::error::Error {
                error: true,
                message: "Invalid token".to_string(),
            }),
            warp::http::StatusCode::UNAUTHORIZED,
        ));
    };

    let bot = query(GET_BOT, vec![body.bot_id.clone()])
        .await?
        .rows
        .unwrap_or_default();

    // Check if bot exists or deleted
    if bot.is_empty() {
        return Ok(super::err("Invalid bot_id".to_string()));
    } else if bot[0].columns[1]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_boolean()
        .ok_or_else(|| anyhow!("Can't convert to bool"))?
    {
        return Ok(super::err("This bot has been deleted".to_string()));
    }

    // Check if the redirect_url is valid
    if !bot[0].columns[2]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_set()
        .ok_or_else(|| anyhow!("Can't convert to vec"))?
        .to_vec()
        .iter()
        .any(|x| {
            x.as_text()
                .ok_or_else(|| anyhow!("Can't convert to string"))
                .unwrap()
                == &body.redirect_uri[..]
        })
    {
        return Ok(super::err("Invalid redirect_uri".to_string()));
    }

    // If empty, tries to find a valid code
    if body.response_type.is_empty() {
        let res = query(GET_OAUTH, vec![vanity.clone()])
            .await?
            .rows
            .unwrap_or_default();

        if res.is_empty() {
            Ok(super::err("".to_string()))
        } else {
            if res
                .iter()
                .filter(|x| {
                    *x.columns[1]
                        .as_ref()
                        .ok_or_else(|| anyhow!("No reference"))
                        .unwrap()
                        .as_text()
                        .ok_or_else(|| anyhow!("Can't convert to string"))
                        .unwrap()
                        == body.bot_id
                })
                .map(|x| {
                    x.columns[0]
                        .as_ref()
                        .ok_or_else(|| anyhow!("No reference"))
                        .unwrap()
                        .as_text()
                        .ok_or_else(|| anyhow!("Can't convert to string"))
                        .unwrap()
                        .to_string()
                })
                .collect::<String>()
                .is_empty()
            {
                return Ok(super::err("".to_string()));
            }

            let id = random_string(24);
            let _ = set(
                &memcached,
                id.clone(),
                Characters(format!(
                    "{}+{}+{}",
                    body.bot_id, body.redirect_uri, vanity
                )),
            );

            Ok(warp::reply::with_status(
                warp::reply::json(&crate::model::error::Error {
                    error: false,
                    message: id,
                }),
                warp::http::StatusCode::OK,
            ))
        }
    } else if body
        .scope
        .split_whitespace()
        .filter(|x| !["identity" /*, "private" */].contains(x))
        .any(|_| true)
    {
        Ok(super::err("Invalid scope".to_string()))
    } else {
        let id = random_string(24);
        let _ = set(
            &memcached,
            id.clone(),
            Characters(format!(
                "{}+{}+{}+{}",
                body.bot_id, body.redirect_uri, vanity, body.scope
            )),
        );

        Ok(warp::reply::with_status(
            warp::reply::json(&crate::model::error::Error {
                error: false,
                message: id,
            }),
            warp::http::StatusCode::OK,
        ))
    }
}

/// Handle JWT creation, code deletation
pub async fn get_oauth_code(
    memcached: MemPool,
    body: crate::model::body::GetOAuth,
) -> Result<WithStatus<Json>> {
    let data = match get(&memcached, body.code.clone()).unwrap() {
        Some(r) => Vec::from_iter(r.split('+').map(|x| x.to_string())),
        None => vec![],
    };
    if data.is_empty() {
        return Ok(super::err("Invalid code".to_string()));
    }
    let user_id = &data[2];

    if *data[0] != body.client_id {
        return Ok(super::err("Invalid client_id".to_string()));
    }

    if data[3]
        .split_whitespace()
        .filter(|x| !["identity" /*, "private" */].contains(x))
        .any(|_| true)
    {
        return Ok(super::err("Invalid scope".to_string()));
    }

    let bot = query(GET_BOT, vec![body.client_id.clone()])
        .await?
        .rows
        .unwrap_or_default();

    // Check if bot exists or deleted
    if bot.is_empty() {
        return Ok(super::err("Invalid client_id".to_string()));
    } else if bot[0].columns[1]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_boolean()
        .ok_or_else(|| anyhow!("Can't convert to bool"))?
    {
        return Ok(super::err("This bot has been deleted".to_string()));
    }
    // Check if the redirect_url is valid
    if !bot[0].columns[2]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_set()
        .ok_or_else(|| anyhow!("Can't convert to vec"))?
        .to_vec()
        .iter()
        .any(|x| {
            x.as_text()
                .ok_or_else(|| anyhow!("Can't convert to string"))
                .unwrap()
                == &body.redirect_uri[..]
        })
    {
        return Ok(super::err("Invalid redirect_uri".to_string()));
    }
    // Check if client_secret is valid
    if *bot[0].columns[3]
        .as_ref()
        .ok_or_else(|| anyhow!("No reference"))?
        .as_text()
        .ok_or_else(|| anyhow!("Can't convert to string"))?
        != body.client_secret
    {
        return Ok(super::err("Invalid client_secret".to_string()));
    }

    // Delete used key
    let _ = del(&memcached, body.code);

    // Create JWT & OAuth
    let jwt = helpers::jwt::create_jwt(
        user_id.to_string(),
        data[3].split_whitespace().map(|x| x.to_string()).collect(),
    );
    create_oauth(
        jwt.clone(),
        user_id.to_string(),
        body.client_id.clone(),
        data[3].split_whitespace().map(|x| x.to_string()).collect(),
    )
    .await;

    Ok(warp::reply::with_status(
        warp::reply::json(&crate::model::error::Error {
            error: false,
            message: jwt,
        }),
        warp::http::StatusCode::CREATED,
    ))
}
