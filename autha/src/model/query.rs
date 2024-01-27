use serde::Deserialize;

/// Represents the query structure for creating new authorization token.
#[derive(Deserialize)]
pub struct OAuth {
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
}
