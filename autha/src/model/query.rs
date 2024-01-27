use serde::Deserialize;

/// Represents the query structure for creating new authorization token.
#[derive(Deserialize)]
pub struct OAuth {
    /// Application (bot) vanity/unique identifier.
    pub client_id: String,
    /// Redirect URL to be followed by the user.
    pub redirect_uri: String,
    /// Bot access granted by the user.
    pub scope: String,
}
