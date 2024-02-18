use serde::Deserialize;

/// Represents the query structure for creating a new authorization token.
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct OAuth {
    /// Application (bot) vanity/unique identifier.
    pub client_id: String,
    /// PKCE `code_verifier` hashed with SHA256.
    pub code_challenge: Option<String>,
    /// PKCE hashing method. Only support `S256` (sha256).
    pub code_challenge_method: Option<String>,
    /// Name of a query string parameter where the token is returned.
    response_type: String,
    /// Redirect URL to be followed by the user.
    pub redirect_uri: String,
    /// Bot access granted by the user.
    pub scope: String,
    /// Protect from CSRF.
    pub state: Option<String>,
}
