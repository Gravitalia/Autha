use serde::Deserialize;

/// Represents the query structure for creating new authorization token.
#[derive(Deserialize)]
pub struct OAuth {
    /// Application (bot) vanity/unique identifier.
    pub client_id: String,
    /// Bot access granted by the user.
    pub scope: String,
    /// Redirect URL to be followed by the user.
    pub redirect_uri: String,
    /// PKCE hashing method. Only support `S256` (sha256).
    pub code_challenge_method: Option<String>,
    /// PKCE`code_verifier` hashed with SHA256.
    pub code_challenge: Option<String>,
}
