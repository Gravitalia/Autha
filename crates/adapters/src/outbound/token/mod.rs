//! Token adapter.

pub mod jwt;
mod refresh;

use application::ports::outbound::{RefreshTokenManager, Token, TokenSigner};
pub use jwt::TokenSigner as AdapterTokenSigner;
pub use refresh::SecureRefreshTokenManager;

/// `Token` port.
pub struct TokenAdapter {
    signer: AdapterTokenSigner,
    refresh: SecureRefreshTokenManager,
}

impl TokenAdapter {
    /// Create a new [`TokenAdapter`].
    pub fn new(
        signer: AdapterTokenSigner,
        refresh: SecureRefreshTokenManager,
    ) -> Self {
        Self { signer, refresh }
    }
}

impl Token for TokenAdapter {
    fn signer(&self) -> &dyn TokenSigner {
        &self.signer
    }

    fn refresh_token(&self) -> &dyn RefreshTokenManager {
        &self.refresh
    }
}
