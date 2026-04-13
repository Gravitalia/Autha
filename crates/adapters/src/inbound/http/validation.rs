//! Custom validation functions for request fields.

use domain::identity::id::UserId;
use validator::ValidationError;

/// Validate user ID format (2-15 alphanumeric characters).
pub fn validate_user_id(id: &str) -> Result<(), ValidationError> {
    UserId::parse(id).map(|_| ()).map_err(|_| {
        ValidationError::new("invalid_format").with_message(
            "User ID must be 3-64 ASCII letters/digits or '_'".into(),
        )
    })
}

/// Validate locale format (ISO 639-1).
pub fn validate_locale(locale: &str) -> Result<(), ValidationError> {
    if locale.len() != 2 {
        return Err(ValidationError::new("invalid_locale").with_message(
            "Locale must be 2-character ISO 639-1 code".into(),
        ));
    }

    Ok(())
}

/// Validate password strength.
pub fn validate_password_strength(
    password: &str,
) -> Result<(), ValidationError> {
    use passwords::{analyzer, scorer};

    let analysis = analyzer::analyze(password);
    let score = scorer::score(&analysis);

    if score < 80.0 {
        return Err(ValidationError::new("weak_password").with_message(
            "Password is too weak. Use a mix of letters, numbers, and symbols.".into(),
        ));
    }

    Ok(())
}
