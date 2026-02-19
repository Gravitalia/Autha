//! Custom validation functions for request fields.

use validator::ValidationError;

/// Validate user ID format (2-15 alphanumeric characters).
pub fn validate_user_id(id: &str) -> Result<(), ValidationError> {
    if id.len() < 2 || id.len() > 15 {
        return Err(ValidationError::new("invalid_length")
            .with_message("User ID must be 2-15 characters".into()));
    }

    if !id.chars().all(|c| c.is_alphanumeric()) {
        return Err(ValidationError::new("invalid_format")
            .with_message("User ID must be alphanumeric".into()));
    }

    Ok(())
}

/// Validate locale format (ISO 639-1).
pub fn validate_locale(locale: &str) -> Result<(), ValidationError> {
    if locale.len() != 2 {
        return Err(ValidationError::new("invalid_locale").with_message(
            "Locale must be 2-character ISO 639-1 code".into(),
        ));
    }

    if !locale.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(ValidationError::new("invalid_locale")
            .with_message("Locale must be lowercase".into()));
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

    // Require score >= 80 (strong password)
    if score < 80.0 {
        return Err(ValidationError::new("weak_password").with_message(
            "Password is too weak. Use a mix of letters, numbers, and symbols.".into(),
        ));
    }

    Ok(())
}
