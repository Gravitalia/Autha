# Session tokens

When the user creates their account or logs in, a pair of tokens is created.
The session token is a 15-minute [JWT](https://datatracker.ietf.org/doc/html/rfc7519).
The second is a refresh token (64 alphanumeric characters) valid for 15 days.

Refresh token allows you to obtain a new JWT and refresh token.
Each new JWT created invalidates the old refresh token.

Add in `config.yaml` following code:
```yaml
token:
  key_id: fixed_string_for_this_key
  private_key_pem: |-
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgg8wQwttCoiBA9yQZ
    Uo+lImtpakc48rw9mHTPhD6k5A+hRANCAATkZYzb0mgzeeckNkE2dKlwX9zxW9Qz
    4JtlLQH76IOhXNObDGrsrsEeo5KDCQe1rrkYT/mTNuWepEEotRd4DRvf
    -----END PRIVATE KEY-----
  public_key_pem: |-
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5GWM29JoM3nnJDZBNnSpcF/c8VvU
    M+CbZS0B++iDoVzTmwxq7K7BHqOSgwkHta65GE/5kzblnqRBKLUXeA0b3w==
    -----END PUBLIC KEY-----
```

| Parameter           | Description                                               |
|---------------------|-----------------------------------------------------------|
| `key_id`            | JWK ID. Public key retrieving for signature verficiation. |
| `private_key_pem`*  | Private key to sign JWTs. NEVER SHARE IT.                 |
| `public_key_pem`*   | Public key for signature verficiation.                    |

\* Key **MUST** be ES256.

If your Autha instance is distributed, use a signature key pair for each container.