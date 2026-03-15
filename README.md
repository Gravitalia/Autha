Autha
=====

Autha is an account management server designed for decentralized
identities and infrastructures. It provides a security-first
approach centered on PKI, public key distribution, and client-side
token generation, rather than traditional server-issued session tokens.

---

It implements several widely adopted standards:
  * Human-readable errors (RFC 7807);
  * Support multi-factor authentication via TOTP (RFC 6238);
  * Support WebFinger (RFC 7033);
  * Support LDAP (RFC 4511);
  * Support JWK (RFC 7517);
  * Partial OpenID Connect support (ES256 only).

> [!WARNING]
> Telemetry (tracing, logging and metrics) is also included using OTLP.
> Although, telemetry is deactivable(1) to increase anonymity.

## Security Model

Autha allows users to create, update, and delete accounts, register and
revoke public keys and generate authentication tokens **client-side**.

If a private key is compromised, the corresponding public key can be revoked
and immediately removed from the set distributed by Autha.

Autha integrates **WebAuthn**, leveraging native hardware security (TPM, HSM,
YubiKey, etc.)

As a consequence, the security of private keys ultimately depends on the
guarantees provided by the underlying hardware and platform vendors (Big Tech).
Not you. Not us.

## Documentation

See documentation ([gravitalia.github.io/Autha](https://gravitalia.github.io/Autha
)) for more settings.

## Deployment

You can deploy Autha using Docker.
[Example](https://github.com/Gravitalia/Autha/tree/master/docker).

## License

Licensed under [BSD](https://github.com/Gravitalia/Autha/blob/master/LICENSE).

(1) Simply remove OpenTelemetry (OTLP) from `compose.yaml`.
