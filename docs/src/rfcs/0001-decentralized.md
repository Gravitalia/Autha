## 1. Introduction

Autha is a decentralized authentication system that enables users to authenticate themselves using asymmetric cryptographic keys via WebAuthn. Users are responsible for securely storing and managing their own private keys.

Autha's role is limited to publishing the users’ corresponding public keys in a verifiable and accessible manner.

### 1.2 Impact

Any system implementing Autha **MUST** support user authentication regardless of the specific instance used. In particular, a user **MUST** be able to authenticate from any Autha-compatible instance, provided their public key is available and their private key is valid.

This ensures cross-instance interoperability and preserves the decentralized nature of the authentication mechanism.

## 2. Schema

### 2.1 User Identifier (User ID)

Each user is identified by a unique and stable identifier, referred to as the **User ID**.

A User ID **MUST** follow the format:

```
<vanity>@<server-domain>
```

For example: `alice@auth.example.com`.

- `vanity`: A user-chosen identifier (MAY be pseudonymous).
- `server-domain`: The domain of the Autha-compatible server that exposes the user's public identity.

A User **MUST** have exactly one User ID, and this identifier **MUST** remain consistent across all Autha operations.

### 2.2 Server

Server exposes user as specified on [ActivityPub](https://www.w3.org/TR/activitypub/) format.

### 2.3 Keys

An Autha-compatible server **MUST NOT** store or have access to any private key. It **MUST ONLY** store and expose public keys associated with a given user.

A user **MAY** have multiple active public keys (e.g., to support multiple devices or key rotations). Each key **MUST** be uniquely identifiable and linked to the owning User ID.

The `/users/:USER_ID` endpoint **MUST** return public keys using the following JSON structure:

```json
[
  {
    "id": "0000",
    "owner": "alice@auth.example.com",
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "created_at": "YYYY-MM-DD"
  },
  ...
]
```

- `id`: A unique identifier for the public key.
- `owner`: The associated User ID.
- `public_key_pem`: The public key in PEM format.
- `created_at`: ISO 8601 date when the key was created or registered.