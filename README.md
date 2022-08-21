<img src="https://www.gravitalia.studio/favicon.webp" width="40" />

# Autha
> Autha, pronounced `Otter` 🦦, is the service that manages user accounts and the associated delegation. ☄️

Autha is an OAuth2 server designed with **Rust** to allow extreme low resource usage, low *latency* and high request throughput.<br />
It implements an account creation, connection and authorization delegation system.

**Status**:

[![Rust build](https://github.com/Gravitalia/Autha/actions/workflows/rust.yml/badge.svg)](https://github.com/Gravitalia/Autha/actions/workflows/rust.yml) [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FGravitalia%2FAutha.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FGravitalia%2FAutha?ref=badge_shield)

## Security
> We want to guarantee our users **increased security**. This way, all users can see how we store data and also help us to improve the cryptographic systems.
- `Argon2` & `ChaCha20Poly1305` are the two hashing and cryptographic systems used
- Short expiration time (< `15 min.`)
- JWT with asymmetric key
- One-Time Usage OAuth token

#### Argon2
[Argon2id](https://en.wikipedia.org/wiki/Argon2) is a key-derivative hash function that is resistant to side-channel attacks and optimizes resistance to GPU cracking attacks.<br />
It allows us to manage the amount of memory used (normally `1GB`), the degree of parallelism as well as the number of iterations to do.

#### ChaCha20Poly1305
[ChaCha20](https://en.wikipedia.org/wiki/Salsa20) is an encryption function built around a pseudorandom function.<br />
[Poly1305](https://en.wikipedia.org/wiki/Poly1305) (MAC) allows to verify the integrity of the data as well as their veracity (authenticity).<br />
[ChaCha20Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) is an AEAD algorithm standardized by RFC. It allows to verify authenticity and confidentiality.

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FGravitalia%2FAutha.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FGravitalia%2FAutha?ref=badge_large)
