<img src="https://avatars.githubusercontent.com/u/81774317?s=200&v=4" width="40" />

# Autha

> Autha, pronounced `Otter` 🦦, is the service that manages user accounts and provides identity (authorization server, AS).

Autha is an authorization server working with OAuth2 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)), written with Rust.
It implements account creation, management, deletation and access delegation.

Autha has been designed to be safe, fast and efficient.

**Status**:

[![Autha/bazel](https://github.com/Gravitalia/Autha/actions/workflows/bazel.yml/badge.svg)](https://github.com/Gravitalia/Autha/actions/workflows/bazel.yml) [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FGravitalia%2FAutha.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FGravitalia%2FAutha?ref=badge_shield)

## Feature highlights
- Support multi-factor authentication via TOTP ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238))
- Support telemetry ([Prometheus](https://prometheus.io/), [Jaeger](https://www.jaegertracing.io/) and Grafana [Loki](https://grafana.com/oss/loki/))

## Getting started

See our [quick starting guide](https://github.com/Gravitalia/Autha/blob/master/docs/quick_start.md) to find out how to properly set up Autha.

## License

This project is Licensed under [Mozilla Public License, Version 2.0](https://github.com/Gravitalia/Autha/blob/master/LICENSE).
