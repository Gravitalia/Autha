FROM rust:bookworm AS builder

ARG TARGETPLATFORM

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /autha

RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") rustup target add aarch64-unknown-linux-gnu ;; \
    "linux/amd64") rustup target add x86_64-unknown-linux-gnu ;; \
    *) echo "${TARGETPLATFORM} not supported" && exit 1 ;; \
esac

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") cargo build --release --target aarch64-unknown-linux-gnu ;; \
    "linux/amd64") cargo build --release --target x86_64-unknown-linux-gnu ;; \
    *) echo "${TARGETPLATFORM} not supported" && exit 1 ;; \
esac

RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") cp target/aarch64-unknown-linux-gnu/release/autha /autha/autha ;; \
    "linux/amd64") cp target/x86_64-unknown-linux-gnu/release/autha /autha/autha ;; \
esac


FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /autha/autha /autha
COPY --from=builder /autha/migrations /migrations

ENTRYPOINT ["/autha"]
