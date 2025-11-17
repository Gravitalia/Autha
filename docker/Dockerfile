FROM rust:alpine AS builder

ARG TARGETPLATFORM
RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") rustup target add aarch64-unknown-linux-musl ;; \
    "linux/amd64") rustup target add x86_64-unknown-linux-musl ;; \
    *) echo "${TARGETPLATFORM} is not supported." && exit 1 ;; \
esac

RUN USER=root cargo new --bin autha
WORKDIR /autha

ENV     RUSTFLAGS="-Ctarget-feature=+crt-static"
RUN     apk add -q --update-cache --no-cache build-base openssl-dev musl pkgconfig protobuf-dev

COPY ./Cargo.toml   ./Cargo.toml
COPY ./Cargo.lock   ./Cargo.lock
COPY ./src          ./src
COPY ./migrations  ./migrations
COPY ./.sqlx        ./.sqlx

RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") cargo build --release --target aarch64-unknown-linux-musl ;; \
    "linux/amd64") cargo build --release --target x86_64-unknown-linux-musl ;; \
    *) echo "${TARGETPLATFORM} is not supported." && exit 1 ;; \
esac

RUN case "${TARGETPLATFORM}" in \
    "linux/arm64") mv /autha/target/aarch64-unknown-linux-musl/release/autha /autha/target/release/ ;; \
    "linux/amd64") mv /autha/target/x86_64-unknown-linux-musl/release/autha /autha/target/release/ ;; \
    *) echo "${TARGETPLATFORM} is not supported." && exit 1 ;; \
esac

FROM gcr.io/distroless/static-debian12

COPY --from=builder /autha/migrations  /bin/migrations
COPY --from=builder /autha/target/release/autha /bin/autha
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/bin/autha"]