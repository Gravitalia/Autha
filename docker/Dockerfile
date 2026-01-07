FROM --platform=$BUILDPLATFORM rust:alpine AS builder

ARG TARGETARCH

RUN USER=root cargo new --bin autha
WORKDIR /autha

ENV     RUSTFLAGS="-Ctarget-feature=+crt-static"
RUN     apk add -q --update-cache --no-cache \
            build-base \
            openssl-dev \
            musl \
            pkgconfig \
            protobuf-dev

COPY ./Cargo.toml   ./Cargo.toml
COPY ./Cargo.lock   ./Cargo.lock
COPY ./src          ./src
COPY ./migrations  ./migrations
COPY ./.sqlx        ./.sqlx

RUN case "$TARGETARCH" in \
      "arm64") TARGET="aarch64-unknown-linux-musl" ;; \
      "amd64") TARGET="x86_64-unknown-linux-musl" ;; \
      *) echo "Unsupported architecture \"$TARGETARCH\"" && exit 1 ;; \
    esac && \
    cargo build --release --target $TARGET && \
    cp target/$TARGET/release/autha /autha/target/release/

FROM gcr.io/distroless/static-debian12

COPY --from=builder /autha/migrations  /bin/migrations
COPY --from=builder /autha/target/release/autha /bin/autha
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/bin/autha"]