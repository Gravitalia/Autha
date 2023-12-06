FROM rust:alpine3.18 AS builder

RUN USER=root cargo new --bin autha
WORKDIR /autha

ENV     RUSTFLAGS="-C target-feature=-crt-static"
RUN     apk add -q --update-cache --no-cache build-base openssl-dev musl pkgconfig protobuf-dev

COPY ./Cargo.toml ./Cargo.toml
COPY ./autha ./autha
COPY ./crypto ./crypto
COPY ./db ./db
#COPY ./build.rs ./build.rs

RUN cargo build --release

FROM alpine:3.18 AS runtime

COPY --from=builder /autha/target/release/autha /bin/autha

EXPOSE 1111/tcp
CMD     ["./bin/autha"]
