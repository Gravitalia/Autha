FROM rust:alpine AS builder

RUN USER=root cargo new --bin autha
WORKDIR /autha

ENV     RUSTFLAGS="-Ctarget-feature=-crt-static"
RUN     apk add -q --update-cache --no-cache build-base openssl-dev musl pkgconfig protobuf-dev

COPY ./Cargo.toml   ./Cargo.toml
COPY ./Cargo.lock   ./Cargo.lock
COPY ./src          ./src
COPY ./migrations  ./migrations
COPY ./.sqlx        ./.sqlx

RUN cargo build --release 

FROM alpine:3 AS runtime

RUN apk add --no-cache libgcc

RUN addgroup -S appgroup && adduser -S rust -G appgroup
USER rust

COPY --from=builder /autha/migrations  /bin/migrations
COPY --from=builder /autha/target/release/autha /bin/autha

CMD ["./bin/autha"]
