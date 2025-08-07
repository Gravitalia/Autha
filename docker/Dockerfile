FROM rust:alpine AS builder

RUN USER=root cargo new --bin autha
WORKDIR /autha

ENV     RUSTFLAGS="-Ctarget-cpu=native"
RUN     apk add -q --update-cache --no-cache build-base openssl-dev musl pkgconfig

COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY ./src        ./src
COPY ./.sqlx      ./.sqlx

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /autha/target/x86_64-unknown-linux-musl/release/autha /bin/autha

CMD ["./bin/autha"]
