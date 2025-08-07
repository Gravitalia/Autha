FROM rust:slim AS builder

RUN  apt-get update && apt-get install -y \
      build-essential \
      pkg-config \
      libssl-dev \
      musl-tools \
      curl

WORKDIR   /autha
COPY     ./Cargo.toml ./Cargo.toml
COPY     ./Cargo.lock ./Cargo.lock
COPY     ./src        ./src
COPY     ./.sqlx      ./.sqlx

RUN  rustup target add x86_64-unknown-linux-musl
ENV  RUSTFLAGS="-Ctarget-feature=+crt-static -Ctarget-cpu=native"
RUN  cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /autha/target/x86_64-unknown-linux-musl/release/autha /bin/autha

CMD ["./bin/autha"]
