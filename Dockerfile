FROM rust:1.69-slim-buster as build

RUN USER=root cargo new --bin autha
WORKDIR /autha

COPY ./Cargo.toml ./Cargo.toml

RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config protobuf-compiler

RUN rustup target add x86_64-unknown-linux-musl

RUN cargo build --target x86_64-unknown-linux-musl --release \
 && rm src/*.rs

COPY ./src ./src
COPY ./proto ./proto
COPY ./build.rs ./build.rs

RUN rm ./target/release/deps/autha* \
 && cargo build --target x86_64-unknown-linux-musl --release

FROM debian:latest

COPY --from=build /autha/target/release/autha .

EXPOSE 1111
CMD ["./autha"]
