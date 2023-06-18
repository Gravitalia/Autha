FROM rust:1.69 as build

RUN USER=root cargo new --bin autha
WORKDIR /autha

COPY ./Cargo.toml ./Cargo.toml

RUN cargo build --release \
 && rm src/*.rs

RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config protobuf-compiler

COPY ./src ./src
COPY ./proto ./proto
COPY ./build.rs ./build.rs

RUN rm ./target/release/deps/autha* \
 && cargo build --release

FROM debian:latest

COPY --from=build /autha/target/release/autha .

EXPOSE 1111
CMD ["./autha"]
