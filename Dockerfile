FROM rust:1.68 as build

RUN USER=root cargo new --bin torresix
WORKDIR /torresix

COPY ./Cargo.toml ./Cargo.toml
COPY ./src ./src
COPY ./build.rs ./build.rs
COPY proto/ proto/

RUN apt-get update && apt-get install -y libssl-dev pkg-config protobuf-compiler

RUN cargo build --release --bin server

FROM rust:1.68-slim-buster

COPY --from=build /torresix/target/release/server .

EXPOSE 50051
CMD ["./server"]
