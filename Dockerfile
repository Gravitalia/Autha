FROM rust:1.69-slim-buster as build

RUN USER=root cargo new --bin autha
WORKDIR /autha

COPY ./Cargo.toml ./Cargo.toml

RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config protobuf-compiler

RUN cargo build --release \
 && rm src/*.rs

COPY ./src ./src
COPY ./proto ./proto
COPY ./build.rs ./build.rs

RUN rm ./target/release/deps/autha* \
 && cargo build --release

FROM alpine:3.18

COPY --from=build /autha/target/release/autha .

EXPOSE 1111
CMD ["./autha"]
