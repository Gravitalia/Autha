FROM rust:1.63 as build

RUN USER=root cargo new --bin autha
WORKDIR /autha

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

RUN cargo build --release
RUN rm src/*.rs

COPY ./src ./src

RUN rm ./target/release/deps/autha*
RUN cargo build --release

FROM rust:1.63-slim-buster

COPY --from=build /autha/target/release/autha .

EXPOSE 1111
CMD ["./autha"]
