FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/php_tarpit /php_tarpit

FROM gcr.io/distroless/cc-debian12
COPY --from=build /php_tarpit /usr/local/bin/php_tarpit
COPY personas /etc/php_tarpit/personas
ENV PHP_TARPIT_PERSONA=/etc/php_tarpit/personas/apache-modphp-wordpress.toml \
    PHP_TARPIT_DATA_DIR=/data
VOLUME /data
ENTRYPOINT ["/usr/local/bin/php_tarpit"]
