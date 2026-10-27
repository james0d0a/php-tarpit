# Build context is the repo root (see compose.yaml): the viewer's contract
# test dev-depends on the sensor crate, so cargo needs its manifest to load
# the viewer workspace, though the sensor is not compiled here.
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY viewer ./viewer
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/viewer/target \
    cargo build --release --locked --manifest-path viewer/Cargo.toml \
    && cp viewer/target/release/php_tarpit_viewer /php_tarpit_viewer

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /php_tarpit_viewer /usr/local/bin/php_tarpit_viewer
ENV PHP_TARPIT_VIEWER_DATA_DIR=/data
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/php_tarpit_viewer"]
