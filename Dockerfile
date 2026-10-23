FROM rust:1.96-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/php_tarpit /php_tarpit
# The sensor runs as non-root with no-new-privileges, so it can only bind
# ports 80/443 by keeping CAP_NET_BIND_SERVICE through execve: that needs this
# file capability *and* the capability granted to the container (cap_add).
RUN setcap cap_net_bind_service=+ep /php_tarpit && mkdir /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /php_tarpit /usr/local/bin/php_tarpit
COPY personas /etc/php_tarpit/personas
# A fresh named volume inherits this ownership, so the non-root user can write it.
COPY --from=build --chown=nonroot:nonroot /data /data
ENV PHP_TARPIT_PERSONA=/etc/php_tarpit/personas/apache-modphp-wordpress.toml \
    PHP_TARPIT_DATA_DIR=/data
USER nonroot:nonroot
VOLUME /data
ENTRYPOINT ["/usr/local/bin/php_tarpit"]
