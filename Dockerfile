FROM rust:1.96-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin bison flex && rm -rf /var/lib/apt/lists/*

# libpcap built static with no optional backends, so the distroless runtime
# needs no extra shared libraries (Debian's libpcap pulls in dbus/systemd).
ARG LIBPCAP_VERSION=1.10.7
ARG LIBPCAP_SHA256=68fa62cffb974f4275641ce14c2e2d75739251f30e00e6a0900903b247d76a03
RUN curl -fsSLO https://www.tcpdump.org/release/libpcap-${LIBPCAP_VERSION}.tar.xz \
    && echo "${LIBPCAP_SHA256}  libpcap-${LIBPCAP_VERSION}.tar.xz" | sha256sum -c - \
    && tar xf libpcap-${LIBPCAP_VERSION}.tar.xz \
    && cd libpcap-${LIBPCAP_VERSION} \
    && ./configure --prefix=/opt/libpcap --disable-shared --disable-usb --disable-netmap \
        --disable-bluetooth --disable-dbus --disable-rdma --without-libnl --without-dag \
        --without-septel --without-snf --without-turbocap \
    && make -j"$(nproc)" && make install \
    && cd .. && rm -rf libpcap-${LIBPCAP_VERSION}*
# Only libpcap.a is in this directory, so `-lpcap` links statically.
ENV LIBPCAP_LIBDIR=/opt/libpcap/lib LIBPCAP_VER=${LIBPCAP_VERSION}

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/php_tarpit /php_tarpit
# The sensor runs as non-root with no-new-privileges, so it keeps its two
# capabilities through execve only via these file capabilities *and* the
# container granting them (cap_add): NET_BIND_SERVICE for ports 80/443,
# NET_RAW for wire capture.
RUN setcap cap_net_bind_service,cap_net_raw=+ep /php_tarpit && mkdir /data

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
