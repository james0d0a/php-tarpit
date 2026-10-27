# php_tarpit

Honeypot sensor that poses as a PHP server vulnerable to php2shell (CVE-2026-109618/109619) and records what scanners send.

## Install

Needs Docker Engine 24.0.6+ (rootful) on Linux.

```sh
git clone https://github.com/james0d0a/php-tarpit && cd php-tarpit
sudo install -d -o 65532 -g 65532 data   # output folder; the sensor runs as uid 65532
docker compose up -d --build
```

The sensor listens on ports 80 and 443 using host networking.

## Configure

Uncomment variables under `environment:` in `compose.yaml`, e.g. `PHP_TARPIT_PHP_VERSION`, `PHP_TARPIT_HOSTNAME`, `PHP_TARPIT_MAX_TOTAL_BYTES`. Run `docker run --rm php_tarpit:latest --help` for the full list.

## Output

Everything is written to `./data/`, readable without root except `tls/key.pem` and `tls/keylog.txt` (use `sudo`):

| Path | Contents |
|---|---|
| `requests.jsonl` | one line per request |
| `connections.jsonl` | one line per connection |
| `streams/`, `bodies/` | raw bytes; bodies stored once by sha256 |
| `pcap/` | wire capture of ports 80/443 |
| `tls/keylog.txt` | decrypts the pcap in Wireshark |

To decrypt: `mergecap -w all.pcap data/pcap/*.pcap`, then open `all.pcap` with `tls.keylog_file` set to `data/tls/keylog.txt`.

## Review

The viewer is a read-only web UI over `./data`, browsed by attack session. It listens on the host's loopback only and has no login, so reach it through SSH:

```sh
docker compose --profile viewer up -d --build    # on the sensor host
ssh -L 8080:127.0.0.1:8080 <sensor-host>          # on your workstation
```

Then open http://localhost:8080. Filter attack sessions by body, request count, method, status, target, source IP, time or first sighting (the session that first sent a given request body); drill into requests for headers, bodies (text or hex, download as a file) and the exact wire bytes. Refresh to pick up new traffic.

To review a copy instead: `cargo run --release --manifest-path viewer/Cargo.toml -- --data-dir ./copy-of-data`, then open http://localhost:8080.

## Test

```sh
cargo test      # unit tests (needs libpcap-devel)
cargo harness   # end-to-end with curl and Nuclei (needs Docker)
cargo test --manifest-path viewer/Cargo.toml    # viewer
```
