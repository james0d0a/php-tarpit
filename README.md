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

## Test

```sh
cargo test      # unit tests (needs libpcap-devel)
cargo harness   # end-to-end with curl and Nuclei (needs Docker)
```
