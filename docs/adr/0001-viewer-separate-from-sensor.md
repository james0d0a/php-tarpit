# Viewer runs separately from the sensor, read-only, on loopback

The viewer is its own process and crate, mounts `data/` read-only, listens on 127.0.0.1 only and has no authentication; operators reach it through `ssh -L`. We did not embed the UI in the sensor because the sensor faces the internet on host networking, and any admin endpoint or parser bug there would expose the capture pipeline and reveal the honeypot. SSH is the only gate. This assumes a single-tenant sensor host, and a `Host`-header allowlist blocks DNS rebinding from the operator's browser.

## Considered Options

- **Embedded in the sensor on an extra port**: rejected because it puts admin code in the internet-facing process.
- **Static HTML report**: rejected because there is no near-live view beside a running sensor.
- **Terminal UI**: rejected because wide headers, long payloads and drill-down are better served by a browser. The browser surface is handled by rendering all attacker data as escaped text under a strict CSP with no inline script.

## Consequences

- The viewer cannot depend on sensor internals. It parses the JSONL format with its own lenient types, ignoring unknown fields and skipping a partial trailing line, so the JSONL format is the contract between the two.
- The viewer never serves `tls/`.
- Review state such as notes or a reviewed flag would need a store outside `data/`, which stays sensor-owned.
