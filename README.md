# clipguard

`clipguard` is a macOS-only MVP clipboard firewall written in Go. It runs locally and uses:
- `pbpaste` / `pbcopy` for clipboard reads and writes
- `osascript` helpers for active-app lookup and notifications

No server, database, or network calls are used.

Current detectors:
- PEM private key blocks
- JWT-like tokens (`header.payload.signature`)
- Env-style secrets (`KEY=VALUE` for secret-like key names)
- High-entropy long tokens

## Build

```bash
go build ./cmd/clipguard
```

Or via Makefile:

```bash
make build
```

## Run

Sanitize text from stdin:

```bash
cat input.txt | ./clipguard sanitize
```

Show findings summary, risk/score, triggered detectors, and before/after on stderr while writing sanitized text to stdout:

```bash
cat input.txt | ./clipguard sanitize --diff
```

Run polling mode:

```bash
./clipguard run
```

Run polling mode with custom interval (ms):

```bash
./clipguard run --interval 250
```

Run polling mode with an explicit YAML config path:

```bash
./clipguard run --config ./configs/example.yaml
```

Print version:

```bash
./clipguard --version
```

Config is optional. When `--config` is omitted, clipguard uses built-in defaults and then attempts:

`~/.config/clipguard/config.yaml`

YAML schema:

```yaml
global:
  poll_interval_ms: 500
  thresholds:
    med: 8
    high: 15
  detector_toggles:
    pem_private_key: true
    jwt: true
    env_secret: true
    high_entropy_token: true
  actions:
    low: allow
    med: sanitize
    high: block
  allowlist_patterns:
    - '(?i)^public_[A-Z0-9_]+$'

per_app:
  "Google Chrome":
    actions:
      med: warn
      high: sanitize
    allowlist_patterns:
      - '^chrome-extension://'
```

Action options per risk level:
- `allow`: keep clipboard content unchanged
- `warn`: show a notification and keep clipboard unchanged
- `sanitize`: redact matched secret spans
- `block`: clear clipboard content

Use [`configs/example.yaml`](configs/example.yaml) as a starting point.

## Test

```bash
go test ./...
```

Or via Makefile:

```bash
make test
```
