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

## macOS permissions

`clipguard` asks macOS `System Events` for the frontmost app name. On some systems this requires enabling Accessibility access for the terminal/app running `clipguard`:

`System Settings -> Privacy & Security -> Accessibility`

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

Scan current clipboard once and print decision:

```bash
./clipguard once
```

Scan once with reasoning details:

```bash
./clipguard once --verbose
```

Equivalent one-shot mode via `run`:

```bash
./clipguard run --once
```

Run polling mode with reasoning logs:

```bash
./clipguard run --verbose
```

Temporarily disable enforcement:

```bash
./clipguard snooze 5m
```

Allow only the next clipboard event to bypass enforcement once:

```bash
./clipguard allow-once
```

Print version:

```bash
./clipguard --version
```

Config is optional. When `--config` is omitted, clipguard uses built-in defaults and then attempts:

`~/.config/clipguard/config.yaml`

Runtime user controls (`snooze` / `allow-once`) are stored in:

`$(os.UserConfigDir)/clipguard/state.json`

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
- `sanitize`: redact matched secret spans, write sanitized text, and notify
- `block`: replace clipboard content with `[CLIPGUARD BLOCKED]` and notify

Allowlist behavior:
- If a full clipboard value matches an `allowlist_patterns` regex, clipguard treats it as `allow`.
- Matched finding spans are also skipped when they match allowlist regexes.

Use [`configs/example.yaml`](configs/example.yaml) as a starting point.

## Manual Test Checklist (macOS)

1. Build:

```bash
go build ./cmd/clipguard
```

2. One-shot decision check:

```bash
printf '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n' | pbcopy
./clipguard once
```

3. Polling check with faster interval:

```bash
./clipguard run --interval 250
```

4. While running, copy a secret pattern and confirm clipboard becomes sanitized or `[CLIPGUARD BLOCKED]` per config, with notification shown.

## Test

```bash
go test ./...
```

Or via Makefile:

```bash
make test
```
