# clipguard

`clipguard` is a macOS-only clipboard firewall written in Go.
It continuously scans clipboard text for likely secrets and applies policy actions per risk level and foreground app.

## Scope

What it does:
- Detects likely sensitive text (PEM private keys, JWT-like tokens, env-style secrets, high-entropy tokens)
- Applies policy actions: `allow`, `warn`, `sanitize`, `block`
- Supports per-app policy overrides (for example stricter browser/chat policies)
- Provides optional local JSONL audit logging with hash-only clipboard representation

What it does not do:
- No network calls, no telemetry, no analytics, no cloud service
- No binary/file attachment scanning (text clipboard only)
- No guarantee against all secret exfiltration vectors
- No perfect detection accuracy (false positives/false negatives are possible)

## Privacy and Security

- Local-only by design.
- Optional audit logging is disabled by default.
- Audit entries include metadata only: timestamp, app, risk, score, finding types, action, and `contentHash` (SHA-256).
- Raw clipboard text is never written to audit logs.
- Verbose/diagnostic outputs print redacted previews and hashes, not raw detected secret spans.

## Threat Model

`clipguard` is intended to reduce accidental copy/paste leaks of sensitive text from local user workflows.

In scope:
- Accidental paste of secrets copied in browsers, chat apps, terminals, editors
- Immediate local policy enforcement on clipboard changes

Out of scope:
- Malware with full local permissions
- Screen capture/keylogger compromise
- Deliberate data exfiltration by a trusted user
- Non-text clipboard payloads

## Platform and Permissions

- Supported OS: **macOS only** (`darwin`)
- Uses `pbpaste` / `pbcopy` for clipboard access
- Uses `osascript` + `System Events` for foreground app and notifications
- You may need Accessibility permission for your terminal/app:
  - `System Settings -> Privacy & Security -> Accessibility`

## Quickstart

### Build

```bash
go build -o ./clipguard ./cmd/clipguard
```

### Initialize config

```bash
./clipguard config init
```

### Run once (decision only)

```bash
./clipguard once --verbose
```

### Run continuous protection

```bash
./clipguard run
```

Notes:
- Default poll interval: `500ms`
- Minimum poll interval: `100ms` (lower values are clamped)

## Install (local)

```bash
go build -o ./clipguard ./cmd/clipguard
install -m 0755 ./clipguard /usr/local/bin/clipguard
```

## Example Configuration

Use [`configs/example.yaml`](configs/example.yaml) as a base.

Recommended policy style:
- Strict for browsers/chat
- More lenient for IDE/terminal

```yaml
global:
  poll_interval_ms: 500
  thresholds:
    med: 8
    high: 15
  actions:
    low: allow
    med: sanitize
    high: block

per_app:
  "Google Chrome":
    actions:
      med: warn
      high: block
  "Slack":
    actions:
      med: warn
      high: block
  "iTerm2":
    detector_toggles:
      high_entropy_token: false
  "Visual Studio Code":
    thresholds:
      med: 12
      high: 20
```

## Manual Verification Workflow (macOS)

1. Build:

```bash
go build -o ./clipguard ./cmd/clipguard
```

2. Copy a known sensitive sample and run once:

```bash
printf '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n' | pbcopy
./clipguard once --verbose
```

3. Run the loop and trigger policy actions:

```bash
./clipguard run --interval 250
```

4. Optional audit log mode:

```bash
./clipguard run --audit-log
./clipguard log --tail 20
```

Expected audit location:
- `$(os.UserConfigDir)/clipguard/audit.jsonl`

## Troubleshooting

- `unsupported OS`: clipguard runs only on macOS.
- `osascript active app failed`: grant Accessibility permission to your terminal/app.
- `load config`: invalid YAML or invalid policy keys; fix config and rerun.
- Polling too aggressive warning: raise `poll_interval_ms` to `>=100`.
- Unexpected detections: tune `detector_toggles`, `thresholds`, and `allowlist_patterns`.

## Development

```bash
make fmt
make vet
make lint
make test
make build
make ci
```

## License

MIT. See [`LICENSE`](LICENSE).
