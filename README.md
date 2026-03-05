# guardmycopy

`guardmycopy` is a macOS-only clipboard firewall written in Go.
It continuously scans clipboard text for likely secrets and applies policy actions per risk level and foreground app.

## Scope

What it does:
- Detects likely sensitive text (PEM private keys, JWT-like tokens, env-style secrets, high-entropy tokens, and common service tokens such as AWS access key IDs, GitHub PATs, Slack tokens/webhooks, and Stripe secret keys)
- Applies policy actions: `allow`, `warn`, `sanitize`, `block`
- Supports per-app and per-app-bundle-id policy overrides (for example stricter browser/chat policies)
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

`guardmycopy` is intended to reduce accidental copy/paste leaks of sensitive text from local user workflows.

In scope:
- Accidental paste of secrets copied in browsers, chat apps, terminals, editors
- Immediate local policy enforcement on clipboard or foreground-app changes

Out of scope:
- Malware with full local permissions
- Screen capture/keylogger compromise
- Deliberate data exfiltration by a trusted user
- Non-text clipboard payloads

## Platform and Permissions

- Supported OS: **macOS only** (`darwin`)
- Uses native AppKit pasteboard reads/writes plus `changeCount` polling for lower-latency clipboard monitoring
- Uses `osascript` + `System Events` for foreground app name, bundle ID, and notifications
- You may need Accessibility permission for your terminal/app:
  - `System Settings -> Privacy & Security -> Accessibility`

## Quickstart

### Build

```bash
go build -o ./guardmycopy ./cmd/guardmycopy
```

### Initialize config

```bash
./guardmycopy config init
```

### Run once (decision only)

```bash
./guardmycopy once --verbose
```

### Run continuous protection

```bash
./guardmycopy run
```

Notes:
- Default poll interval: `500ms`
- Minimum poll interval: `100ms` (lower values are clamped)
- Clipboard polling checks the native pasteboard change counter before doing a full text read when possible, reducing steady-state monitoring overhead
- Adaptive idle backoff: after `4` consecutive polls with no clipboard or foreground-app change, the run loop doubles the interval stepwise up to `2s` while idle, then resets immediately to the configured base interval on the next clipboard or foreground-app change

### Manage macOS launch agent

Install and bootstrap the launch agent:

```bash
./guardmycopy install
```

Check launch agent + runtime bypass state:

```bash
./guardmycopy status
```

Uninstall launch agent:

```bash
./guardmycopy uninstall
```

## Install (Homebrew tap)

Tap this repository and install:

```bash
brew tap rhushab/guardmycopy https://github.com/rhushab/guardmycopy
brew install rhushab/guardmycopy/guardmycopy
```

Notes:
- The tap formula tracks immutable release tags and builds from source.
- `go` is installed automatically as a build dependency.

## Install (manual local)

```bash
go build -o ./guardmycopy ./cmd/guardmycopy
install -m 0755 ./guardmycopy /usr/local/bin/guardmycopy
```

## Example Configuration

Use [`configs/example.yaml`](configs/example.yaml) as a base.

Recommended policy style:
- Strict for browsers/chat
- More lenient for IDE/terminal
- Use bundle-id overrides for app variants that share the same visible app name

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
    aws_access_key_id: true
    github_pat_classic: true
    github_pat_fine_grained: true
    slack_token: true
    slack_webhook: true
    stripe_secret_key: true
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
    actions:
      high: block

per_app_bundle_id:
  "com.google.Chrome":
    actions:
      med: warn
      high: block
```

Policy precedence:
- `per_app_bundle_id` override (if bundle ID matches)
- `per_app` override (if app name matches)
- `global`

## Manual Verification Workflow (macOS)

1. Build:

```bash
go build -o ./guardmycopy ./cmd/guardmycopy
```

2. Copy a known sensitive sample and run once:

```bash
printf '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n' | pbcopy
./guardmycopy once --verbose
```

3. Run the loop and trigger policy actions:

```bash
./guardmycopy run --interval 250
```

4. Optional audit log mode:

```bash
./guardmycopy run --audit-log
./guardmycopy log --tail 20
./guardmycopy log stats --since 7d
```

`log stats --since` requires a duration window and supports `d`, `h`, and `m` units.

Expected audit location:
- `$(os.UserConfigDir)/guardmycopy/audit.jsonl`

## Troubleshooting

- `unsupported OS`: guardmycopy runs only on macOS.
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
