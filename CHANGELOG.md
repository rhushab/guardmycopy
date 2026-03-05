# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- CLI launch-agent lifecycle commands: `install`, `uninstall`, and `status`
- `install` command support for rendering an embedded launch-agent plist template, writing `~/Library/LaunchAgents/com.guardmycopy.agent.plist`, creating log directory, and running `launchctl bootstrap gui/$(id -u)`
- `status` output now includes launch-agent loaded/running state plus runtime bypass state (`snoozed-until`, `allow-once`) from persisted user state
- `log stats --since <duration>` command for local audit analytics (top blocked/warned apps, risk-level counts, and recent block reasons) with safe skipping of malformed JSONL lines
- Added a common token pack detector for AWS access key IDs, GitHub PATs (classic + fine-grained), Slack tokens/webhooks, and Stripe secret keys with distinct finding types and config toggles
- Added optional `per_app_bundle_id` policy overrides with precedence `bundle_id > app name > global`, plus macOS foreground bundle-id resolution in decision context
- Homebrew tap formula at `Formula/guardmycopy.rb` for source installs via `brew`

### Changed
- Added explicit macOS-only guardrails for launch-agent lifecycle commands with clear errors on other operating systems
- Service run loop now uses adaptive idle polling backoff: unchanged clipboard reads gradually increase poll interval (capped at 2s) and reset immediately to the configured base interval when clipboard content changes
- CLI version now reports `1.0.0-rc2-dev` while unreleased changes are in progress

## [1.0.0-rc1] - 2026-03-04

### Added
- Open-source readiness docs: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE`
- GitHub Actions CI workflow for macOS build/test/vet/gofmt checks
- Release checklist at `scripts/release_checklist.md`
- Integration-style service loop test covering clipboard change -> decision -> action with mocks
- Additional detector and redactor test coverage

### Changed
- Safe defaults hardened: high-risk default action is now `block`
- Config loading now supports warning-aware loading for safe fallbacks
- Invalid allowlist regex entries are ignored with warnings instead of crashing startup
- Poll intervals below 100ms are clamped with clear warnings
- `sanitize --diff` now prints redacted previews and hashes instead of raw sensitive content
- macOS subprocess execution paths (`pbpaste`, `pbcopy`, `osascript`) now run with timeouts and improved error handling
- Makefile expanded with `fmt`, `fmt-check`, `vet`, `lint`, `test`, `build`, `ci`

### Removed
- Tracked built binary artifact from repository root

## [0.8] - 2026-03-04

### Added
- Baseline release snapshot tag `v0.8`

## [0.7] - 2026-03-04

### Added
- Optional local JSONL audit logging and `log` command
- Runtime user controls (`snooze`, `allow-once`) with persisted state

## [0.6] - 2026-03-04

### Added
- Per-app policy overrides and allowlist support
- Config initialization command and example config

## [0.5] - 2026-03-04

### Added
- Continuous run loop and one-shot command flow
- macOS platform adapter selection and notification plumbing

## [0.4] - 2026-03-04

### Added
- Additional detectors for env-style secrets and high-entropy tokens

## [0.3] - 2026-03-04

### Added
- JWT detector and risk scoring improvements

## [0.2] - 2026-03-04

### Added
- Redaction pipeline and initial CLI commands

## [0.1] - 2026-03-04

### Added
- Initial project scaffold
- PEM private key detection

[1.0.0-rc1]: https://github.com/rhushab/guardmycopy/releases/tag/v1.0.0-rc1
[0.8]: https://github.com/rhushab/guardmycopy/releases/tag/v0.8
[0.7]: https://github.com/rhushab/guardmycopy/releases/tag/v0.7
[0.6]: https://github.com/rhushab/guardmycopy/releases/tag/v0.6
[0.5]: https://github.com/rhushab/guardmycopy/releases/tag/v0.5
[0.4]: https://github.com/rhushab/guardmycopy/releases/tag/v0.4
[0.3]: https://github.com/rhushab/guardmycopy/releases/tag/v0.3
[0.2]: https://github.com/rhushab/guardmycopy/releases/tag/v0.2
[0.1]: https://github.com/rhushab/guardmycopy/releases/tag/v0.1
