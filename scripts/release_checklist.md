# Release Checklist

Use this checklist when cutting a release.

## 1) Pre-flight

- Ensure working tree is clean.
- Confirm version/changelog updates are complete.
- Confirm README and policy docs are current.

## 2) Local Verification

Run from repo root:

```bash
make ci
```

Then run a manual macOS smoke test:

```bash
go build -o ./clipguard ./cmd/clipguard
./clipguard once --verbose
./clipguard run --once --verbose
```

Optional audit-log validation:

```bash
./clipguard once --audit-log
./clipguard log --tail 5
```

Confirm no raw clipboard content appears in audit logs.

## 3) Security Verification

- No network/telemetry code introduced.
- Audit log schema remains hash+metadata only.
- Verbose/debug output does not print raw secret spans.
- Defaults remain safe for high-risk findings.

## 4) Tag and Release Candidate

```bash
git tag -a v1.0.0-rc1 -m "v1.0.0-rc1"
git push origin v1.0.0-rc1
```

## 5) GitHub Release Notes

Include:
- Highlights of security/privacy posture
- Breaking or behavior changes
- Manual upgrade/config notes
- Known limitations

## 6) Post-release

- Verify CI green on tagged commit.
- Verify binary build from tag on macOS.
- Track first user issues for detector tuning.
