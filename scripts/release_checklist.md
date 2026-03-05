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
go build -o ./guardmycopy ./cmd/guardmycopy
./guardmycopy once --verbose
./guardmycopy run --once --verbose
```

Optional audit-log validation:

```bash
./guardmycopy once --audit-log
./guardmycopy log --tail 5
```

Confirm no raw clipboard content appears in audit logs.

## 3) Security Verification

- No network/telemetry code introduced.
- Audit log schema remains hash+metadata only.
- Verbose/debug output does not print raw secret spans.
- Defaults remain safe for high-risk findings.

## 4) Tag and Release Candidate

```bash
git tag -a v1.0.0-rc2 -m "v1.0.0-rc2"
git push origin v1.0.0-rc2
```

## 5) GitHub Release Notes

Include:
- Highlights of security/privacy posture
- Breaking or behavior changes
- Manual upgrade/config notes
- Known limitations

After pushing the tag, update `Formula/guardmycopy.rb` on `main`:
- Set `url` to `.../refs/tags/<tag>.tar.gz`
- Set `version` to the release version
- Set `sha256` to the downloaded tarball checksum (`curl -L <url> | shasum -a 256`)

## 6) Post-release

- Verify CI green on tagged commit.
- Verify binary build from tag on macOS.
- Verify Homebrew tap install:

```bash
brew update
brew tap rhushab/guardmycopy https://github.com/rhushab/guardmycopy
brew reinstall rhushab/guardmycopy/guardmycopy
guardmycopy version
```

- Track first user issues for detector tuning.
