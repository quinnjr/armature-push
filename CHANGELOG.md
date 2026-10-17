# Changelog — `armature-push`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

### Security

- Web Push endpoint address classification now uses the shared
  `armature_http_client::egress` classifier, which additionally refuses
  `192.88.99.0/24`, documentation ranges, `64:ff9b:1::/48`, `100::/64`,
  `2001:2::/48`, `2001:db8::/32`, `3fff::/20`, `5f00::/16`, `fec0::/10` and
  IPv6 multicast.
- All provider HTTP clients (Web Push, FCM, APNS) are built with `.no_proxy()`:
  an ambient `HTTP(S)_PROXY` previously resolved Web Push endpoints itself,
  defeating the resolve-and-pin guard, and received credential-bearing FCM/APNS
  traffic (L19).
- Device tokens and Web Push endpoints are no longer logged verbatim; debug
  logs carry a 6-character prefix and the length (L21).
- `jsonwebtoken` now uses the `aws_lc_rs` backend instead of `rust_crypto`,
  dropping the `rsa` crate (RUSTSEC-2023-0071, non-constant-time RSA) from the
  FCM signing path (M29).

### Changed

- **Breaking:** the unused `p256` optional dependency (and therefore the
  implicit `p256` feature) is removed; the `apns` feature no longer enables it.
  Migration: none needed unless you enabled `armature-push/p256` directly.
- The `web-push` feature now depends on `armature-http-client` (egress guard).
- Test signing keys (RSA for FCM, P-256 for APNS) are generated at test time;
  no private keys are committed any more (L28).

## [0.2.2] - 2026-09-15

### Changed

- Dependencies bumped to their latest releases: `jsonwebtoken` 10.4 → 11.0, `p256` 0.13 → 0.14, `tokio` 1.52 → 1.53, `tokio` 1.52 → 1.53.
- Migrate to jsonwebtoken 11 and p256 0.14.

