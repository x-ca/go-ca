# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/).

## [v0.3.1]

### Breaking — `ca` package API

- Removed `LoadRootCA`. Use `NewRootCA` to create a root CA, or load the key
  and certificate via `BaseCA.LoadKey` / `BaseCA.LoadCert` on a `RootCA`
  value directly.
- Removed `TLSCA.WriteCert(commonName, key, cert, chainPath)`. It is replaced
  by `TLSCA.WriteSignedCert(outputDir, commonName, key, cert, tlsChainPath)`,
  which writes under `outputDir/certs/<commonName>/` instead of a hardcoded
  `x-ca/certs/` prefix.
- Changed `RootCA.Write` signature: the unused `chainPath` argument is gone.
  A self-signed root has no issuer, so no chain is written. New signature:
  `RootCA.Write(rootKeyPath, rootCertPath string) error`.
- Changed `LoadTLSCA` signature: the `password` argument is gone. Encrypted
  PEM keys were never actually decrypted (the password was ignored); they
  already produced an error. New signature: `LoadTLSCA(keyPath, certPath string) (*TLSCA, error)`.
- Removed the package-level `supportPemType` variable.
- Removed the `CA` interface (no consumers; `RootCA`/`TLSCA` are concrete).
- Removed the following unused helpers: `CreateCertificateChain`,
  `EnsureDirectory`, `CreateFile`, `ExecPath`.
- `TLSCA` now embeds `BaseCA` instead of redeclaring `Key`, `Cert`,
  `KeyBits`, and `Curve`. Field access is unchanged; only the literal type
  definition changed.
- `TLSCA.CreateKey` is removed; use the embedded `BaseCA.GenerateKey`.

### Breaking — CLI

- Removed the `--tls-key-password` flag from `xca sign`. It had no effect
  (encrypted keys already errored). Decrypt keys with openssl first:
  `openssl rsa -in encrypted.key -out decrypted.key`.

### Changed (behavior)

- `ParseDomains` and `ParseIPs` now return an error naming the offending
  value when an entry is invalid. Previously invalid entries were silently
  dropped. Empty entries are still skipped.
- `CheckFileExists` uses `os.Stat` instead of `os.ReadFile` (no behavior
  change for file paths).
- `randSerial` now returns `(*big.Int, error)` instead of silently falling
  back to `1` when the random source failed. All callers propagate the error.
- `TLSCA.Sign` no longer caps `days` at `tlsCertYears`; only the
  `MaxTLSDays` (825) cap remains. EC leaf certs no longer carry
  `KeyUsageKeyEncipherment` (EC keys cannot perform key encipherment); RSA
  leaf certs retain `DigitalSignature | KeyEncipherment`.
- The TLS CA certificate now includes a `SubjectKeyId`.

### Added

- `ca/ca_test.go`, `ca/tls_test.go`: new test files covering root/TLS CA
  creation, key/cert loading (including the `ECDSA PRIVATE KEY` PEM variant),
  EC vs RSA leaf key usage, E2E root → TLS → leaf signing, wildcard output
  directories, and the `MaxTLSDays` cap.
- `ca/common_test.go`: expanded with negative-path coverage for
  `ParseDomains`, `ParseIPs`, `CheckFileExists`, `ValidateKeyCertMatch`,
  encrypted/unsupported PEM rejection, and `validateSafeName`.
- `TLSCA.WriteSignedCert` validates the common name before embedding it in
  filesystem paths (rejects path separators, `..`, and NUL bytes).

### Fixed

- `TLSCA.WriteSignedCert` now propagates the error when the TLS chain file
  cannot be read. Previously the error was silently swallowed and an
  incomplete bundle was written.
