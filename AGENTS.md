# OpenMLS AI Agent Instructions

This repository is a Rust workspace implementing the Messaging Layer Security (MLS) protocol.
The main library crate is `openmls`; the repository also contains provider crates, test helpers, examples, a CLI, a delivery service, and wasm support.

## Key facts

- `openmls` is the core crate.
- `traits` defines provider interfaces.
- `openmls_rust_crypto` and `libcrux_crypto` are built-in crypto providers.
- `memory_storage` and `sqlite_storage` provide storage implementations.
- `cli`, `delivery-service/ds`, `delivery-service/ds-lib`, `interop_client`, `openmls-wasm`, `openmls_test`, and `fuzz` are workspace crates for tooling, integration, and testing.
- `basic_credential` is a credential implementation crate.
## Current focus for this workspace session

- Primary modification scope: `cli`, `delivery-service/ds` (mls-ds), and `delivery-service/ds-lib`.
- These crates are the middleware foundation for building applications on top of OpenMLS.
- Avoid broad changes to unrelated crates unless required to support this middleware work.
## Recommended commands

Use the repository’s CI commands as the reference for correct local workflow.

- Build the full workspace:
  - `cargo build --workspace --all-targets --exclude openmls-fuzz`
- Run workspace tests:
  - `cargo test --workspace --all-targets --exclude=openmls --exclude openmls-fuzz`
- Run the main crate tests with default features:
  - `cargo test -p openmls --verbose --no-default-features`
- Build/test with feature variants:
  - `cargo build --workspace -F extensions-draft-08 --all-targets --exclude openmls-fuzz`
  - `cargo test --workspace -F extensions-draft-08 --all-targets --exclude=openmls --exclude openmls-fuzz`
- Wasm test target:
  - `cargo test -p openmls --target wasm32-unknown-unknown -F js,js-test`

## Feature flags

- default features
- `fork-resolution`
- `extensions-draft-08` (with `extensions-draft-08-test-dependencies` in CI)
- `js` for wasm builds

## Code and PR conventions

- Rust code must be `rustfmt`-formatted.
- Prefer concise, elegant code changes: avoid bloated, sloppy insertions.
- Commit messages should use present tense, imperative mood, and keep the first line under 80 characters.
- PRs should be linked to an issue, kept reviewable, and generally stay under 1000 lines.
- Use branches for issues and assign yourself when working on them.
- Use `Cargo.toml` `[patch.crates-io]` for local dependency patching during development; switch patches to remote fork/branch for PRs.

## Important notes for agents

- Prefer linking to existing documentation rather than copying it.
- Reference `README.md`, `Developer.md`, and `CONTRIBUTING.md` when explaining repo policies.
- Treat `cli` and `delivery-service` as proof-of-concept tooling, not production APIs.

## Useful links

- [README.md](README.md)
- [Developer.md](Developer.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
