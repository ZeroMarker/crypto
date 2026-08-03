# Phase 0 — Foundation

Workspace layout and hygiene. Everything later builds on this.

## What's here

```
.
├── Cargo.toml            # workspace manifest (shared deps, versions)
├── rust-toolchain.toml   # pinned toolchain
├── ROADMAP.md            # the plan
├── crates/
│   ├── crypto-core/      # Phase 1: primitives
│   └── wallet/           # Phase 2: key management
```

## Workspace conventions

- One library crate per concern under `crates/`, versions inherited from the
  workspace (`version.workspace = true`).
- Dependencies are declared once in the root `Cargo.toml` under
  `[workspace.dependencies]` and referenced as `foo.workspace = true`.
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test` must pass before a
  change is done.

## Commands

```sh
cargo build            # build everything
cargo test --workspace # run all tests (lib + integration + doctests)
cargo clippy --all-targets
cargo fmt --check
```

## Example binaries

```sh
cargo run -p crypto-core --example hashes
cargo run -p crypto-core --example signing
cargo run -p wallet --example mnemonic_to_address
```

## Next

[Phase 1 — Cryptography primitives](02-cryptography.md) is implemented in
`crates/crypto-core`.
