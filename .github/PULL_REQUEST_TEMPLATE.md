## Summary

<!-- what changed and why; link the issue if one exists -->

## Compatibility impact

<!-- does this change any behavior observable by a CUPS client,
config file, filter, or backend? if so, which upstream semantics
does it match (man page / RFC / source reference)? -->

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace --locked`
- [ ] per-crate line coverage `>= 95%` (`./scripts/coverage-gate.sh` / `cargo llvm-cov --package <pkg> --fail-under-lines 95`)
- [ ] `cargo deny check` and `cargo audit`
- [ ] upstream `ipptool` matrix green (`scripts/conformance.sh`)
- [ ] no `unsafe` outside `crates/sys`
- [ ] commits signed off (`git commit -s`, DCO 1.1)
