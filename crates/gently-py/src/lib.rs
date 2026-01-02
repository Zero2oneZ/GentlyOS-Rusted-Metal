// Python bindings disabled on musl-linux
// PyO3 requires glibc
//
// To build on glibc systems:
// 1. Rename Cargo.toml.disabled to Cargo.toml
// 2. Restore src/lib.rs from git
// 3. Run: maturin develop
