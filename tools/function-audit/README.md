# Rust function inventory

Run from the repository root:

```sh
cargo run --locked --manifest-path tools/function-audit/Cargo.toml -- \
  src izanagi-agent/src izanagi-common/src izanagi-dns-proxy/src \
  izanagi-ebpf/src izanagi-http-capture/src izanagi-telemetry/src
```

The tool parses Rust with `syn` and prints tab-separated file, function,
declaration line, and physical line count for definitions of at least 50 lines.
It counts the function signature through the closing brace, including blank
lines and comments, without counting preceding attributes or documentation.
It includes free functions, inherent/trait implementation methods, and default
trait methods, including definitions for other platform/feature configurations.

It excludes `#[test]`/`#[tokio::test]`, `#[cfg(test)]` functions, implementations
and inline modules, inline `mod tests`, and the repository's separately loaded
`tests.rs` and `*_test_support.rs` files. Integration test directories are not
among the roots above. Conditional compilation is not evaluated: other cfg
expressions and macro-generated functions require manual review.
