# Repository Guidelines

## Project Structure & Module Organization

Izanagi is a Rust sandbox and syscall-monitoring tool. The root `src/` contains the CLI, engine, sandbox backends, tracers, and detection rules; CLI handlers live in `src/commands/`. Separate Cargo packages provide `izanagi-agent` (guest execution), `izanagi-common` (shared definitions), `izanagi-ebpf` (kernel probes), `izanagi-telemetry` (correlation/storage), and DNS/HTTP proxies. These packages are not a Cargo workspace; use their manifests explicitly.

Integration tests live in `tests/`, reusable data in `tests/fixtures/`, and manual checks in `tests/manual/`. See `examples/` for executable examples, `docs/` for design/audit records, `image/` and `packer/` for guest images, and `tools/` for supporting utilities.

## Build, Test, and Development Commands

- `cargo build --release`: build the host CLI. On Linux, add `--features landlock,ebpf`.
- `cargo run -- --help`: inspect local CLI commands without starting a sandbox.
- `cargo test --locked --all-targets`: run root unit, integration, and example tests.
- `cargo test --locked --all-targets --manifest-path izanagi-agent/Cargo.toml`: test a component; substitute another component manifest as needed.
- `cargo fmt --all -- --check`: check root formatting; repeat with `--manifest-path` for components.
- On Linux, `cargo clippy --locked --all-targets --all-features -- -D warnings` matches CI linting.

Use `make help` for image and cross-compilation targets. eBPF builds require nightly Rust, `rust-src`, and `bpf-linker`; see `make build-ebpf`.

## Coding Style & Naming Conventions

Use Rust 2024 conventions and rustfmt's four-space indentation. Name modules/functions `snake_case`, types `UpperCamelCase`, and constants `SCREAMING_SNAKE_CASE`.

- Avoid giant functions: keep each function focused on one responsibility, extract meaningful helpers, and aim below 50 physical lines. Document justified declarative exceptions.
- Reuse identical processing: search for existing helpers before implementing new logic. Extract repeated logic into a shared function or module and use it at each call site instead of copying it.
- Preserve public interfaces, protocol compatibility, validation order, and cleanup behavior when splitting or consolidating code.

## Testing Guidelines

Use `#[test]` and `#[tokio::test]`, with descriptive behavior names such as `startup_failures_stop_sandbox_before_exec_or_shell`. Add regressions for affected authentication, cancellation, rollback, framing, and resource-release boundaries. No numeric coverage threshold is configured. Run relevant component suites and verify Linux-only features on Linux; macOS tests cannot establish Landlock/eBPF behavior.

## Commit & Pull Request Guidelines

Recent commits use concise imperative subjects, often `feat:`, `fix:`, or `refactor:`. PR descriptions should explain the problem, resulting behavior, linked issue, and validation commands/results. Document platform limitations and exceptions. Ensure CI, CodeQL, and secret scanning pass before merging.

## Security & Configuration Tips

Use `izanagi init` to generate configuration. Prefer `IZANAGI_SECRET_FILE` over inline credentials. Never log tokens or secret mappings, commit real credentials, or weaken authentication/IP restrictions for production. Keep test bypasses isolated to fixtures and preserve private file permissions.
