# Issue #49: responsibility-based function decomposition

Scope: all production Rust definitions in root and component `src` directories.
The external API, protocol, security boundaries, error handling, cancellation,
startup/rollback order and cleanup must remain unchanged.

## Inventory

`tools/function-audit` uses Rust syntax and physical source spans. See its README
for the command and test exclusions. `function-refactor-49-baseline.tsv` records
the starting main commit `0857e26` (after the shared-helper consolidation in #51).
The issue's original reference is `de356ea`; its three large shell test functions
are excluded, along with other test-only definitions. No issue production
candidate is dropped from scope. `function-refactor-49-remaining.tsv` records the
latest remaining definitions, including helpers introduced by this work.

## Completed responsibilities

### Telemetry

- Correlation: bounded scope eviction, idle expiry, and capacity checks;
  socket incarnation/binding; credential attempts and outcomes; ancestor proofs;
  HTTP transfer results; observation/clock/sequence quality; evidence finalization.
- Schema: envelope identity, process identity and payload validation.
- Audit storage: classifier metadata, probabilities and status validation;
  persisted payload validation; disk-budget eviction and record persistence.

All original telemetry candidates are split. The only remaining telemetry helper
of at least 50 lines is `finish_snapshot` (50 lines): it declaratively constructs
the complete `FeatureSnapshot` from the already validated/aggregated inputs.
Its field mapping stays together so the output schema can be reviewed in one
place; further splitting would scatter one responsibility across setters.

Validation on macOS: component fmt, check, all tests (25), and Clippy with
`-D warnings` passed. Three added regressions cover gaps/sharing during HTTP
transfer, contradictory open results, and stable evidence truncation under
arrival reordering. The same 25 tests also pass against the pre-refactor source,
proving the new cases assert existing behavior. Linux CI verification is pending.

### Agent

All seven original agent candidates are split, and all new production helpers
in this component are below 50 lines. Responsibilities now have explicit names:
Hello/token negotiation, operation authorization, control dispatch, tracer and
sidecar startup, rate-limited event forwarding, pre-fork shell preparation,
post-fork privilege/exec calls, bounded command output, timeout/group cleanup,
PTY input/output, child exit observation/reaping, and root-only proxy metadata.
Startup messages, authentication sequences, stop/drop order, and the persistent
message reader across receive cancellation are preserved.

Validation on macOS: component fmt/check, all 42 tests, and Clippy with
`-D warnings` passed. TCP tests require execution outside the filesystem/network
sandbox. Added tests cover Hello mode/token rejection, denial of all three
protected unauthenticated operations, authenticated sequencing, tracer startup
failure, draining/truncating both output streams, and timeout child reaping.
Linux CI at `cdc93c0` passed all 47 agent tests, including PTY normal exit,
disconnect, stop, protocol error, send failure, task cancellation, surviving
process-group cleanup, and partial-frame preservation. Agent eBPF feature check,
telemetry tests, no_std eBPF build, formatting and all-feature Clippy also passed.

### Interactive initialization

Both original `commands/init.rs` candidates are split, and its production
helpers are all below 50 lines. Prompt order/defaults, backend-specific options,
overwrite cancellation, output escaping, section/array formatting and private
file permissions are maintained. Responsibilities are backend/QEMU/tracer/share
selection, monitored categories and detection settings, MITM address/mapping
input, overwrite confirmation, private persistence, and individual TOML sections.

Local fmt, the 11 initialization tests and default-feature all-target Clippy
passed. Added regressions cover new-file/overwrite permissions and truncation,
plus empty/escaped MITM mapping arrays. The new initialization commit still needs
Linux/macOS CI verification. All-feature builds require Linux because aya and
landlock depend on Linux libc interfaces.

## Outstanding work

The remaining inventory is work to complete, except explicitly documented
declarative exceptions. Tracer, CLI, sandbox, behavior evaluation and
proxy candidates still require decomposition and appropriate boundary tests.
Full fmt/check/test and Linux/feature CI gates, final inventory, PR and merge
remain required before closing #49.
