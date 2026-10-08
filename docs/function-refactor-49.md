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

## Outstanding

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
Linux-only PTY cleanup/cancellation regressions and eBPF feature checks are
pending CI.

## Outstanding work

The remaining inventory is work to complete, except explicitly documented
declarative exceptions. Tracer, CLI, sandbox, behavior evaluation and
proxy candidates still require decomposition and appropriate boundary tests.
Full fmt/check/test and Linux/feature CI gates, final inventory, PR and merge
remain required before closing #49.
