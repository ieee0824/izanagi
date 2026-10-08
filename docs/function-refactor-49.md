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

### Host eBPF tracing

All four original host tracer candidates and their new helpers are below 50
lines. Linux probe attachment, ABI/ELF section validation, kernel map acquisition,
ring-buffer forwarding, observation conversion and loss reporting now have
separate responsibilities. Required/optional probe error handling, legacy
channel backpressure, agent-event filtering and accumulated loss delivery are
preserved. Added tests cover malformed ELF offsets/duplicate metadata, channel
closure during backpressure, loss retention during queue saturation and filtering
of agent telemetry. Linux cross-target check and all-feature/all-target Clippy
pass; execution of Linux-specific tests remains a CI gate.

### Behavior runtime, classifier, CLI and evaluation

All twelve original candidates in these four modules are split, with every new
production helper below 50 lines. Responsibilities include bounded replay,
fixture/path/digest validation, paired evaluation and metrics, session-authorized
retention/export, MCP negotiation and response validation, ingestion state,
freshness checks, cancellable invocation and closed-schema audit persistence.
The same validation/error priority, process kill/reap order, shutdown behavior,
classifier timing and evaluation denominators are retained.

The root macOS all-target test suite passes: 395 library tests, 72 binary tests
and 49 integration tests. Two additional evaluation regressions pass (11 total),
proving digest mismatches and canonical symlink escapes prevent classification.
Linux cross-target all-feature/all-target Clippy also passes.

### Stop validation and log following

PID timestamp validation and tail-line discard/rendering have separate helpers;
both original candidates and their helpers are below 50 lines. Partial lines
still rewind, overlong incomplete lines are discarded, severity filtering and
truncation text are unchanged. Two new log regressions verify the partial-line
retry/filter path and the overlong discard cursor. Binary tests now total 74.

### MCP command handling

All four original MCP candidates and new production helpers are below 50 lines.
JSON/schema parsing, tool-call parameter validation and protocol response
serialization are separate from dispatch. Container execution uses the same
bounded capture/drain operation independently for stdout and stderr, preserving
the timeout, kill/reap and kill-on-drop behavior. All 31 existing MCP tests pass;
a new duplex regression verifies concurrent oversized output is drained on both
streams while only the output prefix is retained. Linux cross-target all-feature
Clippy passes.

The first Linux run for the host-tracing commit exposed a test-fixture permission
assumption: `/proc/1/ns/pid` is inaccessible to the CI user. Forwarding tests now
use the existing fixed collector fixture, avoiding privileged machine state.
Production namespace validation remains unchanged. Linux CI at `4105315`
passes the root test suite, including all new host eBPF tests, and all-feature
Clippy. Agent, telemetry, DNS, common, no_std eBPF and secret-scan gates also pass.

### Proxy management and DNS allowlist

Both proxy-manager candidates and the asynchronous DNS-resolution candidate
are split, with all helpers below 50 lines. Proxy argument construction and
private mapping-file lifetime remain separate from process startup; original
and canonical CA paths still use the same rejection checks. DNS spawn/collection
and timeout bookkeeping preserve completed successes/failures, pending order,
duplicates, warning text and the blocking-task abort limitation.

The eight proxy-manager tests and six DNS allowlist tests pass. Added DNS
regressions cover timeout bookkeeping with duplicate pending hosts and a local
lookup followed by an empty/no-op resolution. Linux cross-target all-target,
all-feature Clippy passes.

### Configuration validation and conversion

All three original configuration candidates and new helpers are below 50 lines.
Behavior/backend requirements, platform restrictions, container networking,
share-path shape/resolution/warnings and Apple container conversion have explicit
responsibilities. The same validation order and defensive network rejection are
preserved, including native-to-Apple conversion outside Linux.

All 51 existing configuration tests and four integration tests pass. An added
regression verifies missing QEMU configuration is reported before a tracer
platform error, and platform errors before invalid share paths. Linux
cross-target all-target/all-feature Clippy passes.

### DTrace tracing

Both original DTrace candidates and new production helpers are below 50 lines.
Syscall-name decoding, schema-driven path reconstruction and single-field
fallbacks are separate from envelope parsing. Command selection/spawn, bounded
stderr logging, nonblocking stdout forwarding and failed-start resource cleanup
are named responsibilities. Double-start registration stays inside one lock;
cleanup still aborts stdout, aborts stderr, then kills/reaps the new child.

All 30 DTrace tests pass on macOS, including a new regression proving a full
channel drops events while stdout continues draining. Default-feature all-target
Clippy passes. Linux feature checks and CI remain required for the final head.

### VM agent tracing

Both original VM agent candidates and every new production helper are below
50 lines. Optional telemetry loss accounting, atomic startup reservation,
connection/readiness and failure recording are separate responsibilities.
Reservation rollback, receive cancellation, stop notification, bounded queues
and weak task ownership remain unchanged. All 13 VM agent tests and the eight
behavior-scenario/five monitoring-lifecycle integration tests pass. The added
telemetry regression verifies saturation marks the next delivered event with
EventLoss. Linux cross-target all-feature/all-target Clippy passes.

### CLI entry and startup command

Both main entry candidates and both startup-command candidates are split; their
new helpers are below 50 lines. Lock opening preserves creation-vs-stale state
and never truncates an existing file. Entry dispatch preserves config-free
commands and config/override/validation/authentication order. Startup keeps
pcap/proxy/engine/CA/state order, rollback, flush-warning suppression and shutdown
error priority. CA retry and trust-store update preserve nonfatal diagnostics.
All existing binary tests pass; regressions cover lock-file contents on reopen
and config-path dispatch without an existing configuration. Linux cross-target
all-target/all-feature Clippy passes.

### Sandbox command construction and container removal

QEMU and Apple Container argument construction are split into shared-volume,
network/port and agent authentication-file/environment responsibilities. All
three completed candidates (both argument builders and container stop) and new
helpers are below 50 lines. Exact argument ordering, first-share-only behavior,
snapshot protection and file-based secrets remain unchanged. Container removal
keeps its advisory diagnostics after stop, and state is cleared at the same point.

All 12 QEMU argument tests, nine Apple argument tests and the full Apple Container
test group pass. Linux cross-target all-target/all-feature Clippy passes.

### QEMU readiness and command exchange

Both readiness-wait and command-exchange candidates and their new helpers are
below 50 lines. A single handshake attempt owns its bounded handshake and
fatal-vs-retry decision; the outer boot deadline/backoff remain unchanged.
Exec exchange preserves connection-lock scope, broken-connection marking and
agent-error handling. PCAP records are still written only after successful
exchange and outside the connection lock.

All 32 QEMU sandbox tests pass. Existing handshake regressions additionally
verify fatal authentication errors propagate from the retry boundary, while an
immediate disconnect returns a retryable absence. Linux cross-target all-target,
all-feature Clippy passes.

### QEMU and Apple Container startup

The final original candidate in each backend is split. All original candidates
and all new production helpers in both backend modules are below 50 lines.
QEMU settings/image validation, token-file rotation, individual process startup,
Ready commit and failed-attempt logging/shutdown are separate responsibilities.
Token and secret-file lifetime, retry limits, output-buffer reset and startup
error/state handling remain unchanged. Apple Container settings/image checks,
private env-file preparation, boot arguments and process execution preserve
RAII cleanup and state/Ready sequencing.

All 33 QEMU and 28 Apple Container tests pass. Added regressions verify retry
rotation removes the old token file, stores a new value with mode 0600, and
cleans up after success; container spawn failures and unsuccessful exits restore
Stopped state without registering a container. Linux cross-target all-target,
all-feature Clippy passes.

## Outstanding work

The remaining inventory is work to complete, except explicitly documented
declarative exceptions. Other tracer, MCP/CLI, sandbox and
proxy candidates still require decomposition and appropriate boundary tests.
Full fmt/check/test and Linux/feature CI gates, final inventory, PR and merge
remain required before closing #49.
