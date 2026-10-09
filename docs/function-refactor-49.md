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
final remaining definitions, including helpers introduced by this work.

The syntax audit was repeated against the issue reference `de356ea`: it finds
79 production candidates, exactly the same file/function set as the starting
main baseline. All 79 were decomposed; no production candidate was excluded.
The remaining inventory has one entry: the new 50-line declarative
`finish_snapshot` helper, justified below.

The per-component validation notes below record checks performed during
implementation. The final verification section supersedes earlier pending-CI
notes.

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

### Landlock enforcement and Engine monitoring

Both Landlock candidates and the Engine startup candidate are split, and all
new production helpers are below 50 lines. Landlock runtime directories,
configuration files and process metadata retain their exact ordered rules and
access masks. Child execution still builds the ruleset before fork and only
applies it inside pre_exec, with no new allocation in that boundary.
Engine startup/authentication rollback, callback wrapping/offloading, saturation
warnings, monitoring failure publication and channel/shutdown handling have
separate responsibilities. Startup and failure ordering are unchanged.

The eight macOS Landlock/stub tests, 22 Engine tests and five monitoring lifecycle
integration tests pass. Linux cross-target all-target/all-feature Clippy passes.
A new Linux enforcement regression checks an explicitly allowed /etc file is
readable while another host-readable /etc file remains denied. Actual Linux
execution remains a CI gate for this commit.

### Interactive MITM configuration

The final root CLI candidate is split into DNS selection, HTTP/TLS addresses,
CA output, hidden mapping input and allowed-host prompts. Every new production
helper is below 50 lines. Prompt ordering/defaults, disabled-section replacement,
address parsing/error behavior, hidden mapping entry and private TOML persistence
are unchanged. The three config-command tests pass; an added regression verifies
new-directory/file permissions and private overwrite without trailing content.
Linux cross-target all-target/all-feature Clippy passes.

### DNS proxy

All three original DNS proxy candidates and new production helpers are below
50 lines. Configuration/allowlist loading, UDP task setup, malformed-query
handling and upstream-response validation are separate responsibilities.
Question normalization, FORMERR/SERVFAIL identity, allowlist forwarding, blocked
responses and all-section rebinding checks retain their behavior and ordering.
Existing listener/task/shutdown behavior is preserved.

All 20 component tests and all-target Clippy pass on macOS. Three new regressions
use a local UDP upstream to verify private IPv4/IPv6 rejection in answers,
additionals and authorities; exact public-response forwarding and malformed
upstream rejection; and FORMERR/questionless handling without upstream traffic.
Two pre-existing response-module Clippy warnings were fixed by scoping a test
import and collapsing an equivalent condition. Linux CI at `492dfd9` passes
root Linux/macOS tests, including the new Landlock enforcement regression, all
component tests, eBPF checks/build, all-feature Clippy and secret scan.

### Kernel eBPF tracepoints

Both original kernel eBPF candidates and all new helpers are below 50 lines.
User-path capture, connector generation, socket identity and socket-address
reads are separate inline(always) responsibilities. Ring reservation loss,
userspace probe-read bounds, submission/discard order, connector ownership,
IPv4/IPv6 scalar reads and socket-state cleanup are preserved.

The no_std release build passes locally with nightly-2026-02-12,
bpfel-unknown-none and build-std=core. The pre-refactor source at `bec9e9e` was
built with the same toolchain. ELF function inspection finds the same 23 function
symbols: 18 have identical executable bytes; the five affected tracepoints
(openat/stat/access/execve/inet_sock_set_state) are each 16 bytes shorter after
optimization. No extracted helper remains as an independent function. This
confirms inlining/code-generation scope, not a live kernel-verifier/load test.
Linux CI no_std build remains required at the final head.

### HTTP request parsing, HTTPS upstream and TLS SNI

Four original HTTP-capture candidates and all new helpers are below 50 lines.
Header/body reads, public-address resolution/selection, bounded upstream response
reading, extra-header construction and ClientHello prefix/extension parsing now
have separate responsibilities. Existing body caps, EOF/error handling, first
public address selection, one overall forwarding timeout, CRLF sanitation and
SNI bounds-check ordering remain unchanged.

All 58 component tests pass on macOS, including six added regressions: prefetched
versus separately read body caps, short-body EOF, invalid/oversized headers,
empty/private/mixed upstream address selection, the exact 1 MiB response limit,
and every truncated ClientHello prefix plus oversized extensions. Component
all-target check and formatting pass; existing unused legacy SNI/logger warnings
remain. CI at `8ee22b1` passes all standard CI and secret scanning; final-head
Linux/no_std and CodeQL gates remain required.

### HTTP capture startup

The HTTP binary entry point and every new startup helper are below 50 lines.
Behavior mode dispatch, CA loading/export, mapping and host preparation, listener
spawning and signal handling have separate responsibilities. CA export still
precedes mapping validation, logger creation still follows policy preparation,
and the listener select/error propagation and signal-task abort order are
unchanged. The 59 component tests pass; a new regression verifies certificate
output occurs before invalid mapping failure and logger setup. All-target check
and formatting pass with the same legacy unused-path warnings.

### HTTP metadata forwarding and MITM lifecycle

All six remaining original HTTP candidates and every new helper are below
50 lines. Metadata forwarding separates absolute targets, header-name/framing
validation, upstream request construction, bounded response reading, response
validation/writing, socket identity, request/outcome emission and configuration
validation. MITM separates TLS setup, accepted-connection scheduling, handshake,
decrypted HTTP parsing, allowlist routing, substitution/forwarding and original
request logging. Timeouts, permits, error priority, partial byte counts, HEAD
content length, capture-before-forward behavior and secret-free logging are
preserved. Public interfaces remain unchanged.

All 64 HTTP component tests pass on macOS. Five new regressions cover ambiguous
response framing, HEAD length versus invalid GET bodies before any write,
partial failed-transfer counters/policy classification, port parsing fallback,
and malformed/idle TLS handshakes. All-target check and formatting pass.
Component Clippy succeeds with existing unused-path, public argument-count and
collapsible-condition warnings; the extracted forwarder introduces no new
argument-count warning. The final syntax inventory contains only the documented
50-line declarative telemetry snapshot constructor.

## Final verification

The final implementation is `a84f542`. All 79 original production candidates and
all newly extracted production helpers are below 50 physical lines except the
single justified `finish_snapshot` constructor (50 lines). The checked-in final
inventory is reproduced by the command in `tools/function-audit/README.md`.
The public signature diff contains only internal host-eBPF module helpers and
a cfg(test) collector fixture; existing public APIs and wire definitions are
unchanged. Tests and source review cover error ordering, authentication,
startup rollback, cancellation, process/PTY cleanup, bounded queues/output,
private file persistence, DNS/IP restrictions and secret-free telemetry.

Local final checks on macOS pass:

- Root and all seven component/tool manifests: `cargo fmt -- --check`.
- Root all-target tests: 402 library, 78 binary and 51 integration tests.
- All five userspace components: `cargo check --offline --all-targets`.
- HTTP/TLS: all 64 tests, including 12 added regressions across this PR.
- Root Linux cross-target all-target/all-feature Clippy with `-D warnings`.
- Kernel eBPF no_std release build and before/after ELF inspection, as described
  above. This is build/code-generation validation, not a live privileged kernel
  load/verifier test.

[CI run 37864255646](https://github.com/ieee0824/izanagi/actions/runs/37864255646)
at `a84f542` passes all ten jobs: root Linux tests with `landlock,ebpf`, root
macOS tests, all five component test suites, common no-default-features check,
agent eBPF feature check, actual no_std BPF release build, formatting and
all-feature/all-target Clippy. The associated Security workflow passes dependency
review and secret scanning. Existing HTTP legacy dead-code/argument-count and
collapsible-condition warnings are outside the root Clippy gate and do not
prevent its component check/test; no new argument-count warning remains.

The follow-up commit only finalizes this audit record. Merge of
[PR #52](https://github.com/ieee0824/izanagi/pull/52) is gated on its final-head
CI, Security and CodeQL results; their authoritative state is available on the PR.
