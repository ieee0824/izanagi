# Protocol v2: bincode → postcard

## Choice and compatibility

Postcard 1.1 uses the existing Serde models and specifies a stable wire format
since 1.0 (https://postcard.jamesmunns.com/wire-format).
It is not byte-compatible with bincode. Both host and agent must be upgraded
together, as already required by the positional event schema.
Do not automatically retry with v1 or downgrade authentication.

## Frame

`magic:u8=0xff | version:u8=2 | type:u8 | body_length:u32 LE | postcard body`

Authenticated frames append `sequence:u64 LE | HMAC-SHA256:32 bytes`.
The MAC covers the entire seven-byte header, body, and sequence. Verify the MAC
and sequence before deserializing. Commit the receive sequence only after the
body and message type have been validated.

The body length remains fixed-width little endian. Postcard's body uses varints;
enum order and positional field order remain part of the schema. Schema changes
that are not compatible require a new protocol version, not just serde defaults.
HashMap ordering is not canonical; fixed fixtures must not depend on its order.

The encoder enforces the 1 MiB body limit while writing, rather than after making
an unlimited allocation. Decoders accept only bounded slices and reject unused
bytes. Postcard's slice decoder avoids advertising an impossible sequence length
as a preallocation hint; Serde's map visitor also uses cautious preallocation.
This is a wire-size bound, not a claim that decoded heap usage is exactly 1 MiB.
Malformed collection lengths are covered by regression tests. The current schema
contains no recursive or variable-length zero-sized-element collections; review
resource limits again before adding such types.

Standalone event bytes use the same `0xff,2` prefix followed by postcard data.
Old event payloads must not be read as v2; regenerate stored payloads if applicable.

## Deployment

1. Stop running sessions with the old host (`izanagi down`) before upgrading.
2. Build the new host and agent from the same revision (`make build` and
   `make build-agent-gnu` for the Debian image).
3. Rebuild the guest image (`make qemu-image`) and any container image in use
   (`make image`). Preserve the old binary and image as a matching rollback pair.
   Do not reuse an image containing the v1 agent with the v2 host.
4. Start a fresh session and verify Hello/Ready, command execution, shell and trace
   forwarding with the configured authentication mode. Guest token and shared
   secret provisioning remain unchanged.
5. An `incompatible protocol version` error means the peer/image is outdated.
   Update both sides; do not disable authentication to bypass it.

Rollback: stop new sessions, restore the old host AND old guest/container image,
then create a new session. A live connection cannot be migrated between versions.

## Validation gates

- All variants and event types round-trip, with fixed v2 fixtures.
- Reject legacy versions, truncated frames, oversized bodies, invalid lengths,
  unknown types, type/body mismatches and trailing data.
- Authenticated tampering, wrong keys, replay/gaps and overflow remain rejected.
- Host/agent TCP handshake and Linux/macOS CI pass.
- RustSec scans all lockfiles without the bincode maintenance warning; CodeQL passes.
- Before release, smoke-test the rebuilt QEMU image: authenticated Hello/Ready,
  Exec, Shell and Event forwarding, and rejection of an old-image/new-host pair.
