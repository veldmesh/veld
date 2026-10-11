# Release notes

Notes for upcoming and past releases. User-visible behavior changes and
deployment coordination requirements are recorded here before they ship.

## Unreleased

- **Coord: add proof of key possession to `Register`.** A daemon's `Register`
  request now carries `timestamp_unix` and `signature` — an Ed25519 signature
  by the machine's private key over the request's identity fields (network,
  keys, endpoint, subnet routes and the timestamp) — and the coord server
  rejects a missing, invalid or stale (±120 s) signature with
  `Unauthenticated` before writing anything. Only the holder of an Ed25519
  private key can register or update the peer whose ID is that key.

  **The client and the coord server must be released together.** The wire
  change is a backwards-compatible proto3 addition, but the behavior is not:
  an updated coord server rejects registrations from older clients (they never
  sign), while older coord servers simply ignore the new fields. Ship `veld` /
  `veld-daemon` and `veld-coord` in the same release; self-hosters must
  upgrade their coord server before (or together with) their daemons.

  Signed key rotation (an old-key → new-key handover) is deliberately out of
  scope for this change and is the planned follow-up.

- **Coord: sign peer `name` in `Register` proof of possession.** The `name`
  field is now covered by the Ed25519 signature (domain bumped to
  `veld-coord-register-v2`), so a peer's displayed name cannot be tampered
  with after registration. The golden test vector in
  `internal/crypto/register_test.go` has been updated.

- **Coord: uniform `Unauthenticated` errors for `Register`.** The server now
  returns a single generic message (`"invalid register signature or timestamp"`)
  for all signature and timestamp verification failures, avoiding leakage of
  which check failed or the server's clock. Detailed reasons are still logged
  server-side (including a "check system clock" hint for timestamp failures).
  A new test (`TestServer_Register_UniformAuthError`) asserts the client-visible
  message is identical for a stale timestamp and a bad signature.

- **Docs: document `Register` replay window.** `docs/ARCHITECTURE.md` now notes
  that a captured `Register` can be replayed within the ±120 s window (e.g.
  to re-add a peer after it leaves), but this requires both the account token
  and the captured request; the window is narrow enough to limit practical
  risk while tolerating ordinary clock skew.