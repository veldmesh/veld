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
