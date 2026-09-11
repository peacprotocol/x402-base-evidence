# Changelog

Released versions are tagged; the tag `v0.1.0` and its release asset are unchanged by anything below.

## Unreleased

### Changed

- The reference origin releases a cached settled result only to a request that presents the same payment
  identifier, the same request fingerprint and the same signed EIP-3009 authorization the facilitator verified
  and settled. Previously a decodable payload carrying only the identifier was served the cached body. A
  same-identifier request carrying a different authorization is refused with 409 and neither settles nor
  discloses. The captured authorization is bearer-equivalent within the run; this is a narrower boundary,
  not proof of current wallet possession. (`src/flow/server.ts`)
- Requests under one payment identifier are serialized through an explicit per-identifier operation state:
  `pending`, `completed`, `rejected`, `uncertain`. A matching retry that arrives while the first attempt is in
  flight waits for it and is then served the cached result; it never reaches verification, execution or
  settlement on its own. A rejected attempt releases the identifier for a corrected retry. A settlement whose
  outcome is unknown (the settlement step raised) marks the identifier `uncertain` for the lifetime of the
  process; retries are refused with 409 and the operator must reconcile out of band. The store is in-memory,
  bounded by `identifierCapacity` (default 1024; new identifiers are refused with 503 at capacity, nothing is
  evicted) and lost on restart. No durability, restart recovery or multi-instance coordination is provided.
- The offline verifier reports under profile `x402-base-evidence/offline-verification/2`. Every check carries
  a category (`integrity`, `structure`, `consistency`, `native`) and the report ends with a fixed statement of
  what the verifier establishes and what it does not.
- The verifier decodes the captured native x402 field values with the same bounded staged parser the capture
  path uses and, when the record's terminal state is `response_write_attempted`, holds them to the record
  and the observation: accepted terms, EIP-3009 authorization fields and digest, payment identifier against
  the record reference, resource URL against the request binding, the advertised requirements, and the
  settlement response against the settlement observation. For every other terminal state the native
  artifacts are preserved as presented and reported as such, so evidence of a rejected or malformed payment
  attempt remains verifiable. Previously the native artifacts were digest-checked only, so a producer could
  re-sign evidence whose native amount disagreed with the record without a verifier failure.
- `chain-observation.json` is held to a committed closed schema (`schemas/chain-observation.v1.schema.json`),
  as the two binding documents already were.
- The request-body digest recorded in the request binding is reported as recorded and not recomputed, because
  the request body is not part of the evidence directory.

### Compatibility

- Evidence produced by v0.1.0 verifies under profile 2. The archived run `live-20260828T214534z` and the
  committed fixture pass every added check; the frozen `verification-report.txt` inside the archived bundle was
  written by the profile-1 verifier and lists fewer lines, as `docs/LIVE_BASE_SEPOLIA_ACCEPTANCE.md` already
  notes for the supplied-key checks.
- The fixture facilitator gained an optional `settlementBarrier` used only by the concurrency tests.
- A client that retries a paid request must resend the payment authorization it originally presented. A client
  that re-signs a fresh authorization under the same identifier is refused with 409 rather than settled twice.
- Upstream pins are unchanged (`@x402/*` 2.23.0, `@peac/*` 0.16.4).

### Added

- Acceptance cases `EVM-IDEM-001` to `EVM-IDEM-004` and `EVM-NATIVE-001` to `EVM-NATIVE-007`.

## 0.1.0

First release: the Base x402 `exact` / EIP-3009 payment-evidence reference, the deterministic validation corpus,
the byte-reproducible offline fixture, the acceptance matrix, and the frozen evidence of one live Base Sepolia
acceptance run. See the release notes on the `v0.1.0` tag.
