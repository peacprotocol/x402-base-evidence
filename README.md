# x402 Base Evidence

Reference implementation of payment evidence for the x402 v2 `exact` scheme (EIP-3009) on Base.
A paid resource behind the upstream x402 middleware captures the native payment artifacts, binds
them to the HTTP request and to the bytes the origin produced, records a sealed-L2 settlement
observation, issues a signed PEAC record over the resulting digests, and verifies that record
offline under a supplied public key.

One live acceptance run has been executed on Base Sepolia and its evidence is published with the
`v0.1.0` release ([`docs/LIVE_BASE_SEPOLIA_ACCEPTANCE.md`](docs/LIVE_BASE_SEPOLIA_ACCEPTANCE.md)).
The strongest claim that run supports: the named Base RPC source reported the transaction in a
sealed L2 block, and the admitted receipt contained the expected token transfer.

Independent open-source reference, non-normative. Not an endorsement or official implementation of
Base, Coinbase, the x402 Foundation, Circle, or any facilitator. Apache-2.0.

## Quickstart

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm test           # full gate: validation vectors, rejection corpus, offline flow, security matrix, acceptance, typechecks
pnpm demo:fixture   # offline end-to-end run; rewrites the committed evidence byte-identically
pnpm verify         # offline verification of the committed fixture evidence
pnpm tamper-demo    # one edited field in a copy, one named failure
```

Verify the archived live evidence from a clean clone (files and a public key, no network):

```bash
# download x402-base-evidence-live-20260828T214534z.tar.gz from the v0.1.0 release, then:
echo "240dad2f7adcc5777aa63f5ecaffe02fc1b8b6a401a444d6771c730f6318381e  x402-base-evidence-live-20260828T214534z.tar.gz" | shasum -a 256 -c
tar -xzf x402-base-evidence-live-20260828T214534z.tar.gz
shasum -a 256 -c evidence/base-sepolia/live-20260828T214534z/SHA256SUMS
pnpm verify -- --evidence out/live-20260828T214534z --public-key out/live-20260828T214534z-issuer.pub.json
```

All scripts:

| Command | Purpose |
|---|---|
| `pnpm test` | the whole gate, in order, stopping at the first failure |
| `pnpm test:golden` / `test:negative` / `test:evm` / `test:acceptance` | validation vectors, rejection corpus, security/replay/binding/tamper matrix, acceptance completeness |
| `pnpm typecheck` / `typecheck:compat` | TypeScript 7 primary, TypeScript 6 compatibility gate |
| `pnpm demo:binding` / `demo:offline` | deterministic binding walkthrough, with egress diagnostics installed |
| `pnpm verify -- --evidence <dir> --public-key <file>` | verify any evidence directory |
| `pnpm demo:live:prepare` / `demo:live` | Base Sepolia preflight (spends nothing) / one live paid request |
| `pnpm gen:golden` | regenerate the vectors, then review the diff |

## What it does

- **Staged validation** of the three x402 v2 fields (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`,
  `PAYMENT-RESPONSE`) against the upstream runtime validators, reporting each stage and naming the
  authority that produced each verdict.
- **Two binding documents** tying the payment to the operation requested (RFC 9421 request
  components) and to the bytes the origin produced, canonicalized with RFC 8785 (JCS).
- **A settlement-observation layer** that keeps what the native artifacts said should happen
  (`payment_expectation`) apart from what the facilitator reported (`chain_observation`) and from a
  separately attributed sealed-L2 RPC account, with an explicit recomputable comparison.
- **A signed PEAC record** over the binding and observation digests, and an **offline verifier**
  that recomputes every bound digest, holds the directory to a per-terminal-state presence
  contract, decodes the native artifacts and holds them to the record, and reports observer
  disagreement as a warning rather than resolving it.
- **A paid-resource flow** over the upstream express middleware with a paying client, an in-process
  facilitator and wallet for the offline path, and a byte-reproducible end-to-end fixture.

## Boundary

Verification establishes integrity and internal consistency under the supplied key. It does not
establish external truth, issuer identity (a supplied key is not a trust anchor), native payment
validity, chain finality, client receipt, or that a relying party should accept the evidence.
Chain facts are the issuer's recorded observations of what a named source reported.

The observation layer records **sealed L2 block inclusion only**, established when the receipt's
placement, the transaction object's placement and the sealed block queried by number agree and the
block's transaction list contains the transaction. It never uses the `pending` tag, never infers
inclusion from a receipt's existence, and never claims L1 batch inclusion, L1 finality or
confirmation counts. `receipt_status` is the EVM execution result; matching-payment evidence
additionally requires the expected token, from, to and value transfer event.

Native x402 artifacts remain authoritative for their own claims. This repository preserves,
digests and references them; it does not reinterpret settlement semantics, replace native
signature checks, or extend or modify the PEAC wire format, registries or conformance requirements.

## Status

| Capability | State |
|---|---|
| x402 v2 `exact`, EIP-3009 asset-transfer method, EVM (Base) identifiers | supported |
| `permit2` / `erc7710`, `upto`, batch settlement, streaming, MCP carriers, non-Base networks, mainnet | out of scope; `permit2` and `erc7710` are explicitly rejected |
| field capture, staged validation, request/result binding, validation corpus | implemented |
| end-to-end flow; PEAC issuance and offline verification | implemented; exercised offline and in one live Base Sepolia run |
| settlement observation (sealed-L2 contract) | implemented; exercised against synthetic sealed sources and one live run |
| payment-identifier retries: cached-result authorization, per-identifier serialization | implemented in-memory for one process; no durability or multi-instance coordination |
| x402 signed offers and receipts | preserved verbatim inside captured field values when present; not enabled in the deterministic fixture |

## Live run (Base Sepolia)

`pnpm demo:live:prepare` creates the payer key on first run (gitignored, never printed), checks
chain id, balance, recipient and issuer configuration, facilitator capability and output paths, and
spends nothing. Stopping here to fund the payer is the expected first result.

| Variable | Meaning |
|---|---|
| `PEAC_EXAMPLE_PAY_TO` | Required. Base Sepolia address the operator controls, receiving the payment. No default. |
| `PEAC_EXAMPLE_ISSUER` | Required. Canonical `https` origin of the record issuer (`https://issuer.example`, no path or trailing slash). A non-canonical value fails preflight. |
| `PEAC_EXAMPLE_RPC_URL` | Optional. Defaults to `https://sepolia.base.org` (rate-limited). Only the origin is printed or recorded. |
| `PEAC_EXAMPLE_FACILITATOR_URL` | Optional. Defaults to `https://x402.org/facilitator`. |

`pnpm demo:live` re-runs the preflight, refuses to proceed unless every check passes, then performs
one paid request: real EIP-3009 authorization, facilitator verification and settlement, origin
result, and a bounded sealed-L2 observation through the configured RPC endpoint (~2 s cadence, fixed
deadline, transient states only retried). The evidence is written transactionally under `out/`,
verified offline before it is finalized, and a tamper copy is shown to fail. The facilitator submits
the transaction and pays gas; the payer needs only Base Sepolia test USDC.

## Validation model

Decoding is not validation: the upstream `decode*Header` functions accept any base64 JSON object.
Validation therefore runs as ordered stages, each reported as `accepted`, `rejected` or
`not_evaluated`, stopping at the first failure so the report names the stage that refused.

```text
transport          strict standard base64, within the declared size bound
json               UTF-8 text the upstream decoder accepts as a JSON object
duplicate-members  no ambiguous object members (RFC 7493 discipline; a binding-safety rule of this profile)
upstream-schema    the x402 v2 schema for the artifact type, evaluated by upstream code
scheme-payload     the scheme-specific payload member, for payment payloads
extensions         declared x402 extensions, evaluated by the upstream extension APIs
```

| Artifact | `upstream-schema` | Authority |
|---|---|---|
| `PAYMENT-REQUIRED` | evaluated | `@x402/core` v2 schema |
| `PAYMENT-SIGNATURE` | evaluated | `@x402/core` v2 schema, plus this profile's scheme-payload stage |
| `PAYMENT-RESPONSE` | always `not_evaluated` | first-party local structural check (`x402-base-evidence/local-settle-response-shape@1`); the pinned upstream package exports no runtime validator for it, which the import smoke test re-checks on every run |

**Scheme payload.** The upstream v2 schema types `scheme` as a free string and `payload` as an open
record, so this profile checks the exact/EVM payload itself: the asset-transfer method is resolved
first (`eip3009` explicit or absent is accepted; `permit2`, `erc7710` and unknown values are rejected
with `unsupported_asset_transfer_method`), then the EIP-3009 authorization fields (hex addresses,
bytes32 nonce, decimal-string amounts and timestamps) and the required 65-byte signature are
shape-checked. Signature validity, payer recovery, validity windows and matching against the
requirement remain facilitator semantics. `extra.name` / `extra.version` are EIP-712 domain
parameters the facilitator cross-checks on chain and are deliberately not checked here.

**Type-states.** `CapturedX402Artifact` authorizes nothing. `SchemaValidatedPaymentRequiredArtifact`,
`SchemaValidatedPaymentPayloadArtifact` and `StructurallyCheckedSettleResponseArtifact` are distinct
types produced by fail-closed promotion functions; a captured artifact is not assignable where a
validated one is required (enforced by `@ts-expect-error` vectors in the rejection corpus).

**Diagnostics** are bounded: at most eight `{stage, code, path}` entries from a closed code
vocabulary, path depth at most eight, one kibibyte total, no validator message text retained.

**Acceptance matrix.** Every acceptance case has a stable identifier in `src/acceptance-ids.ts`; the
suites record each as it executes and `pnpm test:acceptance` fails if a declared case did not run.
Two cases are scoped to CI (repeated-run byte comparison, run with networking disabled).
`pnpm test:reset` removes the ledger directory before any suite runs so stale state cannot mask an
omitted case.

### Verifier check inventory

`pnpm verify` runs under profile `x402-base-evidence/offline-verification/2` and prints every check
with its category. Profile 1 was the v0.1.0 check set; profile 2 adds the native-artifact agreement
checks, the chain-observation schema and the request-body preimage statement. v0.1.0 evidence
verifies under profile 2; the `verification-report.txt` frozen inside the v0.1.0 asset was written
by profile 1 and lists fewer lines.

| Category | Checks | A pass establishes |
|---|---|---|
| `integrity` | record signature and schema under the supplied key; every bound digest recomputed from the document beside the record; the origin result body against the digest in the result binding; the supplied key file's declared algorithm, `kid` and issuer against the record | the bytes are intact relative to the supplied key and the record binds exactly these documents |
| `structure` | record type; required extension groups; each binding document and the chain observation against its committed closed schema; the artifact set against the presence contract for the recorded terminal state; observation profile, scheme and attribution; settlement facts consistent with the outcome; an inclusion claim carries its sealed-block basis; the request-body digest is reported as recorded, not recomputed | the documents are the shapes this reference produces and the directory is complete for the state it claims |
| `consistency` | fields the record and the observation both carry (network, terminal state, asset, amount, settlement-response digest, origin-result digest); the recorded comparison recomputed; the transfer-event verdict evaluated whenever a receipt is recorded | the documents describe the same interaction |
| `native` | each present native field value decoded with the bounded staged parser; when the terminal state is `response_write_attempted`: accepted terms, EIP-3009 authorization fields and digest, payment identifier against the record reference, resource URL against the request binding, advertised requirements against the accepted terms, settlement response against the settlement observation | the native artifacts say what the record says they say |

Native agreement is held only where the record claims a settled payment. For every other terminal
state the present native artifacts are decoded and reported as *preserved as presented*, so a
refused, malformed or mismatched payment attempt remains verifiable evidence of the attempt.
Warnings (observer disagreement) never affect the verdict.

## Payment identifier

`payment-identifier` is an x402 extension carried in `PaymentPayload.extensions`, extracted and
validated with the upstream extension APIs. The reference origin implements its deduplication with
one explicit retrieval rule:

- On first use the identifier is bound to a normalized request fingerprint (method, target, scheme,
  network, asset, amount, recipient) and to the signed EIP-3009 authorization the payload presents.
- A cached settled result is released only to a request presenting the same identifier, the same
  fingerprint and the same signed authorization the facilitator verified and settled. A different
  request or a different authorization under the same identifier is refused with 409 and neither
  settles nor discloses.
- Requests under one identifier are serialized through an operation state (`pending`, `completed`,
  `rejected`, `uncertain`). A matching retry that overlaps the first attempt waits and is served its
  result: one identifier yields at most one verification, one execution and one settlement. A
  rejected attempt releases the identifier; an unknown settlement outcome leaves it `uncertain`,
  refusing retries for the life of the process.
- A payload without a valid identifier is refused with 400 before verification, because the
  declaration marks it required.
- The store is in-memory, bounded (`identifierCapacity`, default 1024; new identifiers are refused
  with 503 at capacity, nothing is evicted), and lost on restart. The captured authorization is
  bearer-equivalent within the run. Durable state, restart recovery, multi-instance coordination and
  tenant scoping are outside this reference.

## Request components and byte semantics

Components follow RFC 9421 derived-component semantics as the origin observed them: `@method`
exact, `@scheme` lowercased, `@authority` lowercased with the default port omitted, `@path` verbatim,
`@query` with its leading `?`. They are never rebuilt from an absolute URL or from client headers.
Only the `direct-origin` proxy-trust profile is implemented.

Bodies are `Uint8Array`. x402 field values must be visible ASCII and are digested as UTF-8. Header
encoding is delegated to the installed x402 codec. Digests use `sha256:<64 lowercase hex>`, an
application-local syntax distinct from RFC 9530 `Content-Digest`. Size bounds are application-local
choices.

## Standards and pins

| Standard | Role |
|---|---|
| RFC 9421 | request-component derivation (values only; no HTTP message signature is created or verified) |
| RFC 8785 (JCS) | canonicalization before digesting; `@peac/protocol` is the sole production canonicalizer, `src/jcs-independent.ts` a test-only oracle |
| RFC 7493 (I-JSON) | duplicate-member rejection |
| CAIP-2 | `eip155:84532` for Base Sepolia |
| EIP-3009 | `transferWithAuthorization`, the validated payload |
| JSON Schema 2020-12 | closed schemas in `schemas/` for the binding and observation documents |

| Dependency | Pin |
|---|---|
| `@x402/core`, `@x402/evm`, `@x402/express`, `@x402/extensions` | `2.23.0` |
| `@peac/crypto`, `@peac/kernel`, `@peac/protocol`, `@peac/schema` | `0.16.4` |
| TypeScript | `7.0.2`; `6.0.2` compatibility gate |
| Node.js | `^22.13.0 \|\| ^24.0.0` (CI: 22, 24; 26 as a non-blocking canary) |
| pnpm | `11.23.0`, pinned with its integrity hash |

## Security

See [`SECURITY.md`](SECURITY.md). No live, funded or reusable secret keys and no unconsumed payment
authorizations belong in this repository. The test-only fixture keys and the synthetic signed
fixtures they produce are public test vectors. Live-mode keys stay gitignored under `.local/`. CI
runs a full-history secret scan with a self-proving canary.

## Relationship to PEAC and x402

PEAC is a protocol for portable, verifiable interaction records; this repository is a non-normative
reference example of it. x402 v2 provides signed offers, receipts, payment identifiers and builder
codes, binding payment artifacts to one another. This example adds two application-local
documents that bind them to the operation requested and to the bytes the origin produced:

| Profile | Binds |
|---|---|
| `org.peacprotocol.examples.payment-evidence/request-binding/1` | RFC 9421 request components, content type and encoding, request-body digest, selected observed-value digests |
| `org.peacprotocol.examples.payment-evidence/origin-result-binding/1` | status, content type and encoding, digest of the bytes the origin produced |

Selected network-neutral modules are ported from
[`x402-solana-evidence`](https://github.com/peacprotocol/x402-solana-evidence) v0.1.0; per-module
status is in [`docs/PROVENANCE.md`](docs/PROVENANCE.md). No runtime dependency exists between the
two repositories.

## License

Apache-2.0
