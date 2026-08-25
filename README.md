# x402 Base Evidence

Non-normative reference implementation for the x402 v2 `exact` scheme using the EIP-3009
asset-transfer method on Base: a complete paid-resource flow over the upstream x402 middleware,
staged validation of native x402 payment artifacts against the upstream runtime validators,
origin-observed HTTP request/result binding through RFC 9421 request-component derivation and JCS
canonicalization, a Base settlement-observation layer with an explicit sealed-L2 contract, signed
PEAC record issuance over the resulting digests, and offline verification of that record under a
supplied public key, with a deterministic validation corpus and a byte-reproducible offline
end-to-end fixture.

A live Base Sepolia execution of this flow has not yet been performed from this repository; see
[§4 Current implementation status](#4-current-implementation-status).

Independent open-source reference implementation; not an endorsement or official implementation of
Base, Coinbase, the x402 Foundation, Circle, or any facilitator.

This repository reuses selected network-neutral validation and binding patterns from
[`x402-solana-evidence`](https://github.com/peacprotocol/x402-solana-evidence) v0.1.0 while
remaining standalone. Some modules were hand-ported with their semantics unchanged, some reuse the
pattern with their contents reauthored, and the Base/EVM-specific artifact validation is
implemented against the corresponding upstream x402 EVM shapes. No byte-identical parity is claimed
for any file; the parity that exists is source-level only, established by hand and not
automatically re-verified. See [`docs/PROVENANCE.md`](docs/PROVENANCE.md) for the per-module status
and why each stays local rather than becoming a shared dependency (no runtime dependency exists
between the two repositories, and none is introduced by this note).

## 1. What this is

- A staged validator for the three x402 v2 payment fields (`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`,
  `PAYMENT-RESPONSE`) on the EVM `exact` scheme with the EIP-3009 asset-transfer method, reporting
  each validation stage independently and documenting which authority produced each verdict.
- Two application-local binding documents that tie payment artifacts to the HTTP operation requested
  and to the bytes the origin produced, using RFC 9421 request-component derivation and RFC 8785
  (JCS) canonicalization.
- A deterministic validation corpus: fixtures built against real upstream x402 types, golden vectors
  with hard-coded expected digests, and a rejection corpus covering the failure modes below.
- A reference paid-resource flow: an express origin behind the upstream x402 payment middleware, a
  paying client, an in-process fixture facilitator and wallet stand-in for the offline path, and a
  deterministic end-to-end run whose committed evidence is byte-identical across runs.
- A Base settlement-observation layer that keeps what the native x402 artifacts said should happen
  (`payment_expectation`) structurally apart from what was observed afterwards
  (`chain_observation`), records a sealed-L2 RPC account separately when one was asked, and writes
  an explicit expected-versus-observed comparison instead of merging the two into one truth claim.
- Signed PEAC record issuance covering the binding and observation digests, and an offline verifier
  that recomputes every bound digest, holds the artifact set to a per-terminal-state presence
  contract, and reports observer disagreement as a warning rather than resolving it.
- The Base/EVM counterpart to the network-neutral validation and binding patterns first published
  in the Solana reference, reused here rather than shared as a dependency.

## 2. What this is not

- **Not a live-proven payment flow yet.** The flow is complete and exercised offline against an
  in-process facilitator and wallet stand-in; no real Base Sepolia transaction has been executed
  from this repository, and no output of the offline path may be presented as a payment having been
  made.
- **Not an x402 conformance authority.** Validation authority is always named per artifact
  ([§6](#6-validation-and-acceptance-model)); nothing here should be read as an x402 standards body
  or as speaking for the x402 project.
- **Not a trust or settlement layer.** It does not settle payments, does not act as a payment or
  identity oracle, and does not extend or modify the PEAC wire format, record registry, extension
  registry or conformance requirements.
- **Not official Base, Coinbase, x402 Foundation, or Circle infrastructure**, and x402 did not
  "choose" this project — see the neutrality statement above.

## 3. Verification boundary

This repository captures native x402 artifacts and validates selected structure; computes
request/result binding documents and deterministic digests; issues a signed PEAC record covering
those digests; and verifies that record offline under a supplied public key.

It still does not establish: external truth; client receipt; chain finality; signer authority or
trust; completeness; issuer truthfulness; or a matching payment from `receipt_status` alone.

Verification establishes integrity and internal consistency under the supplied key — never external
truth. A supplied public key is not a trust anchor: it makes the record cryptographically
verifiable, and it says nothing about who holds the private key. A key obtained from the same place
as the evidence establishes internal consistency only.

It does **not** establish:

- that the key, or its holder, is trustworthy, or that the key represents any particular
  organization;
- that the statements inside a record are factually true;
- that any external event described by a record actually occurred;
- payment finality, or that a counterparty received a response.

Chain facts, where an observation layer records them, are issuer observations: a service records a
transaction and the payment state the source reported under its application policy. Verification
establishes the integrity of that report; it does not establish blockchain consensus, and it does
not make the issuer's account of events authoritative.

Base distinguishes Flashblock preconfirmation, sealed L2 block inclusion, L1 batch inclusion and L1
finality. The observation layer here records **sealed L2 block inclusion only**, and only after
comparing the transaction's reported block number and hash against sealed block data queried by
explicit block number: for Base's documented public HTTP JSON-RPC the caller's block tag selects
the confirmation semantics, so the canonical observation never uses the `pending` tag, and sealed
inclusion is never inferred from the mere existence of a transaction receipt. `receipt_status` is
the EVM execution result and nothing else — not an inclusion level, not finality, and not by itself
evidence that the expected payment occurred; matching-payment evidence additionally requires the
expected token, from, to and value transfer event plus native x402 validation. L1 batch inclusion
and L1 finality are never claimed unless separately observed, and no such observation is
implemented. Disagreement between two separately sourced observations is reported as a
disagreement, not resolved into either side being authoritative.

## 4. Current implementation status

| Capability | State |
|---|---|
| x402 v2 | supported |
| x402 v2 `exact` / EIP-3009 asset transfer method | supported |
| `exact` with `permit2` or `erc7710` asset transfer methods | out of scope; explicitly rejected |
| EVM (Base) artifacts and identifiers | supported |
| field-value capture and staged validation | implemented |
| request binding and origin-result binding | implemented |
| deterministic validation vectors and rejection corpus | implemented |
| end-to-end payment flow | implemented; exercised offline against an in-process facilitator |
| PEAC signed record issuance and offline verification | implemented |
| settlement observation layer (sealed-L2 contract) | implemented; exercised against synthetic sealed sources |
| live Base Sepolia execution and live settlement observation | not yet performed from this repository |
| x402 signed offers and receipts | preserved when present inside captured field values; not enabled in the deterministic fixture (see [§9](#9-relationship-to-peac-x402-and-base)) |
| scheme `upto` | out of scope |
| batch settlement | out of scope |
| streaming responses | out of scope |
| mainnet | out of scope |
| MCP carriers | out of scope |
| non-EVM / non-Base networks | out of scope |

## 5. Quickstart

```bash
corepack enable
pnpm install
pnpm test          # ledger reset, imports, deterministic validation vectors, rejection corpus,
                    # offline end-to-end flow, security/replay/binding/tamper matrix,
                    # acceptance matrix, typechecks
pnpm demo:fixture  # offline end-to-end run; rewrites the committed evidence byte-identically
pnpm verify        # offline verification of the committed evidence
pnpm tamper-demo   # edit one bound field in a copy, watch the named check fail
```

### Run

```bash
corepack enable

pnpm install --frozen-lockfile   # exact versions from the lockfile
pnpm test                        # the full gate, in order (see below)
pnpm test:reset                  # clean the acceptance ledger directory (runs first, always)
pnpm test:imports                # upstream export paths and exact version pins
pnpm test:golden                 # deterministic validation vectors, staged-validation reporting,
                                  # golden-vector drift check
pnpm test:negative                # rejection corpus
pnpm test:ledger-integrity       # proves stale ledger state cannot mask an omitted case
pnpm test:flow                   # offline end-to-end flow (also run under plain node)
pnpm test:evm                    # security, replay, evidence, binding and tamper matrix
pnpm test:acceptance             # every declared acceptance case executed
pnpm typecheck                   # TypeScript 7, primary
pnpm typecheck:compat            # TypeScript 6, compatibility gate
pnpm demo:binding                # deterministic walkthrough of the binding layer
pnpm demo:fixture                # offline end-to-end run; rewrites the committed evidence
pnpm demo:offline                # binding walkthrough with egress diagnostics installed
pnpm verify                      # offline verification: files and a public key, nothing else
pnpm verify -- --evidence <dir> --public-key <file>   # verify any evidence directory
pnpm tamper-demo                 # one edited field, one named failure
pnpm demo:live:prepare           # Base Sepolia preflight (the only network-using command)
pnpm gen:golden                  # regenerate the vectors, then review the diff
```

The offline end-to-end run writes `fixtures/expected-evidence/`: a signed record, the two binding
documents, the chain-observation document, the captured field values, the origin result bytes, and
a verification report. Every file is byte-identical across runs; the determinism note inside the
directory states exactly which inputs are pinned to achieve that, and that no payment occurred.

Fixtures are synthetic. The network is Base Sepolia (`eip155:84532`, declared as an explicit local
constant) and the asset is the public Base Sepolia USDC contract, taken from the upstream package's
own default-asset registry. Every payer, recipient,
authorization nonce, transaction hash and signature value is a deterministic synthetic placeholder
derived from a descriptive label via SHA-256; this repository generates and possesses no private key
for any of them and does not use them for onchain execution.

## 6. Validation and acceptance model

**Decoding is not validation.** The upstream `decode*Header` functions are transport decoders: they
accept any base64-encoded JSON object, including one with no x402 structure at all. Treating a
successful decode as "this is a valid x402 object" reports a transport fact as a schema fact.

Validation therefore runs as ordered stages. Each is reported independently as `accepted`,
`rejected` or `not_evaluated`, and a failure stops the sequence, so the report always names the
exact stage that refused the artifact.

```text
transport          strict standard base64, within the declared size bound
json               UTF-8 text the upstream decoder accepts as a JSON object
duplicate-members  no ambiguous object members
upstream-schema    the x402 v2 schema for this artifact type, evaluated by upstream code
scheme-payload     the scheme-specific payload member, for payment payloads
extensions         declared x402 extensions, evaluated by upstream extension APIs
```

### Validation authority per artifact

Validation authorities are documented per stage, and they are not interchangeable. Upstream-schema
verdicts carry the pinned upstream schema authority; settle-response structural verdicts carry an
explicit first-party local authority. Scheme-payload checks are this reference's local profile
checks, and extension validation delegates to the named upstream extension API. The serialized
artifact does not carry a distinct authority identifier for every stage: it carries
`upstreamSchemaAuthority`, and, for settle responses only, a separate `localStructuralAuthority`.

| Artifact | `upstream-schema` | Authority | Notes |
|---|---|---|---|
| `PAYMENT-REQUIRED` | evaluated | `@x402/core` v2 schema | |
| `PAYMENT-SIGNATURE` | evaluated | `@x402/core` v2 schema | plus a scheme-payload check, see below |
| `PAYMENT-RESPONSE` | **always `not_evaluated`** | first-party local structural check | upstream ships no runtime validator for it |

For settle responses the upstream package exports no runtime validator at any export path — this is
a measured claim, not an assumption: the import smoke test searches every upstream export path for
a validator-shaped export on every run, so if upstream adds one, the gate fails and the local check
must be replaced. Rather than invent one and label the result "x402 schema validation", this example
reports a separate `localStructuralStatus` under an explicitly first-party authority string
(`x402-base-evidence/local-settle-response-shape@1`, never shaped like an `@x402/core` identifier),
whose documented basis is the pinned upstream package's own `SettleResponse` TypeScript declaration.

The scheme-payload stage exists because the upstream v2 schema types `scheme` as a free string and
`payload` as an open record. A payload naming an unsupported scheme, or carrying the wrong payload
member for the scheme it names, passes upstream schema validation. That check belongs to the scheme
profile, so this example performs it and reports it as its own stage rather than misattributing the
verdict to the upstream schema.

On Base, the exact scheme's payload uses EIP-3009 `transferWithAuthorization` (the asset-transfer
method native USDC and compatible tokens implement): a signature plus an authorization object
(`from`, `to`, `value`, `validAfter`, `validBefore`, `nonce`). The upstream `isEIP3009Payload` guard
only checks for the presence of an `authorization` member, and the upstream v2 schema types
`payload` as an open record, so a payload carrying an authorization and NO signature passes both.
x402 v2 section 5.2.2 marks `signature` and `authorization` Required for the exact EVM scheme, so
this profile requires the signature and checks the field-level shape (hex addresses, a bytes32
nonce, decimal-string amounts and timestamps, a 65-byte hex signature) as its own scheme-payload
stage, the same way the Solana reference's transaction-shape check went beyond the upstream
package's loose typing.

#### Asset transfer method

x402 v2 exact/EVM does not have one payload shape. It selects an asset-transfer method through
`extra.assetTransferMethod` on the payment requirements, which a payment payload echoes at
`accepted.extra.assetTransferMethod`. The specification defines `eip3009`, `permit2` and `erc7710`,
and a client defaults to `eip3009` when the field is absent. The pinned upstream package implements
two of them for this scheme: `AssetTransferMethod` is `"eip3009" | "permit2"`, and `ExactEvmScheme`
routes on `paymentRequirements.extra?.assetTransferMethod ?? "eip3009"`.

**This reference implements the EIP-3009 profile only** (`SUPPORTED_ASSET_TRANSFER_METHODS =
['eip3009']`). An absent method is read as the EIP-3009 default and accepted; an explicit `eip3009`
is accepted; any other value — `permit2`, `erc7710`, or anything a later revision adds — is rejected
at the scheme-payload stage with the diagnostic `unsupported_asset_transfer_method` at
`accepted.extra.assetTransferMethod`.

The method is resolved BEFORE the payload member is interpreted as EIP-3009. This ordering is the
whole point of the check: a `permit2` requirement carries a `permit2Authorization` payload, but
nothing prevents a counterparty pairing a `permit2` requirement with an EIP-3009-shaped payload. Had
the shape been checked first, that pair would have satisfied every EIP-3009 field check and this
profile would have reported an accepted scheme-payload stage for a transfer method it cannot
evaluate.

`extra.name` and `extra.version` are deliberately NOT checked here. Measured against the pinned
upstream package rather than assumed: they are the EIP-712 domain parameters the client supplies at
signing time, and that the facilitator cross-checks against the token contract's own on-chain
`name()` and `version()` reads, conditionally and over RPC. Neither is an envelope-shape property of
a captured payload, and this reference performs no chain access, so checking their mere presence
would add no assurance while duplicating upstream verification. They remain native x402 and
facilitator semantics.

The exact EVM payload carries a REQUIRED 65-byte EIP-712 `signature` alongside the EIP-3009
`authorization` object; x402 v2 marks both Required. This reference validates the required field
shapes and nothing more. It does NOT recover or cryptographically verify the authorization signer.
Signature validity, payer recovery, validity-window checks and matching against the payment
requirement remain native x402 and facilitator semantics. The observation layer records the
transaction sender as an observed fact from the RPC account; it never treats the broadcaster as
payment authority merely because it submitted the transaction.

### Type-states

Capture and acceptance are separate operations, and the boundary is visible to the compiler rather
than being a flag a caller might forget to inspect:

```text
CapturedX402Artifact                       capture only; authorizes nothing
                                           decoded?: JsonValue   (absent below the json stage)
SchemaValidatedPaymentRequiredArtifact     requires upstream-schema accepted
                                           decoded: PaymentRequired
SchemaValidatedPaymentPayloadArtifact      requires upstream-schema AND scheme-payload accepted
                                           decoded: PaymentPayload
StructurallyCheckedSettleResponseArtifact  requires the local structural check accepted;
                                           upstream-schema stays not_evaluated
                                           decoded: SettleResponse
```

A promoted type REFINES the properties a capture already carries; it introduces no second copy of
the decoded object. `decoded` is optional on a capture, because a value that never reached the json
stage has none, and required on a promoted artifact, because promotion refuses to refine an artifact
that has none. Every field a promoted type declares is therefore present at runtime.

Promotion functions fail closed, and a captured artifact is not assignable where a validated one is
required — enforced by `@ts-expect-error` vectors in the rejection corpus, so the typecheck fails if
the type-states ever stop discriminating. Preserving a malformed artifact is evidence; it is never
authorization.

### Diagnostics

Failures are reported as at most eight `{stage, code, path}` entries, with path depth at most eight
and a total serialized size of at most one kibibyte. `code` comes from a fixed, closed
`X402DiagnosticCode` vocabulary (`src/x402-header.ts`); anything outside it, including an unrecognized
upstream validator issue code, is reported as `unspecified` rather than passed through. No message
text produced by a validator over attacker-controlled input is retained, because that text can embed
the input itself. Diagnostic `path` segments are sanitised (non-identifier characters replaced) and
length-capped, because an object with attacker-chosen member names could otherwise put attacker
content into persisted evidence even through a "safe-looking" path.

### Acceptance matrix

Acceptance cases carry stable identifiers declared in `src/acceptance-ids.ts`. The suites record
each one as it executes and `pnpm test:acceptance` fails if a declared case did not run, so coverage
cannot regress while the counts keep looking healthy. Two cases are scoped to continuous
integration, because a single local process cannot reproduce them: the repeated-run byte comparison
and the run with networking disabled.

**Ledger freshness.** A stale ledger file left over from an earlier run must never be able to make a
later run look complete when a case did not actually execute this time. `pnpm test:reset` removes
the whole ledger directory before any suite begins — the FIRST step of `pnpm test`, not an assumption
that "CI starts from a clean checkout" would happen to provide. `pnpm test:ledger-integrity` is a
regression test that plants a stale, complete-looking ledger file, shows that a directory-wide reset
is what actually prevents it from masking an omitted case, and fails if that stops being true.

## 7. Standards and dependency snapshot

| Standard | Role here |
|---|---|
| RFC 9421 | Request-component derivation semantics for the request binding (`@method`, `@scheme`, `@authority`, `@path`, `@query`). This repository derives request component **values** using RFC 9421 semantics; it does not create or verify an RFC 9421 HTTP Message Signature. |
| RFC 8785 (JCS) | Canonicalization of binding documents before digesting. |
| RFC 7493 (I-JSON) | Duplicate-object-member rejection is a binding-safety requirement of this profile, not an x402 conformance rule; x402 itself does not forbid duplicate members. |
| RFC 8259 (JSON) | Base grammar; `JSON.parse` silently keeps the last duplicate member, which is exactly why the I-JSON discipline above exists. |
| CAIP-2 | Network identifier form (`eip155:84532` for Base Sepolia), declared as an explicit local constant; the pinned upstream default-asset registry is checked to key an entry under it. |
| EIP-3009 | `transferWithAuthorization`, the exact-scheme payload this profile validates for EVM. |
| JSON Schema 2020-12 | Both binding documents validate against closed schemas in `schemas/`. |

The `$id` values in `schemas/*.schema.json` are namespace identifiers; they are not guaranteed to
be dereferenceable (each schema file says so directly via `$comment`).

Digests use `sha256:<64 lowercase hex>` throughout. This is this reference profile's own
application-local digest identifier syntax, not the wire syntax of RFC 9530 `Content-Digest`; if a
real HTTP `Content-Digest` field is ever used, it will implement RFC 9530 semantics and syntax
separately.

| Dependency | Pin |
|---|---|
| `@x402/core` / `@x402/evm` / `@x402/express` / `@x402/extensions` | `2.23.0`, exact |
| `@peac/crypto` / `@peac/kernel` / `@peac/protocol` / `@peac/schema` | `0.16.4`, exact (current published PEAC release) |
| TypeScript | `7.0.2` primary; `6.0.2` (`@typescript/typescript6`) compatibility gate |
| Node.js | `^22.13.0 \|\| ^24.0.0` (CI matrix: 22, 24) |
| pnpm | `11.23.0`, pinned by `packageManager` including its integrity hash |
| ajv | `8.20.0` (JSON Schema 2020-12) |

### Independent canonicalizer

`src/jcs-independent.ts` is a second, separately written RFC 8785 implementation used ONLY to
cross-check the golden vectors in tests. It is not a second production canonicalization authority:
`@peac/protocol`'s `computeJsonDocumentDigestJcs` is the sole canonicalizer used on the actual
evidence path, and nothing signed or persisted is ever produced by the independent implementation.

## 8. Security

See [`SECURITY.md`](SECURITY.md) for the full policy. In summary: no private keys, seed phrases or
signed payment authorizations belong in this repository, its history, its fixtures, its logs, or a
recorded demonstration; every fixture value is a deterministic synthetic placeholder with no
corresponding private key held anywhere in this repository; continuous integration runs a
full-history secret scan with a self-proving canary; validator diagnostics are bounded and never
retain attacker-controlled message text (see [§6](#6-validation-and-acceptance-model)).

## 9. Relationship to PEAC, x402 and Base

PEAC is a protocol for portable, verifiable interaction records. This repository is a
NON-NORMATIVE reference example: it does not extend or modify the PEAC wire format, record registry,
extension registry or conformance requirements.

x402 v2 already provides signed offers, signed receipts, payment identifiers and builder codes, and
its offer-to-receipt matching compares resource URL, network, payer and recency — binding payment
artifacts to one another. It does not bind them to the operation the client asked for, or to the exact
bytes the service origin produced. This example adds two application-local documents that do exactly
that, and nothing else:

| Profile | Binds |
|---|---|
| `org.peacprotocol.examples.payment-evidence/request-binding/1` | RFC 9421 request components, content type and encoding, request-body digest, selected observed-value digests |
| `org.peacprotocol.examples.payment-evidence/origin-result-binding/1` | status, content type and encoding, and the digest of the bytes the origin application produced |

Native x402 artifacts remain authoritative for their own claims. This example preserves, digests and
references them; it does not reinterpret settlement semantics or replace native signature checks.

x402's signed offers and receipts travel inside the `PAYMENT-REQUIRED` and settlement response
surfaces. When a flow carries them, this example preserves them exactly as it preserves every other
captured field value: verbatim inside the captured artifact, covered by that artifact's digest. The
deterministic fixture does not enable the offer-receipt extension, because the upstream extension
stamps offer expiry and receipt issuance times from the process clock with no injection point, and
the committed fixture evidence is required to be byte-identical across runs. Offers and receipts
remain native x402 artifacts and remain authoritative for what they attest; nothing here replaces
them.
Base is referenced here only as the target network for the EVM `exact` scheme; this repository has no
relationship with Base, Coinbase, the x402 Foundation or Circle beyond using their public
specifications and packages.

## Byte semantics

- Bodies are `Uint8Array`. A string would carry an implied encoding into the digest.
- x402 payment field values must be visible ASCII, and are digested as UTF-8 bytes.
- Header decoding is delegated to the installed x402 codec, which uses standard base64 JSON for
  `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE`. This example does not define its
  own transport encoding.
- `payment-identifier` is an x402 **extension** carried inside `PaymentPayload.extensions`, not a
  fourth HTTP field. It is extracted and validated with the upstream extension APIs.
- Size bounds are application-local choices made by this example. They are not derived from, and
  imply nothing about, any HTTP parser limit.

## Request components

Components follow RFC 9421 derived-component semantics and are taken from the message as the origin
observed it:

```text
@method      preserved exactly; HTTP methods are case-sensitive
@scheme      lowercased
@authority   host lowercased, default port for the scheme omitted
@path        percent-encoded octets and dot segments preserved verbatim
@query       includes the leading "?"; a request with no query yields "?"
```

They are never rebuilt by re-parsing an absolute URL, for two reasons. URL parsers normalise:
collapsing dot segments, rewriting percent-encoding and reordering queries, any of which changes the
operation the evidence describes. And reconstructing scheme or authority from client-supplied headers
would let a caller influence what the record says. Adapters pass trusted components explicitly,
together with a `proxyTrustProfile`.

Only `direct-origin` is implemented as a `proxyTrustProfile` value. A trusted-proxy profile (an
explicit trusted-hop policy, `Forwarded`/`X-Forwarded-*` precedence, `Host`/`:authority` treatment,
malformed/duplicate-value and spoofing rejection, a real distinction between direct-origin and
proxied capture) is a genuine feature this repository does not implement, so no such value is
advertised in the type or the schema.

## Privacy

Payment signatures, payer identifiers, receipts and transaction references can be sensitive. Public
evidence is digest-only by default; raw artifacts stay private outside fixture mode. No private key
or payment authorization belongs in this repository, its logs, or a recorded demonstration.

## License

Apache-2.0
