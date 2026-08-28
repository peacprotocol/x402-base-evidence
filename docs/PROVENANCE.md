# Provenance

`x402-base-evidence` includes selected network-neutral modules derived from
[`x402-solana-evidence`](https://github.com/peacprotocol/x402-solana-evidence) so that each
reference remains standalone and reproducible.

**No runtime dependency exists between the two repositories.** Neither repository imports from, nor
is fetched by, the other's CI or build. Any parity below is source-level only, established at the
time this file was written and not automatically re-verified.

Source repository for everything ported: `peacprotocol/x402-solana-evidence`, tag `v0.1.0`, commit
`65bf684e882e1510d7a5b07a9b963fd9f7f0d662`.

| Module in this repository | Ported from (same path unless noted) | Status | Why it stays local |
|---|---|---|---|
| `src/digest.ts` | same | ported, semantically unchanged (chain-agnostic) | Single `sha256:` digest representation; no EVM- or SVM-specific content. |
| `src/strict-json.ts` | same | ported, semantically unchanged (chain-agnostic) | Bounded duplicate-object-member scanner; operates on JSON text, not chain artifacts. |
| `src/jcs-independent.ts` | same | ported, semantically unchanged (chain-agnostic) | Second, independently written RFC 8785 implementation used only as a test oracle for golden vectors. |
| `src/no-egress.ts` | same | ported, semantically unchanged (chain-agnostic) | Diagnostic-only network-egress trip wires for the offline fixture path. |
| `src/components.ts` | same | ported, semantically unchanged except the documented narrowing (chain-agnostic) | RFC 9421 request-component derivation; this repository additionally narrows `ProxyTrustProfile` to only the implemented `direct-origin` value (see [Request components](../README.md#request-components) in the README). |
| `src/binding.ts` | same | ported, semantically unchanged (chain-agnostic) | The two application-local binding documents (request binding, origin-result binding); binds to HTTP operation and origin bytes, not to any chain artifact. |
| `schemas/request-binding.v1.schema.json` | same | ported, semantically unchanged except the documented narrowing (chain-agnostic) | Same `proxyTrustProfile` narrowing as `components.ts`. |
| `schemas/origin-result-binding.v1.schema.json` | same | ported, semantically unchanged (chain-agnostic) | No chain-specific content. |
| `src/acceptance-ids.ts` | same | pattern reused, contents reauthored | Named acceptance registry and non-skippable completeness gate is the same pattern; the declared case IDs are this repository's own (`X402-*`, `REF-*`), and this repository adds a directory-wide ledger reset (`resetAcceptanceLedgers`) plus its regression test not present in the source at the pinned tag. |
| `src/no-egress.ts`, `src/fixture-demo-offline.ts` | same | ported, semantically unchanged / pattern reused | Egress-diagnostics wiring for the offline demo entry point. |
| `.github/workflows/ci.yml` | same | pattern reused, contents reauthored | Same job shape (matrix test, offline no-network job, secret scan with a self-proving gitleaks canary); action pins, image digest and package versions are this repository's own. |
| `src/x402-header.ts` | analogous file exists at the same path | reimplemented | Staged validation of x402 payment fields; the STAGE MODEL and reporting shape are the same pattern, but the scheme-payload check targets EIP-3009 (EVM) instead of an SVM wire transaction, and the settle-response local authority string is this repository's own. |
| `fixtures/deterministic.ts` | analogous file exists at the same path | reimplemented | Same "deterministic, SHA-256-derived synthetic placeholder" discipline; concrete values are Base Sepolia / EVM, not SVM. |
| `src/gen-golden.ts`, `src/test-golden.ts`, `src/test-negative.ts`, `src/test-acceptance.ts`, `src/imports-smoke.ts`, `src/fixture-demo.ts` | analogous files exist at the same paths | pattern reused, contents reauthored | Same test-file shape and philosophy; assertions and fixture data are specific to this repository's EVM artifacts. |

### Flow layer (`src/flow/`)

The reference flow layer mirrors the source repository's `src/flow/` shape. Ported modules keep
their semantics; the Base/EVM-specific modules reuse the pattern with their contents reauthored or
reimplemented against EVM artifacts and Base observation semantics.

| Module in this repository | Status | Notes |
|---|---|---|
| `src/flow/lifecycle.ts`, `src/flow/presence.ts`, `src/flow/safe-read.ts`, `src/flow/key-file.ts`, `src/flow/public-key-file.ts`, `src/flow/profile-schema.ts`, `src/flow/server.ts`, `src/flow/client.ts` | ported, semantically unchanged (chain-agnostic) | The x402 lifecycle model, the artifact presence contract, bounded hostile-input reads, key-file discipline and the express/client wiring carry no chain-specific content; `server.ts` additionally passes scheme metadata through the route price. |
| `src/flow/issuer-key.ts`, `src/flow/issue-record.ts`, `src/flow/verify-evidence.ts`, `src/flow/tamper-demo.ts`, `src/flow/fixture-e2e.ts` | pattern reused, contents adapted | Same issuance/verification model; the chain-observation document shape, its cross-checks and the recomputed expectation comparison are this repository's own. |
| `src/flow/failure-vocabulary.ts`, `src/flow/fixture-facilitator.ts`, `src/flow/fixture-wallet.ts` | pattern reused, contents reauthored | The closed reason vocabulary and the injection-point stand-ins are the same pattern; the supported upstream reasons, the EIP-3009 payload shape and the authorization-nonce dedupe are EVM-specific. |
| `src/flow/observe-settlement.ts`, `src/flow/observe-transaction.ts`, `src/flow/payer-key.ts`, `src/flow/preflight.ts` | reimplemented | The Base-specific surface: the `payment_expectation` / `chain_observation` split with an explicit comparison, the sealed-L2 observation sequence, the secp256k1 payer key, and the Base Sepolia preflight have no source-repository parity. |
| `src/test-evm-matrix.ts` | pattern reused, contents reauthored | Same matrix discipline as the source repository's SVM matrix; the EVM security cases, the upstream-facilitator probe over synthetic chain reads, and the evidence/receipt cases are this repository's own. |

**Not ported / no analog in this repository:** the Solana-specific test files (`test-evidence.ts`,
`test-keys.ts`, `test-preflight.ts`, `test-verifier-inputs.ts`) and the Solana live-run entry
point (`devnet-demo.ts`). No successful live Base Sepolia acceptance artifact is published in
this revision.

## Checksum manifest

No byte-identical parity is claimed for any file (every "ported, semantically unchanged" row above
was ported by hand, not mechanically synced), so no checksum manifest is committed. A checksum
manifest and a local parity test belong here only when byte-identical parity is actually
established for a specific subset of files.
