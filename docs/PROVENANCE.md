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

**Not ported / no analog in this repository:** `src/flow/` (the Solana observation layer) and the
Solana-specific test files (`test-evidence.ts`, `test-keys.ts`, `test-preflight.ts`,
`test-svm-matrix.ts`, `test-verifier-inputs.ts`). Base chain observation, live payment execution,
and PEAC evidence issuance are not implemented in this repository.

## Checksum manifest

No byte-identical parity is claimed for any file (every "ported, semantically unchanged" row above
was ported by hand, not mechanically synced), so no checksum manifest is committed. A checksum
manifest and a local parity test belong here only when byte-identical parity is actually
established for a specific subset of files.
