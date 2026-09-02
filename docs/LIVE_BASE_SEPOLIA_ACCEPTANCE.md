# Live Base Sepolia acceptance

One live acceptance run of the paid-resource flow described in the README was executed on Base
Sepolia and PASSED. This document records exactly what was executed, what the resulting evidence
contains, how anyone holding the evidence can verify it, and — just as deliberately — what this
run does not establish.

The strongest claim this run supports is exactly this, and nothing stronger:

> The named Base RPC source reported the transaction in a sealed L2 block, and the admitted
> receipt contained the expected token transfer.

## 1. What was executed

`pnpm demo:live` (`src/flow/live-e2e.ts`) performed ONE paid request against the local example
origin: a real EIP-3009 `transferWithAuthorization` authorization signed by the local payer key,
presented through the x402 v2 `exact` scheme to the configured facilitator, which submitted the
settlement transaction; the origin result was produced and bound; and the settlement transaction
was observed through a separately attributed Base Sepolia RPC source under the sealed-L2
observation contract. A signed PEAC record was issued over the resulting digests, the evidence
directory was verified offline before being finalized, and a tamper demonstration confirmed that
an altered copy fails verification.

## 2. Run facts

| Fact | Value |
| --- | --- |
| Run identifier | `live-20260828T214534z` |
| Execution source commit | `154ea6c53a526f9ff21435d0c2c6097495c3f9cd` |
| Network | `eip155:84532` (Base Sepolia, a test network) |
| Token contract (test USDC) | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| Amount | `250000` base units (6 decimals) |
| Payer (authorization signer) | `0x3806B86702CAD11A877065d66d9d2d31c0c22e71` |
| Recipient (`payTo`) | `0xb0751238952665665ED5106C52FC49f6537C4879` |
| Settlement transaction | `0x4297fed04acc90240bb77893f027d8c20050108e5274c2213ea46f637badb873` |
| Block number | `46092625` |
| Block hash | `0xf7cc1e86a198beb48cd89c1a0f5ea2f2559b077f86c176f5f156d1c18e262ec6` |
| RPC observation source | `https://sepolia.base.org` |
| Observation level | `l2_block_inclusion` (sealed L2 block; no L1 claim, no confirmation counts) |
| Token transfer | one `Transfer` event on the expected token contract matching payer, recipient and amount |
| Record issuer | `https://www.originary.xyz` |
| Record signing key id (`kid`) | `payment-evidence-live-mtdhdcjk` (Ed25519) |
| `record.jws` SHA-256 | `32236db991089ea87067bf27b3618260cf57ebfccf1b07499c6fc0ee5fd9028b` |

The transaction on chain was submitted by the facilitator (transaction sender
`0xd407e409e34e0b9afb99ecceb609bdbcd5e7f1bf`), which pays gas in this flow. The broadcaster is
observed separately and is never treated as the payment authority; payment authority is the
EIP-3009 authorization signed by the payer above.

Native x402 artifacts were captured beside the record and are digest-bound by it: the 402
`PAYMENT-REQUIRED` challenge (`artifacts/payment-required.txt`), the payment signature material
(`artifacts/payment-signature.txt`), and the facilitator settlement response
(`artifacts/payment-response.txt`). The native x402 artifacts remain authoritative for native
payment semantics; the PEAC record composes with them and does not replace them.

## 3. Where the evidence lives, and the immutable checksums

The evidence directory is a run artifact, not repository source, so it is not committed to this
repository's history. Its complete SHA-256 checksum list, produced from the frozen post-run bytes,
IS committed:

- [`evidence/base-sepolia/live-20260828T214534z/SHA256SUMS`](../evidence/base-sepolia/live-20260828T214534z/SHA256SUMS)

That file lists every evidence file by repository-relative path with its SHA-256 digest. The
SHA-256 of the `SHA256SUMS` file itself is:

```text
56b069f3b891654adc260da50484b6743aed51e20ef659eca21c2dde204bf1e7
```

Anyone holding a copy of the evidence directory can check it byte-for-byte:

```sh
shasum -a 256 -c evidence/base-sepolia/live-20260828T214534z/SHA256SUMS
```

## 4. Provenance: what is signed and what is metadata

The distinction matters and is easy to blur, so it is stated exactly:

- **Inside the signature.** `record.jws` signs the record payload: the payment expectation and
  observation digests, the request and origin-result binding digests, the artifact digests, the
  terminal state, and the record metadata. Verifying the signature establishes that THOSE bytes
  are intact under the supplied key.
- **Outside the signature.** The signed evidence does NOT contain the Git source commit. The
  binding "execution source commit `154ea6c5…` → run `live-20260828T214534z` → the evidence file
  hashes above → the transaction facts above" is publication metadata: this document and the
  committed `SHA256SUMS` file assert it as provenance. It is checkable (the hashes recompute; the
  transaction is public on Base Sepolia), but it is not cryptographically signed inside
  `record.jws`, and nothing here should be read as claiming that it is.

## 5. Verifying the evidence

Verification is offline: files and a public key, nothing else — no network, no access to the
origin, no state shared with the run.

```sh
pnpm verify --evidence out/live-20260828T214534z --public-key out/live-20260828T214534z-issuer.pub.json
```

Result for this run: **Verified.** The record signature checked under the published public key,
every bound digest recomputed from the document beside it, both application-local binding
documents matched their committed schemas, the artifact set satisfied the presence contract for
the recorded terminal state (`response_write_attempted`), and the cross-document fields
(network, asset, amount, terminal state, settlement-response digest, origin-result digest) were
internally consistent.

Tamper demonstration: a COPY of the evidence directory with a single field changed
(`payment_expectation.amount_base_units`) was run through the same verifier and **failed**,
with the failure naming the edited document (the chain-observation digest no longer recomputed)
rather than vaguely rejecting the directory. The canonical evidence was not modified.

## 6. What is reproducible

**Verification is reproducible.** Anyone with the evidence directory and the public key file can
re-run the command above and get the same verdict, and can check the bytes against `SHA256SUMS`.

**The run itself is deliberately not byte-reproducible.** The evidence describes one live
interaction: a fresh authorization nonce, real timestamps, the request components the origin
actually observed, and a real transaction. Re-running `pnpm demo:live` produces a NEW run with new
evidence, never these bytes. Byte-reproducibility belongs to the offline fixture path, which is
covered by the deterministic acceptance matrix (`src/acceptance-ids.ts`), not to live runs.

## 7. What this run does NOT establish

- **Not L1 finality.** The observation level is `l2_block_inclusion`: a named RPC source reported
  the transaction in a sealed L2 block. No claim is made about L1 batch inclusion, L1 finality,
  preconfirmation state, or confirmation counts.
- **Not a consensus oracle.** One RPC source was consulted. Its report is recorded as that
  source's statement, not as what "the chain" says.
- **Not proof that every external claim is true.** Offline verification establishes integrity and
  internal consistency under the supplied key. Two documents agreeing is a property of the
  documents, not of the world.
- **Not proof of who holds the private key.** The published public key file makes the record
  cryptographically verifiable; it does not establish who controls the signing key, and a key
  obtained alongside the evidence establishes internal consistency only.
- **Not proof of address ownership** beyond what the run itself established: the payer key signed
  the authorization, and the recipient address was the configured `payTo`.
- **Not a reputation score, not a policy decision, and not a payment rail.** This repository
  observes and records; it does not settle payments, rank parties, or decide anything.
- **Not a production or mainnet result.** Base Sepolia is a test network; the amount is test USDC.
- **Not external adoption or endorsement** by Base, Coinbase, the x402 Foundation, Circle, or any
  facilitator.
