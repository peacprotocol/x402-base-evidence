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

A clean clone contains this checksum list but not the evidence bytes; section 7 explains how to
obtain them from the `v0.1.0` release asset. Anyone holding the evidence directory at the listed
paths can then check it byte-for-byte from the repository root:

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
  `record.jws`, and nothing here should be read as claiming that it is. The same holds for the
  commit tagged `v0.1.0`, which publishes this bundle and this document: it is a second,
  different provenance fact, and it is equally outside the signature.

## 5. Verifying the evidence

Verification is offline: files and a public key, nothing else — no network, no access to the
origin, no state shared with the run.

```sh
pnpm verify -- --evidence out/live-20260828T214534z --public-key out/live-20260828T214534z-issuer.pub.json
```

The command reads the evidence directory and the public key file under `out/`, which a clean clone
does not provide; section 7 covers obtaining them.

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
Section 7 walks through doing exactly that from a clean clone.

**The run itself is deliberately not byte-reproducible.** The evidence describes one live
interaction: a fresh authorization nonce, real timestamps, the request components the origin
actually observed, and a real transaction. Re-running `pnpm demo:live` produces a NEW run with new
evidence, never these bytes. Byte-reproducibility belongs to the offline fixture path, which is
covered by the deterministic acceptance matrix (`src/acceptance-ids.ts`), not to live runs.

## 7. Reproducing the verification from a clean clone

A clean clone of this repository does not contain the evidence bytes: `out/` is a run artifact and
is never committed. The frozen post-run bytes are published as an asset of the GitHub release
`v0.1.0`, so the verification can be reproduced from a clean clone in five steps.

1. Clone and install from the committed lockfile:

   ```sh
   git clone https://github.com/peacprotocol/x402-base-evidence.git
   cd x402-base-evidence
   corepack enable
   pnpm install --frozen-lockfile
   ```

2. Download `x402-base-evidence-live-20260828T214534z.tar.gz` from the `v0.1.0` release and check
   its SHA-256 before extracting anything:

   ```sh
   echo "240dad2f7adcc5777aa63f5ecaffe02fc1b8b6a401a444d6771c730f6318381e  x402-base-evidence-live-20260828T214534z.tar.gz" | shasum -a 256 -c
   ```

3. Extract at the repository root. The archive recreates exactly the `out/...` paths that the
   committed `SHA256SUMS` names, and places two untracked files beside them at the root:
   `PROVENANCE.txt` (the run facts and the signed/unsigned boundary from section 4) and a copy of
   `SHA256SUMS` that is byte-identical to the committed one.

   ```sh
   tar -xzf x402-base-evidence-live-20260828T214534z.tar.gz
   ```

4. Check every extracted file against the committed checksum list; all twelve lines must read
   `OK`:

   ```sh
   shasum -a 256 -c evidence/base-sepolia/live-20260828T214534z/SHA256SUMS
   ```

5. Verify the record offline under the published public key; the expected verdict is
   `Verified.`:

   ```sh
   pnpm verify -- --evidence out/live-20260828T214534z --public-key out/live-20260828T214534z-issuer.pub.json
   ```

To see a failure, change one field in a COPY of the evidence directory and verify the copy: the
verdict becomes `Not verified.` and the `FAIL` lines name the document whose digest no longer
recomputes. The extracted bundle is unchanged by any of this, and step 4 can be repeated afterwards.

The verification needs no network access. The verifier reads the evidence directory and the key
file and nothing else; running it with the repository's egress diagnostics installed
(`node --import ./src/no-egress.ts src/flow/verify-evidence.ts --evidence ... --public-key ...`)
reports the same verdict with no refused call.

Reading the result correctly:

- **Two commits, two facts.** The execution source commit `154ea6c5…` is the tree that produced
  the run. The commit tagged `v0.1.0` is the repository state that publishes this bundle and this
  document; the release notes name it. Neither commit is signed inside `record.jws` (section 4).
  The verifier at the tagged commit reports three supplied-key consistency checks in addition to
  those recorded in the frozen `verification-report.txt`, which was written by the verifier at the
  execution source commit; the verdict is the same.
- **The loopback origin is a run fact.** `payment-required.txt`, `payment-signature.txt` and
  `request-binding.json` name `http://127.0.0.1:4021/v1/forecast?region=alpha&units=metric` as the
  resource URL and request authority. That is the local example origin the run actually observed,
  recorded as the observed origin authority; it is not a filesystem path, and nothing in the bundle
  points at any machine.
- **The published authorization cannot be presented again.** `payment-signature.txt` carries the
  EIP-3009 authorization the payer signed for this one run. It was consumed by the settlement
  transaction, the token contract's `authorizationState` reports its nonce as used, and its
  validity window (`validBefore`) has passed.
- **Same boundary as the run itself.** Base Sepolia only; sealed L2 inclusion, not L1 finality; one
  RPC source; no claim about who holds the signing key; no adoption or endorsement by any party.
  Section 8 states the full list.

The asset is built deterministically from copies of the frozen bytes (members in sorted order,
member timestamp fixed at `2026-08-28T21:45:40Z`, numeric owner `0:0`, modes `0644` and `0755`,
gzip without a name or timestamp), so rebuilding it from the same bytes yields the same SHA-256.

## 8. What this run does NOT establish

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
