# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub security advisories once this repository is
published. Do not open public issues for vulnerabilities.

## Key and payment material

Two classes of key material exist here, and this policy distinguishes them rather than claiming
the repository holds none.

**Prohibited — never in this repository, its history, its logs, or a recorded demonstration:**

- live, funded, production or reusable secret private keys;
- wallet credentials and seed phrases;
- unconsumed or reusable payment authorizations;
- private key material copied into evidence artifacts;
- private key material printed, logged or recorded, in any mode.

**Permitted — deliberately present, as public test vectors:**

- deterministic, explicitly labelled TEST-ONLY fixture keys in fixture and test code, where
  cryptographic behavior genuinely needs a real signature: the fixture issuer signing key in
  `src/flow/issuer-key.ts` (`FIXTURE_ISSUER_PRIVATE_KEY`), which signs the committed fixture
  record, and the deterministic EVM test keys in `src/test-evm-matrix.ts`, used in-process so the
  installed upstream EIP-712/EIP-3009 validation logic runs over real signatures;
- the synthetic signed fixture artifacts those keys and the labelled placeholder values produce,
  including the committed `fixtures/expected-evidence/record.jws` and the captured payment field
  values. They are public verification material, and verifying them is the point of committing
  them.

Test-only fixture keys are permanently public and permanently compromised. They MUST NEVER be
funded; MUST NEVER be reused outside these fixtures; MUST NEVER be treated as credentials or trust
anchors; and their addresses MUST NOT be treated as controlled production identities.

- **Fixture account values are placeholders.** Every payer, recipient and authorization value in
  the deterministic fixtures is a synthetic placeholder derived from a descriptive label; no
  private key for those account addresses is derived or held here, they are not used for onchain
  execution, and no claim is made that no account with a matching address could ever exist on any
  network, which this repository has no way to verify.
- **Keys used by any live mode stay outside version control**, gitignored under `.local/`, with
  restrictive file permissions, created only when no key file exists (an existing file is refused,
  never replaced), and never printed; only the corresponding public address is ever displayed.
- **Base Sepolia only.** Any live mode targets a development network with Base Sepolia test
  assets. Mainnet execution, mainnet funds and real credentials are outside the scope of this
  reference implementation.
- A secret scan runs over the full history in continuous integration, with a self-proving canary.
  Its one allowlist entry is scoped to the committed fixture record and the jwt rule only, so a
  real token anywhere else in the repository is still a finding.

## Handling observed payment artifacts

Payment signatures, payer identifiers, receipts and transaction references can identify people and
counterparties.

- Public evidence is digest-only by default, and raw live artifacts remain private by default. An
  explicitly reviewed Base Sepolia testnet acceptance bundle MAY be published when it contains no
  reusable secret and no private third-party data, its payment authorization has been consumed on
  chain and cannot be presented again, and the publication is documented in the acceptance
  document (`docs/LIVE_BASE_SEPOLIA_ACCEPTANCE.md`).
- Validator diagnostics never retain message text produced over attacker-controlled input, and are
  bounded in count, depth and total size, so an untrusted payload cannot inflate what is logged or
  persisted.
- Observed field values are size-bounded before anything is decoded or digested.

## Cached results and retries

The reference origin implements the x402 payment-identifier extension's deduplication. The extension
leaves the retrieval rule to the application, so it is stated here.

- A cached settled result is released only to a request presenting the same payment identifier, the
  same request fingerprint and the same signed EIP-3009 authorization the facilitator verified and
  settled. An identifier alone, or an identifier with a different authorization, is refused with
  409 and reaches neither verification nor settlement.
- Requests under one identifier are serialized through an explicit operation state (`pending`,
  `completed`, `rejected`, `uncertain`). Overlapping matching retries share one operation. An
  unknown settlement outcome leaves the identifier `uncertain`; it is neither retried nor released.
- The captured authorization is bearer-equivalent within the run: whoever holds the exact
  `PAYMENT-SIGNATURE` value can retrieve that result until the process ends. Evidence bundles are
  published only after the authorization has been consumed on chain, its window has passed and the
  origin that served it has stopped. A deployment serving private results needs a stronger retrieval
  credential than possession of the captured artifact.
- The store is in-memory, bounded and lost on restart. Durable state, restart recovery,
  multi-instance coordination and tenant scoping are outside this reference.

## Verification boundary

This repository captures native x402 artifacts and validates selected structure; computes
request/result binding documents and deterministic digests; issues a signed PEAC record covering
those digests; and verifies that record offline under a public key supplied to the verifier.

Verification establishes integrity and internal consistency under the supplied key — never external
truth. A supplied public key is not a trust anchor. When the record claims a settled payment, the
verifier also decodes the captured native x402 artifacts with a bounded parser and holds their
terms, authorization, identifier, resource and settlement fields to the record and the observation;
for any other terminal state they are preserved as presented. The full check inventory, by category,
is in the README under "Verifier check inventory".

It still does not establish:

- external truth, or that any event described actually occurred;
- that a counterparty received a response;
- blockchain finality or inclusion;
- that a key, or its holder, is authoritative or trustworthy;
- that the captured artifacts are a complete account of an interaction;
- that the issuer's statements are truthful;
- that a matching payment succeeded. A reported `receipt_status` records the EVM execution result a
  source reported; it is not evidence of a settled, matching payment. Matching-payment evidence
  additionally requires the expected token, from, to and value transfer event plus native x402
  validation.

PEAC signature and integrity verification by itself does not establish onchain inclusion or
finality. This example may retain a separately attributed RPC source's L2-inclusion observation
after bounded consistency checks. The verifier establishes the integrity and internal consistency
of that recorded observation; it does not independently establish blockchain consensus, external
truth, issuer authority, client receipt or finality.

Base distinguishes Flashblock preconfirmation, sealed L2 block inclusion, L1 batch inclusion and L1
finality. The observation layer in this repository records sealed L2 block inclusion only, with the
named source and the observation level actually established: the recorded observation never uses
the `pending` block tag, sealed inclusion is recorded only after the receipt's reported placement,
the transaction object's reported placement and sealed block data queried by explicit block number
all agree — including that the sealed block's own transaction list contains the transaction — and
it is never inferred from the mere existence of a transaction receipt. An EVM receipt's execution
status is not a finality claim, and L1 batch inclusion and L1 finality are never claimed unless
separately observed.
