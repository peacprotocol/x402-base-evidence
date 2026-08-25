# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via GitHub security advisories once this repository is
published. Do not open public issues for vulnerabilities.

## Key and payment material

This repository must never contain private keys, payment authorizations, or funded-wallet material.

- **No private keys, seed phrases or signed payment authorizations** in the repository, in its
  history, in test fixtures, in logs, or in a recorded demonstration. Every account and
  authorization value in the fixtures is a deterministic synthetic placeholder derived from a
  descriptive label. This repository generates and possesses no private key for any of them and does
  not use them for onchain execution; it makes no claim that no account with a matching address could
  ever exist on any network, which it has no way to verify.
- **Keys used by any live mode stay outside version control**, under an ignored local
  directory, with restrictive file permissions. They are never regenerated per run and never
  printed; only the corresponding public address is ever displayed.
- **Base Sepolia only.** Any live mode targets a development network with valueless test assets.
  Mainnet execution, mainnet funds and real credentials are outside the scope of this reference
  implementation.
- A secret scan runs over the full history in continuous integration.

## Handling observed payment artifacts

Payment signatures, payer identifiers, receipts and transaction references can identify people and
counterparties.

- Public evidence is digest-only by default; raw artifacts stay private outside fixture mode.
- Validator diagnostics never retain message text produced over attacker-controlled input, and are
  bounded in count, depth and total size, so an untrusted payload cannot inflate what is logged or
  persisted.
- Observed field values are size-bounded before anything is decoded or digested.

## Verification boundary

This repository captures native x402 artifacts and validates selected structure; computes
request/result binding documents and deterministic digests; issues a signed PEAC record covering
those digests; and verifies that record offline under a public key supplied to the verifier.

Verification establishes integrity and internal consistency under the supplied key — never external
truth. A supplied public key is not a trust anchor.

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

Base distinguishes Flashblock preconfirmation, sealed L2 block inclusion, L1 batch inclusion and L1
finality. The observation layer in this repository records sealed L2 block inclusion only, with the
named source and the observation level actually established: the canonical observation never uses
the `pending` block tag, sealed inclusion is recorded only after the reported block number and hash
agree with sealed block data queried by explicit block number, and it is never inferred from the
mere existence of a transaction receipt. An EVM receipt's execution status is not a finality claim,
and L1 batch inclusion and L1 finality are never claimed unless separately observed.
