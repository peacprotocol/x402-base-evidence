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

Two different things are described below. They are separated deliberately, because a generic
statement about "successful verification" would otherwise read as though this repository performed
signature verification, which it does not.

**This repository** captures and validates selected x402 artifact structure, computes request and
origin-result binding documents with deterministic digests, and can compare a supplied document
against a referenced digest. It issues no signed record and verifies no signature.

**Separate PEAC signing and verification tooling** may issue a signed PEAC record covering those
digests, and may verify such a signature under a public key supplied to the verifier.

Neither establishes:

- external truth, or that any event described actually occurred;
- that a counterparty received a response;
- blockchain finality or inclusion;
- that a key, or its holder, is authoritative or trustworthy;
- that the captured artifacts are a complete account of an interaction;
- that the issuer's statements are truthful;
- that a matching payment succeeded. A reported receipt status (a `receipt_status`-style field, which
  this repository does not itself emit) records what a source said under its own application policy;
  it is not evidence of a settled, matching payment.

Base distinguishes Flashblock preconfirmation, sealed L2 block inclusion, L1 batch inclusion and L1
finality. This repository implements no chain-observation layer. Any observation implementation must
record the named source and the observation level actually established; an EVM receipt's execution
status is not a finality claim.
