/**
 * One PEAC record per run, and the evidence directory around it.
 *
 * ONE RECORD, NOT A BUNDLE. The record carries digests; the documents those digests cover sit
 * beside it as ordinary files. No archive format, manifest or container is invented here: a
 * directory of files and a signed record that names them by digest is enough, and anything more
 * would be a format this example is in no position to define.
 *
 * WHAT GOES WHERE. The registered commerce group carries the registered payment fields and nothing
 * else, because it validates strictly and rejects unknown keys, which is what makes it a shared
 * vocabulary rather than a bag. Everything observational lives in an example-local group whose key
 * is namespaced to this example, so it cannot be mistaken for a registered PEAC field.
 *
 * DETERMINISM. Issuance stamps an issued-at time from the process clock and there is no option to
 * supply one, so the offline path pins the clock for the duration of the call. That is the whole
 * of the determinism arrangement: the record identifier is supplied, every other input is fixed,
 * and no part of the issuance path is patched or reimplemented.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { issue } from '@peac/protocol';
import type { Sha256Digest } from '../digest.ts';
import type {
  PaymentEvidenceOriginResultBindingV1,
  PaymentEvidenceRequestBindingV1,
} from '../binding.ts';
import { bindingDigest } from '../binding.ts';
import type { IssuerKey } from './issuer-key.ts';
import type { LifecycleObservation } from './lifecycle.ts';
import {
  readIssuerPublicKeyFile,
  writeIssuerPublicKeyFile,
  type LoadedIssuerPublicKey,
} from './public-key-file.ts';
import { chainObservationDigest, type BaseChainObservationV1 } from './observe-settlement.ts';
import type { EvidenceArtifact } from './presence.ts';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

/** Where the deterministic offline evidence is committed, so it can be verified without a run. */
export const EXPECTED_EVIDENCE_DIR = join(APP_ROOT, 'fixtures', 'expected-evidence');
/** Repository-relative name, used in output so no machine-specific path is ever printed. */
export const EXPECTED_EVIDENCE_DISPLAY = 'fixtures/expected-evidence';
/** Where a live run writes its evidence. Gitignored: it describes one run, not a fixture. */
export const runEvidenceDir = (runId: string): string => join(APP_ROOT, 'out', runId);
/** Repository-relative name for a live run's directory, so no machine-specific path is printed. */
export const runEvidenceDisplay = (runId: string): string => `out/${runId}`;
/**
 * Where a live run writes the public half of the key its record was signed with.
 *
 * Beside the evidence rather than inside it: the directory is the thing being verified, and a key
 * that lives in the material it verifies invites reading the pair as self-authenticating. It is
 * neither, and the run says so when it prints the command.
 */
export const runPublicKeyPath = (runId: string): string =>
  join(APP_ROOT, 'out', `${runId}-issuer.pub.json`);
export const runPublicKeyDisplay = (runId: string): string => `out/${runId}-issuer.pub.json`;

/** Registered PEAC record type for commerce evidence. */
export const RECORD_TYPE = 'org.peacprotocol/payment';
/** Registered extension group this record type requires. */
export const COMMERCE_GROUP = 'org.peacprotocol/commerce';
/** Example-local group. Namespaced, unregistered, and never presented as a PEAC field set. */
export const PAYMENT_EVIDENCE_GROUP = 'com.example/payment_evidence';

/** Observed x402 field values, each already accepted at the capture boundary. */
export interface ObservedFieldDigests {
  readonly 'payment-required': { readonly value: string; readonly digest: Sha256Digest };
  readonly 'payment-signature'?: { readonly value: string; readonly digest: Sha256Digest };
  readonly 'payment-response'?: { readonly value: string; readonly digest: Sha256Digest };
}

export interface EvidenceInputs {
  readonly issuerKey: IssuerKey;
  /**
   * Record identifier. Supplied so an offline run reproduces byte for byte. A live run omits it
   * and issuance generates one, because a run that happened once has nothing to reproduce.
   */
  readonly jti?: string;
  /** When the interaction happened, as an RFC 3339 timestamp. */
  readonly occurredAt: string;
  /** Pinned issued-at time, in Unix seconds. Offline only; a live run uses the real clock. */
  readonly issuedAtUnixSeconds?: number;
  readonly requestBinding: PaymentEvidenceRequestBindingV1;
  readonly originResultBinding?: PaymentEvidenceOriginResultBindingV1;
  readonly originResultBody?: Uint8Array;
  readonly observedFields: ObservedFieldDigests;
  readonly chainObservation: BaseChainObservationV1;
  readonly lifecycle: LifecycleObservation;
  /** Payment reference the client used, when the payment-identifier extension was in play. */
  readonly paymentReference?: string;
  /** Currency or asset symbol for the registered commerce group. */
  readonly currency: string;
  readonly environment: 'live' | 'test';
}

export interface EvidenceLayout {
  readonly jws: string;
  /** Relative path to file bytes, exactly as written. */
  readonly files: ReadonlyMap<EvidenceArtifact, Uint8Array>;
}

const encoder = new TextEncoder();

/** Canonical JSON serialization for the sidecar documents, so a reader can recompute digests. */
function documentBytes(value: unknown): Uint8Array {
  return encoder.encode(`${JSON.stringify(value, null, 2)}\n`);
}

/**
 * Run a function with the process clock pinned.
 *
 * Issuance derives the issued-at claim from `Date.now`. Rather than patch or fork that path, the
 * offline run fixes the clock around the call and restores it immediately, which is the same thing
 * a fixed clock means anywhere else. A live run never uses this.
 */
async function withPinnedClock<T>(unixSeconds: number | undefined, fn: () => Promise<T>): Promise<T> {
  if (unixSeconds === undefined) return fn();
  const realNow = Date.now;
  Date.now = () => unixSeconds * 1000;
  try {
    return await fn();
  } finally {
    Date.now = realNow;
  }
}

/**
 * Issue the record and assemble the evidence layout.
 *
 * Digests are computed before issuance because they are what the record binds; the record cannot
 * be issued and then have the documents chosen to match it.
 */
export async function issueEvidence(inputs: EvidenceInputs): Promise<EvidenceLayout> {
  const requestBindingDigest = await bindingDigest(inputs.requestBinding);
  const originResultBindingDigest =
    inputs.originResultBinding !== undefined
      ? await bindingDigest(inputs.originResultBinding)
      : undefined;
  const observationDigest = await chainObservationDigest(inputs.chainObservation);

  // Only the registered fields, because the group validates strictly. The lifecycle phase is
  // recorded only when settlement actually succeeded: `settlement` on a refused payment would be
  // exactly the overstatement this example exists to avoid.
  const commerce: Record<string, unknown> = {
    payment_rail: 'x402',
    amount_minor: inputs.chainObservation.payment_expectation.amount_base_units,
    currency: inputs.currency,
    asset: inputs.chainObservation.payment_expectation.asset,
    env: inputs.environment,
    ...(inputs.paymentReference !== undefined ? { reference: inputs.paymentReference } : {}),
    ...(inputs.chainObservation.chain_observation.settlement_outcome === 'succeeded'
      ? { event: 'settlement' }
      : {}),
  };

  const paymentEvidence: Record<string, unknown> = {
    terminal_state: inputs.lifecycle.terminalState,
    lifecycle_states: [...inputs.lifecycle.states],
    network: inputs.chainObservation.payment_expectation.network,
    request_binding_digest: requestBindingDigest,
    ...(originResultBindingDigest !== undefined
      ? { origin_result_binding_digest: originResultBindingDigest }
      : {}),
    payment_required_digest: inputs.observedFields['payment-required'].digest,
    ...(inputs.observedFields['payment-signature'] !== undefined
      ? { payment_signature_digest: inputs.observedFields['payment-signature'].digest }
      : {}),
    ...(inputs.observedFields['payment-response'] !== undefined
      ? { payment_response_digest: inputs.observedFields['payment-response'].digest }
      : {}),
    chain_observation_digest: observationDigest,
  };

  const result = await withPinnedClock(inputs.issuedAtUnixSeconds, () =>
    issue({
      iss: inputs.issuerKey.iss,
      kind: 'evidence',
      type: RECORD_TYPE,
      privateKey: inputs.issuerKey.privateKey,
      kid: inputs.issuerKey.kid,
      jti: inputs.jti,
      pillars: ['commerce'],
      occurred_at: inputs.occurredAt,
      extensions: {
        [COMMERCE_GROUP]: commerce,
        [PAYMENT_EVIDENCE_GROUP]: paymentEvidence,
      },
    }),
  );

  const files = new Map<EvidenceArtifact, Uint8Array>();
  files.set('record.jws', encoder.encode(`${result.jws}\n`));
  files.set('request-binding.json', documentBytes(inputs.requestBinding));
  files.set('chain-observation.json', documentBytes(inputs.chainObservation));
  files.set(
    'artifacts/payment-required.txt',
    encoder.encode(inputs.observedFields['payment-required'].value),
  );
  if (inputs.observedFields['payment-signature'] !== undefined) {
    files.set(
      'artifacts/payment-signature.txt',
      encoder.encode(inputs.observedFields['payment-signature'].value),
    );
  }
  if (inputs.observedFields['payment-response'] !== undefined) {
    files.set(
      'artifacts/payment-response.txt',
      encoder.encode(inputs.observedFields['payment-response'].value),
    );
  }
  if (inputs.originResultBinding !== undefined) {
    files.set('origin-result-binding.json', documentBytes(inputs.originResultBinding));
  }
  if (inputs.originResultBody !== undefined) {
    files.set('origin-result-body.bin', inputs.originResultBody);
  }

  return { jws: result.jws, files };
}

/**
 * Write an evidence layout to a directory, creating it if needed.
 *
 * Writes in place, which is what the deterministic fixture needs: it rewrites one committed
 * directory with identical bytes every run, and `git diff` after a run is the determinism check.
 * Staging and renaming that directory would mean deleting and recreating tracked files to produce
 * the same content, which is worse than the failure it would guard against, and an interrupted
 * fixture run is recoverable from the repository. A live run writes into a directory nothing else
 * can restore, so it uses `writeEvidenceTransactionally` below instead.
 */
export function writeEvidence(directory: string, layout: EvidenceLayout): void {
  for (const [relativePath, bytes] of layout.files) {
    const target = join(directory, relativePath);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes);
  }
}

/** A run whose output path is already taken. What is already there is never touched. */
export class EvidenceCollisionError extends Error {
  /**
   * @param path - The path that is already occupied.
   * @param what - What that path was going to hold, so the message names the actual conflict.
   */
  readonly path: string;
  constructor(path: string, what = 'Evidence') {
    super(
      `${what} already exists at ${path}\n` +
        "  It was not modified, and nothing was written. A run's outputs belong to that run.",
    );
    this.name = 'EvidenceCollisionError';
    this.path = path;
  }
}

/**
 * Reserve a run's output paths and write the material a reviewer needs, before anything is spent.
 *
 * WHY THIS RUNS FIRST. The evidence a live run produces is verifiable only alongside the public
 * half of the key it was signed with. Writing that key after the evidence leaves a window in which
 * devnet funds have already moved and the material a reviewer needs cannot be produced: a full
 * transcript of a real payment, unusable by anyone else. So both output paths are claimed and the
 * key file is written and read back before the run is allowed to reach a payment at all.
 *
 * The ordering gives the property worth stating: a finalized evidence directory implies the key
 * file beside it already exists, because the directory cannot be moved into place until long after
 * the key was written. The reverse does not hold, and does not need to: a key file left without a
 * directory is public material describing a run that did not complete.
 *
 * @param input.evidenceDirectory - Where complete evidence will belong. Must not exist.
 * @param input.publicKeyFile - Where the public half of the signing key goes. Must not exist.
 * @param input.issuerKey - The key this run will sign with. Only its public half is written.
 * @returns The key file as read back from disk, so what a reviewer will load is what was checked.
 * @throws EvidenceCollisionError when either path is taken, before anything is written.
 * @throws InvalidPublicKeyFileError when the file just written does not read back as a key.
 */
export function prepareRunOutputs(input: {
  readonly evidenceDirectory: string;
  readonly publicKeyFile: string;
  readonly issuerKey: { readonly publicKey: Uint8Array; readonly kid: string; readonly iss: string };
}): LoadedIssuerPublicKey {
  const { evidenceDirectory, publicKeyFile, issuerKey } = input;
  if (existsSync(evidenceDirectory)) throw new EvidenceCollisionError(evidenceDirectory);
  if (existsSync(publicKeyFile)) {
    throw new EvidenceCollisionError(publicKeyFile, 'A verification key file');
  }

  mkdirSync(dirname(publicKeyFile), { recursive: true });
  // Written exclusively, so a file that appeared between the check above and this line is a
  // collision rather than something to overwrite.
  writeIssuerPublicKeyFile(publicKeyFile, issuerKey);
  // Read back through the same reader a reviewer uses: a file that cannot be loaded is discovered
  // here, where nothing has been spent, rather than by the person the evidence was handed to.
  return readIssuerPublicKeyFile(publicKeyFile);
}

/** Distinguishes concurrent runs that share a starting instant. */
function stagingToken(): string {
  return `${Date.now().toString(36)}-${randomBytes(6).toString('hex')}`;
}

/**
 * Write a live run's evidence so that the destination is either complete or absent.
 *
 * A directory that appears one file at a time is readable halfway through, and a reader has no way
 * to tell an emission that is still running, or one that died, from a complete set someone has
 * since edited. So everything is written to a uniquely named staging directory beside the
 * destination, verified there, and only then moved into place with a single rename.
 *
 * The consequence is the property worth having: a final directory existing means a complete,
 * verified artifact set. It is never overwritten and never merged into, because a previous run's
 * evidence is that run's, and reusing its name would silently restate what it recorded.
 *
 * A failure leaves the staging directory where it is rather than deleting it. Its name says it is
 * incomplete, the destination still does not exist, and a run that has already spent real funds
 * should not have its artifacts discarded to keep the output tidy.
 *
 * @param input.finalDirectory - Where complete evidence belongs. Must not already exist.
 * @param input.layout - The artifacts to write.
 * @param input.finalize - Verification and anything else that belongs in the directory, run against
 *   the staged path so its output arrives with the rest or not at all. Throwing aborts the move.
 * @throws EvidenceCollisionError when the destination exists, before anything is written.
 */
export async function writeEvidenceTransactionally(input: {
  readonly finalDirectory: string;
  readonly layout: EvidenceLayout;
  readonly finalize: (stagedDirectory: string) => Promise<void>;
}): Promise<void> {
  const { finalDirectory, layout, finalize } = input;
  if (existsSync(finalDirectory)) throw new EvidenceCollisionError(finalDirectory);

  const parent = dirname(finalDirectory);
  mkdirSync(parent, { recursive: true });
  const staged = join(parent, `.tmp-${stagingToken()}`);
  // Created exclusively: a name that somehow already exists is a collision, not a directory to
  // write into, and the run stops rather than mixing two emissions together.
  mkdirSync(staged);

  writeEvidence(staged, layout);
  await finalize(staged);

  // Re-checked immediately before the move, because the destination is decided by a clock and two
  // runs could reach this point in the same second.
  if (existsSync(finalDirectory)) throw new EvidenceCollisionError(finalDirectory);
  renameSync(staged, finalDirectory);
}
