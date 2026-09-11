/**
 * Independent verification of an evidence directory.
 *
 * Given the directory and a public key, and nothing else: no access to the origin, no network, no
 * shared state with whatever produced it. That is the property the whole example exists to
 * demonstrate, so this file deliberately reads only files and the supplied key.
 *
 * Six things are checked, and the order is the point:
 *   1. the record's signature, so nothing downstream is trusted before it is intact
 *   2. every digest recomputed from the document beside it, so the record's claims about those
 *      documents are checked rather than believed
 *   3. each application-local binding document against its committed schema, because a digest
 *      proves which document was bound and says nothing about whether it is well formed
 *   4. the origin result body against the digest inside the result binding, because a binding that
 *      names a body nobody can check is decoration
 *   5. the artifact set against the presence contract for the terminal state the record itself
 *      carries, so removing an inconvenient file is a failure and not a smaller directory
 *   6. the fields two documents deliberately repeat, against each other, because a directory whose
 *      signature and digests are all intact can still describe two different payments
 *
 * INTERNAL CONSISTENCY IS NOT TRUTH. The agreement checks compare what this evidence says in one
 * place against what it says in another. They establish that the record and the observation
 * describe the same interaction. They establish nothing about the network: not that a transaction
 * exists, not that it is final, not that any chain agrees, and not that the party named as the
 * issuer is who they say they are. Two documents agreeing is a property of the documents.
 *
 * WHAT SUCCESS MEANS. The contents are intact relative to the key material supplied to this
 * verifier, and the documents match what the record says about them. It does not establish that
 * the key belongs to any particular organization, that the payment settled, or that any statement
 * inside the documents is true. Those are separate questions, and this reports on none of them.
 *
 * WARNINGS, WHICH ARE NOT VERDICTS. Some things are worth telling a reader without being a finding
 * about the contents: two observers of the same transaction reporting different things is the case
 * that exists today. Those are collected separately from the checks and never affect the outcome,
 * because reconciling observers would mean choosing which one to believe, and nothing here is in a
 * position to do that.
 */
import { join } from 'node:path';
import { verifyLocal, computeJsonDocumentDigestJcs } from '@peac/protocol';
import type { JsonValue } from '@peac/kernel';
import type { PaymentPayload, PaymentRequired, SettleResponse } from '@x402/core/types';
import { extractPaymentIdentifier } from '@x402/extensions/payment-identifier';
import { coerceDigest, digestBytes, type Sha256Digest } from '../digest.ts';
import { decodeStrictUtf8, parseStrictJson, type StrictJsonRefusal } from '../strict-json.ts';
import {
  captureObservedX402Artifact,
  X402_STAGES,
  type CapturedX402Artifact,
  type X402HeaderName,
} from '../x402-header.ts';
import { ComponentError, componentsFromAbsoluteUri } from '../components.ts';
import { checkPresence, EVIDENCE_ARTIFACTS, type EvidenceArtifact } from './presence.ts';
import {
  ARTIFACT_CONTAINERS,
  ARTIFACT_MAX_BYTES,
  checkContainerDirectory,
  readBoundedFile,
} from './safe-read.ts';
import {
  COMMERCE_GROUP,
  EXPECTED_EVIDENCE_DIR,
  EXPECTED_EVIDENCE_DISPLAY,
  PAYMENT_EVIDENCE_GROUP,
  RECORD_TYPE,
} from './issue-record.ts';
import { resolveIssuerKey } from './issuer-key.ts';
import { TERMINAL_STATES, type TerminalState } from './lifecycle.ts';
import { validateLocalProfile, type LocalProfileDocument } from './profile-schema.ts';
import {
  compareExpectationToObservation,
  PROFILE_CHAIN_OBSERVATION,
  type BaseChainObservationV1,
  type ComparisonVerdict,
} from './observe-settlement.ts';
import { sameAddress } from './observe-transaction.ts';
import {
  InvalidPublicKeyFileError,
  PUBLIC_KEY_ALGORITHM,
  readIssuerPublicKeyFile,
  SUPPLIED_KEY_CAVEAT,
  type LoadedIssuerPublicKey,
} from './public-key-file.ts';

/**
 * The one x402 scheme this example observes.
 *
 * Stated here so an observation naming another scheme is refused rather than read as though the
 * fields below meant what they mean under `exact`. It is a bound on what this example claims to
 * have looked at, not a judgement about any other scheme.
 */
const OBSERVED_SCHEME = 'exact';

/**
 * The verifier profile this build of the verifier implements.
 *
 * A profile is a version of the check set, not a version of this file. Profile 1 was the v0.1.0
 * check set: no native-artifact agreement, no chain-observation schema. Profile 2 adds both. A
 * reader comparing two reports needs to know which check set produced each one before comparing
 * their outcomes at all.
 */
export const VERIFIER_PROFILE = 'x402-base-evidence/offline-verification/2';

/**
 * What a check is checking, so a reader can tell four different kinds of question apart at a
 * glance: whether the bytes are intact under the supplied key, whether a document has the shape
 * this example produces, whether documents that repeat a fact agree with each other, and whether
 * the native x402 artifacts this evidence captured agree with what the record and the observation
 * say about them.
 *
 *   integrity     record signature/schema; every bound digest recomputed; the origin result body
 *                 digest; what a supplied key file declares about itself.
 *   structure     record type; extension groups; local-profile schema checks; the artifact
 *                 presence contract; chain observation profile/scheme/attribution; settlement
 *                 facts against the outcome; rpc observation basis checks; terminal state.
 *   consistency   cross-document agreement (network/terminal state/asset/amount/digests); the
 *                 expectation comparison recomputed; the transfer verdict evaluated.
 *   native        agreement between the captured native x402 artifacts and the record.
 */
export type VerificationCategory = 'integrity' | 'structure' | 'consistency' | 'native';

export interface VerificationCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly category: VerificationCategory;
  /** Bounded explanation. Never quotes attacker-controlled document text. */
  readonly detail: string;
}

/**
 * Something a reader should be told that is not a verdict on the contents.
 *
 * Kept in its own collection rather than as a third value of `ok`, so that a warning structurally
 * cannot decide whether a directory verified. Integrity is a question about bytes and a key; two
 * observers saying different things is a question about the world, and answering the second one
 * here would mean this verifier deciding which observer to believe.
 */
export interface VerificationWarning {
  readonly name: string;
  /** Bounded explanation. Never quotes attacker-controlled document text. */
  readonly detail: string;
}

export interface EvidenceVerificationReport {
  readonly ok: boolean;
  /** Which check set produced this report. See `VERIFIER_PROFILE`. */
  readonly profile: typeof VERIFIER_PROFILE;
  readonly checks: readonly VerificationCheck[];
  /** Never affects `ok`. See `VerificationWarning`. */
  readonly warnings: readonly VerificationWarning[];
}

const pass = (name: string, category: VerificationCategory, detail = ''): VerificationCheck => ({
  name,
  ok: true,
  category,
  detail,
});
const fail = (name: string, category: VerificationCategory, detail: string): VerificationCheck => ({
  name,
  ok: false,
  category,
  detail,
});

/**
 * What reading one artifact produced.
 *
 * Three outcomes, not two, and the third is the point. "Absent" is a fact about the evidence and
 * feeds the presence contract; "unreadable" is a fact about this machine and must never be
 * reported as absence, because a directory whose files cannot be read would otherwise verify as a
 * smaller, consistent one.
 */
type ArtifactRead =
  | { readonly kind: 'present'; readonly bytes: Uint8Array }
  | { readonly kind: 'absent' }
  | { readonly kind: 'unreadable'; readonly reason: string };

/**
 * Read one artifact, without deciding anything about what its state means.
 *
 * The read is bounded and refuses anything that is not a regular file, because the directory comes
 * from whoever produced the evidence and a name in it can point at a pipe, a device or somewhere
 * else entirely. Only `ENOENT` is absence. Every refusal, a symlink, a non-regular file, a file
 * past its bound, or one this process may not open, is reported as unreadable with its reason: the
 * caller cannot tell those apart from a missing file by looking at the directory, so this refuses
 * to guess on its behalf.
 */
function readArtifact(directory: string, artifact: EvidenceArtifact): ArtifactRead {
  const read = readBoundedFile(join(directory, artifact), ARTIFACT_MAX_BYTES[artifact]);
  if (read.kind === 'read') return { kind: 'present', bytes: read.bytes };
  if (read.kind === 'absent') return { kind: 'absent' };
  return { kind: 'unreadable', reason: `${read.refusal}: ${read.detail}` };
}

/**
 * What admitting one JSON sidecar produced. Refusal is a result, never an exception.
 *
 * A refused document carries which rule refused it, because "not readable as JSON" covers bytes
 * that are not text, an object whose members are ambiguous, nesting past the scanner's bound and
 * ordinary syntax damage, and a reader deciding whether a directory was tampered with or merely
 * corrupted needs to know which one happened.
 */
type JsonRead =
  | { readonly kind: 'parsed'; readonly value: unknown }
  | { readonly kind: 'refused'; readonly refusal: StrictJsonRefusal }
  | { readonly kind: 'absent' };

/** A JSON object, as opposed to an array, a null, or a bare scalar wearing the same file name. */
function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * A bounded rendering of a value read out of a document.
 *
 * Report text is the one place attacker-controlled content could reach a reader's terminal at
 * whatever length it likes, so a value taken from a file is described rather than reproduced.
 */
function describeBound(value: unknown): string {
  if (typeof value === 'string') return value.length <= 80 ? value : `${value.slice(0, 80)}...`;
  if (typeof value === 'object' && value !== null) return 'a value that is not a string';
  return String(value).slice(0, 80);
}

function isTerminalState(value: unknown): value is TerminalState {
  return typeof value === 'string' && (TERMINAL_STATES as readonly string[]).includes(value);
}

/**
 * What a supplied key file said about itself, beyond the bytes verification actually uses.
 *
 * Only the bytes decide whether a signature is valid. The rest of the file is a description of
 * those bytes, and a description that disagrees with the record is worth reporting: it means the
 * file and the evidence were not produced for each other, whatever the signature says.
 */
export interface SuppliedKeyMetadata {
  readonly algorithm: string;
  readonly kid: string;
  readonly issuer: string;
}

/**
 * Verify an evidence directory.
 *
 * @param directory - Directory holding the record and the documents it binds.
 * @param publicKey - Ed25519 public key the record is expected to verify under.
 * @param suppliedKey - What a supplied key file declared, when the key came from one. Reported as
 *   its own checks; it is never treated as an identity claim.
 */
export async function verifyEvidence(
  directory: string,
  publicKey: Uint8Array,
  suppliedKey?: SuppliedKeyMetadata,
): Promise<EvidenceVerificationReport> {
  const checks: VerificationCheck[] = [];
  const warnings: VerificationWarning[] = [];

  // The directories the artifact names descend through, before any of those names is read. A
  // symlink standing in for one would leave every path below it looking like it names this
  // evidence directory while the bytes came from somewhere else, so it is refused here rather than
  // producing a set of individually plausible reads.
  for (const container of ARTIFACT_CONTAINERS) {
    const state = checkContainerDirectory(join(directory, container));
    if (state.kind === 'refused') {
      return {
        ok: false,
        profile: VERIFIER_PROFILE,
        checks: [
          fail(
            'nested artifact directories are directories',
            'structure',
            `${container} was refused (${state.refusal}: ${state.detail})`,
          ),
        ],
        warnings,
      };
    }
  }

  // Read every artifact once, before anything is decided. A file that exists but cannot be read is
  // reported as exactly that and stops the run: treating it as absent would let an unreadable
  // directory verify as a smaller, self-consistent one.
  const present = new Map<EvidenceArtifact, Uint8Array>();
  const unreadable: string[] = [];
  for (const artifact of EVIDENCE_ARTIFACTS) {
    const read = readArtifact(directory, artifact);
    if (read.kind === 'present') present.set(artifact, read.bytes);
    else if (read.kind === 'unreadable') unreadable.push(`${artifact} (${read.reason})`);
  }
  if (unreadable.length > 0) {
    return {
      ok: false,
      profile: VERIFIER_PROFILE,
      checks: [
        fail(
          'every artifact is readable',
          'structure',
          `refused, and absence must not be assumed: ${unreadable.join('; ')}`,
        ),
      ],
      warnings,
    };
  }

  /**
   * Admit one JSON sidecar, once.
   *
   * Every reader of a sidecar goes through here and reuses the admitted value, so a document cannot
   * be admitted strictly in one place and loosely in another, and a refused file produces a result
   * rather than an exception out of the middle of verification.
   *
   * The admission rules are the ones canonicalization requires. These documents are about to be
   * canonicalized and compared against digests inside a signed record, so bytes that are not valid
   * UTF-8 are refused rather than repaired, and an object with two members of the same name is
   * refused rather than resolved: JSON.parse would keep the last occurrence, another parser could
   * keep the first, and the signed digest would then cover whichever document the reader's parser
   * happened to build. That is a PEAC binding-safety rule, not an x402 conformance rule.
   */
  const parsedJson = new Map<EvidenceArtifact, JsonRead>();
  const readJsonArtifact = (artifact: EvidenceArtifact): JsonRead => {
    const cached = parsedJson.get(artifact);
    if (cached !== undefined) return cached;
    const bytes = present.get(artifact);
    let read: JsonRead;
    if (bytes === undefined) read = { kind: 'absent' };
    else {
      const admitted = parseStrictJson(bytes);
      read =
        admitted.status === 'parsed'
          ? { kind: 'parsed', value: admitted.value }
          : { kind: 'refused', refusal: admitted.refusal };
    }
    parsedJson.set(artifact, read);
    return read;
  };

  /** Why a sidecar was not admitted, in the report's voice rather than the scanner's. */
  const refusedDetail = (artifact: EvidenceArtifact, refusal: StrictJsonRefusal): string =>
    `${artifact} was refused before canonicalization (${refusal})`;

  const recordBytes = present.get('record.jws');
  if (recordBytes === undefined) {
    return {
      ok: false,
      profile: VERIFIER_PROFILE,
      checks: [fail('record present', 'structure', 'record.jws is missing')],
      warnings,
    };
  }
  // Decoded fatally, like every other document here. A record is base64url text, so bytes that are
  // not valid UTF-8 are not a record; replacing what is malformed would hand the verification
  // primitive a string nobody signed.
  const recordText = decodeStrictUtf8(recordBytes);
  if (recordText === undefined) {
    return {
      ok: false,
      profile: VERIFIER_PROFILE,
      checks: [fail('record signature and schema', 'integrity', 'the record bytes are not valid UTF-8')],
      warnings,
    };
  }
  const jws = recordText.trim();

  // The record is attacker-controlled bytes like everything else here, so a refusal from the
  // verification primitive is a result and a throw from it is still a verification failure.
  let verified: Awaited<ReturnType<typeof verifyLocal>>;
  try {
    verified = await verifyLocal(jws, publicKey);
  } catch {
    return {
      ok: false,
      profile: VERIFIER_PROFILE,
      checks: [
        fail('record signature and schema', 'integrity', 'the record could not be read as a PEAC record'),
      ],
      warnings,
    };
  }
  if (!verified.valid) {
    return {
      ok: false,
      profile: VERIFIER_PROFILE,
      checks: [fail('record signature and schema', 'integrity', `${verified.code}`)],
      warnings,
    };
  }
  checks.push(pass('record signature and schema', 'integrity', `verified under kid ${verified.kid}`));

  const claims = verified.claims as unknown as {
    iss?: unknown;
    type?: string;
    extensions?: Record<string, Record<string, unknown>>;
  };

  /**
   * What the key file said, against what the record says.
   *
   * Reported as three separate checks rather than one, because they answer different questions: an
   * algorithm this example does not verify under, a key identifier naming a different key, and an
   * issuer naming a different party are three distinct disagreements and a reader should be told
   * which one occurred. None of them is an identity check: a matching description of a key is
   * still a description, and the caveat printed alongside says so.
   */
  if (suppliedKey !== undefined) {
    checks.push(
      suppliedKey.algorithm === PUBLIC_KEY_ALGORITHM
        ? pass('supplied key algorithm', 'integrity', PUBLIC_KEY_ALGORITHM)
        : fail(
            'supplied key algorithm',
            'integrity',
            `the key file declares ${describeBound(suppliedKey.algorithm)}, ` +
              `and this example verifies only ${PUBLIC_KEY_ALGORITHM}`,
          ),
    );
    checks.push(
      suppliedKey.kid === verified.kid
        ? pass('supplied key identifier matches the record', 'integrity', verified.kid)
        : fail(
            'supplied key identifier matches the record',
            'integrity',
            `the key file names ${describeBound(suppliedKey.kid)}, ` +
              `the record names ${describeBound(verified.kid)}`,
          ),
    );
    checks.push(
      suppliedKey.issuer === claims.iss
        ? pass('supplied key issuer matches the record', 'integrity', suppliedKey.issuer)
        : fail(
            'supplied key issuer matches the record',
            'integrity',
            `the key file names ${describeBound(suppliedKey.issuer)}, ` +
              `the record names ${describeBound(claims.iss)}`,
          ),
    );
  }
  checks.push(
    claims.type === RECORD_TYPE
      ? pass('record type', 'structure', RECORD_TYPE)
      : fail('record type', 'structure', `expected ${RECORD_TYPE}, record carries ${String(claims.type)}`),
  );

  const commerce = claims.extensions?.[COMMERCE_GROUP];
  const evidence = claims.extensions?.[PAYMENT_EVIDENCE_GROUP];
  if (commerce === undefined || evidence === undefined) {
    checks.push(fail('extension groups', 'structure', 'the record is missing a required extension group'));
    return { ok: false, profile: VERIFIER_PROFILE, checks, warnings };
  }
  checks.push(pass('extension groups', 'structure', `${COMMERCE_GROUP}, ${PAYMENT_EVIDENCE_GROUP}`));

  /** Recompute one bound digest from the document that sits beside the record. */
  const recomputeJson = async (
    name: string,
    artifact: EvidenceArtifact,
    claimed: unknown,
  ): Promise<void> => {
    const bytes = present.get(artifact);
    if (claimed === undefined) {
      checks.push(
        bytes === undefined
          ? pass(name, 'integrity', 'not bound and not present')
          : fail(name, 'integrity', `${artifact} is present but the record binds no digest for it`),
      );
      return;
    }
    if (bytes === undefined) {
      checks.push(fail(name, 'integrity', `the record binds a digest but ${artifact} is missing`));
      return;
    }
    const parsed = readJsonArtifact(artifact);
    if (parsed.kind !== 'parsed') {
      // Reported without canonicalizing anything: a document that was refused never reaches the
      // digest computation below, so no digest is recomputed over a document nobody can pin down.
      checks.push(
        fail(
          name,
          'integrity',
          parsed.kind === 'refused'
            ? refusedDetail(artifact, parsed.refusal)
            : `${artifact} is missing`,
        ),
      );
      return;
    }
    const recomputed = coerceDigest(await computeJsonDocumentDigestJcs(parsed.value as JsonValue));
    checks.push(
      recomputed === claimed
        ? pass(name, 'integrity', recomputed)
        : fail(name, 'integrity', `recomputed ${recomputed}, record binds ${describeBound(claimed)}`),
    );
  };

  /**
   * Hold one admitted sidecar to the committed schema for its example-local profile.
   *
   * A separate question from the digest beside it. The digest says which document the record bound;
   * this says whether that document is one this example could have produced, so a binding with a
   * missing component, an unknown member or a digest string of the wrong shape is reported rather
   * than passed through intact.
   *
   * EXAMPLE-LOCAL, and the name says so. These schemas describe two documents this repository
   * invents. Satisfying one is not PEAC conformance and not x402 conformance, and neither profile
   * is registered anywhere.
   *
   * A document that was refused or is absent produces no check here: the digest check above already
   * carries that failure, and restating it as a second one would tell a reader nothing new.
   */
  const checkLocalProfile = (
    name: string,
    artifact: EvidenceArtifact,
    document: LocalProfileDocument,
  ): void => {
    const parsed = readJsonArtifact(artifact);
    if (parsed.kind !== 'parsed') return;
    const result = validateLocalProfile(document, parsed.value);
    checks.push(
      result.ok
        ? pass(name, 'structure', 'matches the example-local schema')
        : fail(name, 'structure', result.detail),
    );
  };

  await recomputeJson(
    'request binding digest',
    'request-binding.json',
    evidence['request_binding_digest'],
  );
  checkLocalProfile('request binding local profile', 'request-binding.json', 'request-binding');
  await recomputeJson(
    'origin result binding digest',
    'origin-result-binding.json',
    evidence['origin_result_binding_digest'],
  );
  checkLocalProfile(
    'origin result binding local profile',
    'origin-result-binding.json',
    'origin-result-binding',
  );
  await recomputeJson(
    'chain observation digest',
    'chain-observation.json',
    evidence['chain_observation_digest'],
  );
  // Schema-only: a separate question from the digest above. The digest says which bytes the
  // record bound; this says whether those bytes have the shape this example's own observation
  // profile produces, exactly as the two binding documents are already held to their schemas.
  checkLocalProfile('chain observation local profile schema', 'chain-observation.json', 'chain-observation');

  /** Recompute an observed field value digest from the bytes recorded beside the record. */
  const recomputeObserved = (name: string, artifact: EvidenceArtifact, claimed: unknown): void => {
    const bytes = present.get(artifact);
    if (claimed === undefined) {
      checks.push(
        bytes === undefined
          ? pass(name, 'integrity', 'not bound and not present')
          : fail(name, 'integrity', `${artifact} is present but the record binds no digest for it`),
      );
      return;
    }
    if (bytes === undefined) {
      checks.push(fail(name, 'integrity', `the record binds a digest but ${artifact} is missing`));
      return;
    }
    const recomputed = digestBytes(bytes);
    checks.push(
      recomputed === claimed
        ? pass(name, 'integrity', recomputed)
        : fail(name, 'integrity', `recomputed ${recomputed}, record binds ${describeBound(claimed)}`),
    );
  };

  recomputeObserved(
    'payment-required digest',
    'artifacts/payment-required.txt',
    evidence['payment_required_digest'],
  );
  recomputeObserved(
    'payment-signature digest',
    'artifacts/payment-signature.txt',
    evidence['payment_signature_digest'],
  );
  recomputeObserved(
    'payment-response digest',
    'artifacts/payment-response.txt',
    evidence['payment_response_digest'],
  );

  // The result binding names the body by digest, so the body is checked against the binding rather
  // than against the record: that is where the claim about the bytes actually lives.
  const resultBinding = readJsonArtifact('origin-result-binding.json');
  const bodyBytes = present.get('origin-result-body.bin');
  if (resultBinding.kind !== 'absent') {
    if (resultBinding.kind === 'refused') {
      const detail = refusedDetail('origin-result-binding.json', resultBinding.refusal);
      checks.push(fail('origin result body', 'integrity', detail));
    } else if (!isJsonObject(resultBinding.value)) {
      checks.push(fail('origin result body', 'integrity', 'the result binding is not a JSON object'));
    } else if (bodyBytes === undefined) {
      checks.push(
        fail('origin result body', 'integrity', 'the result binding exists but the body is missing'),
      );
    } else {
      const boundBodyDigest = resultBinding.value['bodyDigest'];
      const recomputed: Sha256Digest = digestBytes(bodyBytes);
      checks.push(
        recomputed === boundBodyDigest
          ? pass('origin result body', 'integrity', recomputed)
          : fail(
              'origin result body',
              'integrity',
              `recomputed ${recomputed}, binding names ${describeBound(boundBodyDigest)}`,
            ),
      );
    }
  }

  // The terminal state comes from inside the signed record, so the expected artifact set cannot be
  // chosen after the fact to match whatever files happen to be there.
  const terminalState = evidence['terminal_state'];
  if (!isTerminalState(terminalState)) {
    checks.push(fail('terminal state', 'structure', 'the record carries no recognised terminal state'));
    return { ok: false, profile: VERIFIER_PROFILE, checks, warnings };
  }
  const violations = checkPresence(terminalState, new Set(present.keys()));
  checks.push(
    violations.length === 0
      ? pass('artifact presence contract', 'structure', `consistent with ${terminalState}`)
      : fail(
          'artifact presence contract',
          'structure',
          violations
            .map((v) => `${v.artifact} is ${v.present ? 'present' : 'missing'} but declared ${v.expectation}`)
            .join('; '),
        ),
  );

  // A refused or unreached settlement must carry no transaction facts, because a transaction
  // reference beside a failure reads as a payment that happened.
  const observationRead = readJsonArtifact('chain-observation.json');
  if (observationRead.kind === 'refused') {
    checks.push(
      fail(
        'chain observation',
        'structure',
        refusedDetail('chain-observation.json', observationRead.refusal),
      ),
    );
  } else if (observationRead.kind === 'parsed' && !isJsonObject(observationRead.value)) {
    checks.push(fail('chain observation', 'structure', 'chain-observation.json is not a JSON object'));
  } else if (observationRead.kind === 'parsed') {
    const observationDocument = observationRead.value as Record<string, unknown>;
    const expectation = isJsonObject(observationDocument['payment_expectation'])
      ? (observationDocument['payment_expectation'] as Record<string, unknown>)
      : undefined;
    const report = isJsonObject(observationDocument['chain_observation'])
      ? (observationDocument['chain_observation'] as Record<string, unknown>)
      : undefined;
    const rpc = isJsonObject(observationDocument['rpc_observation'])
      ? (observationDocument['rpc_observation'] as Record<string, unknown>)
      : undefined;

    // Which document this is, and which payment scheme it describes. Both are stated by the
    // producer, so both are checked rather than assumed: an observation carrying another profile,
    // or another scheme, is not the document the rest of these checks are written against.
    checks.push(
      observationDocument['profile'] === PROFILE_CHAIN_OBSERVATION
        ? pass('chain observation local profile', 'structure', PROFILE_CHAIN_OBSERVATION)
        : fail(
            'chain observation local profile',
            'structure',
            `expected ${PROFILE_CHAIN_OBSERVATION}, the document names ` +
              `${describeBound(observationDocument['profile'])}`,
          ),
    );
    checks.push(
      observationDocument['scheme'] === OBSERVED_SCHEME
        ? pass('chain observation scheme', 'structure', OBSERVED_SCHEME)
        : fail(
            'chain observation scheme',
            'structure',
            `this example records the ${OBSERVED_SCHEME} scheme only, the document names ` +
              `${describeBound(observationDocument['scheme'])}`,
          ),
    );
    checks.push(
      expectation !== undefined && report !== undefined
        ? pass(
            'expectation and observation are separately attributed',
            'structure',
            'payment_expectation and chain_observation both present with their sources',
          )
        : fail(
            'expectation and observation are separately attributed',
            'structure',
            'the document does not carry both attributed objects',
          ),
    );
    if (expectation === undefined || report === undefined) {
      return { ok: false, profile: VERIFIER_PROFILE, checks, warnings };
    }

    const settled = report['settlement_outcome'] === 'succeeded';
    const hasTransaction = typeof report['transaction_hash'] === 'string';
    checks.push(
      settled === hasTransaction
        ? pass(
            'settlement facts match the outcome',
            'structure',
            settled ? 'settled, transaction recorded' : 'not settled, no transaction recorded',
          )
        : fail(
            'settlement facts match the outcome',
            'structure',
            settled
              ? 'settlement succeeded but no transaction reference is recorded'
              : 'a transaction reference is recorded for a settlement that did not succeed',
          ),
    );

    /**
     * The sealed-L2 RPC account, when one is present.
     *
     * Optional by design: an offline run asks nobody, and a live run whose endpoint was
     * unreachable records an unavailable observation rather than none. What is not optional is
     * that it describe the same transaction the settlement did, and that an inclusion claim carry
     * the sealed block data it was established from. An inclusion level without block placement
     * would be a claim the document does not back, and a second observer attached to a different
     * transaction would read as corroboration of something this run never observed.
     */
    if (rpc !== undefined) {
      const sameTransaction =
        typeof report['transaction_hash'] === 'string' &&
        rpc['transaction_hash'] === report['transaction_hash'];
      checks.push(
        sameTransaction
          ? pass(
              'rpc observation transaction',
              'structure',
              'it describes the transaction the settlement recorded',
            )
          : fail(
              'rpc observation transaction',
              'structure',
              'it describes a transaction the settlement observation does not record',
            ),
      );
      const claimsInclusion = rpc['observation_level'] === 'l2_block_inclusion';
      checks.push(
        !claimsInclusion ||
          (typeof rpc['block_number'] === 'string' && typeof rpc['block_hash'] === 'string')
          ? pass(
              'rpc inclusion claim carries its basis',
              'structure',
              claimsInclusion
                ? 'l2_block_inclusion with sealed block placement recorded'
                : 'no inclusion level is claimed',
            )
          : fail(
              'rpc inclusion claim carries its basis',
              'structure',
              'the observation claims l2_block_inclusion without recording the sealed block data',
            ),
      );

      /**
       * Two observers of the same transaction, saying different things.
       *
       * Reported and never resolved. The facilitator is a party to the payment and the RPC
       * endpoint is a separate observer, so deciding which of them was right would mean this
       * verifier promoting one account to a fact about the network, which it is in no position to
       * do. Nor is it a signature failure: the record says exactly what each observer said, and it
       * says it intact. So the disagreement is surfaced where a reader will see it, and left
       * there.
       */
      if (sameTransaction && settled && rpc['receipt_status'] === 'reverted') {
        warnings.push({
          name: 'observer disagreement',
          detail:
            'the settlement reporter recorded success; the RPC endpoint reported the transaction ' +
            'with a reverted execution status. These are separate attributed observations and ' +
            'have not been reconciled here.',
        });
      }
      if (sameTransaction && settled && rpc['observation_state'] === 'not_found') {
        warnings.push({
          name: 'observer disagreement',
          detail:
            'the settlement reporter recorded success; the RPC endpoint reported no receipt and ' +
            'no transaction for that hash at the time it was asked. These are separate attributed ' +
            'observations and have not been reconciled here.',
        });
      }
    }

    /**
     * The recorded comparison, recomputed.
     *
     * The comparison is a pure function of the expectation, the settlement report and the RPC
     * account, so the verifier runs the same function over the document it was handed and holds
     * the recorded verdicts to the result. A comparison edited to say `match` while the fields
     * beside it disagree fails here by name. Recomputing it is still internal consistency, not
     * truth: agreement between two parts of one document says nothing about the network.
     */
    const recordedComparison = isJsonObject(observationDocument['comparison'])
      ? (observationDocument['comparison'] as Record<string, unknown>)
      : undefined;
    if (recordedComparison === undefined) {
      checks.push(fail('expectation comparison', 'consistency', 'the document records no comparison object'));
    } else {
      const recomputed = compareExpectationToObservation({
        payment_expectation: expectation,
        chain_observation: report,
        ...(rpc !== undefined ? { rpc_observation: rpc } : {}),
      } as unknown as Pick<
        BaseChainObservationV1,
        'payment_expectation' | 'chain_observation' | 'rpc_observation'
      >);
      const disagreements = (
        Object.entries(recomputed) as ReadonlyArray<[string, ComparisonVerdict | 'linked']>
      ).filter(([field, verdict]) => recordedComparison[field] !== verdict);
      checks.push(
        disagreements.length === 0
          ? pass(
              'expectation comparison',
              'consistency',
              Object.entries(recomputed)
                .map(([field, verdict]) => `${field}=${verdict}`)
                .join(' '),
            )
          : fail(
              'expectation comparison',
              'consistency',
              disagreements
                .map(
                  ([field, verdict]) =>
                    `${field} is recorded as ${describeBound(recordedComparison[field])}, ` +
                    `recomputed as ${verdict}`,
                )
                .join('; '),
            ),
      );
      // A successful execution status alone is never matching-payment evidence: when the RPC
      // account carries a receipt, the transfer-event verdict must have been evaluated, so a
      // reader is always told whether the expected transfer was actually observed.
      if (rpc !== undefined && typeof rpc['receipt_status'] === 'string') {
        checks.push(
          recomputed.transfer_event !== 'not_evaluated'
            ? pass('transfer event verdict evaluated', 'consistency', recomputed.transfer_event)
            : fail(
                'transfer event verdict evaluated',
                'consistency',
                'an RPC receipt is recorded but the transfer-event verdict was not evaluated',
              ),
        );
      }
    }

    /**
     * The fields the record and the observation deliberately state twice.
     *
     * Everything above this point checks that each document is the one the record bound and that it
     * has not been altered. None of it compares the documents to each other, so a directory whose
     * signature is valid and whose every digest recomputes can still hold a record describing one
     * payment beside an observation describing another: both were signed and bound together, and
     * neither is damaged. That is a producer defect rather than tampering, and it is exactly the
     * kind of defect a reader receiving evidence from elsewhere cannot see.
     *
     * INTERNAL CONSISTENCY ONLY. These compare this evidence against itself. Agreement means the
     * two documents describe the same interaction. It says nothing about whether the transaction
     * exists, whether it is final, whether any chain agrees, or whether the issuer is who the
     * record names, and no check below may be read as saying otherwise.
     */
    const agreeOnValue = (name: string, recorded: unknown, observed: unknown): void => {
      if (typeof recorded !== 'string' || typeof observed !== 'string') {
        checks.push(
          fail(name, 'consistency', 'the value is absent on one side, so there is nothing to compare'),
        );
        return;
      }
      checks.push(
        recorded === observed
          ? pass(name, 'consistency', describeBound(recorded))
          : fail(
              name,
              'consistency',
              `the record carries ${describeBound(recorded)}, ` +
                `the observation carries ${describeBound(observed)}`,
            ),
      );
    };

    /**
     * The same comparison for a digest that either side may legitimately not carry.
     *
     * A run that settled nothing has no settlement response and no origin result, so absence on
     * both sides is the honest state and passes. Absence on one side alone does not: a digest
     * recorded in one document and not in the other means the two documents disagree about what
     * this run produced.
     */
    const agreeOnOptionalDigest = (
      name: string,
      recorded: unknown,
      observed: unknown,
      absentDetail: string,
    ): void => {
      if (recorded === undefined && observed === undefined) {
        checks.push(pass(name, 'consistency', absentDetail));
        return;
      }
      if (typeof recorded !== 'string' || typeof observed !== 'string') {
        checks.push(
          fail(name, 'consistency', 'it is recorded in one of the two documents and not in the other'),
        );
        return;
      }
      checks.push(
        recorded === observed
          ? pass(name, 'consistency', describeBound(recorded))
          : fail(
              name,
              'consistency',
              `one document names ${describeBound(recorded)}, ` +
                `the other names ${describeBound(observed)}`,
            ),
      );
    };

    agreeOnValue(
      'record and observation name the same network',
      evidence['network'],
      expectation['network'],
    );
    agreeOnValue(
      'record and observation name the same terminal state',
      terminalState,
      observationDocument['terminal_state'],
    );
    agreeOnValue(
      'record and observation name the same asset',
      commerce['asset'],
      expectation['asset'],
    );
    agreeOnValue(
      'record and observation name the same amount',
      commerce['amount_minor'],
      expectation['amount_base_units'],
    );
    agreeOnOptionalDigest(
      'record and observation name the same settlement response digest',
      evidence['payment_response_digest'],
      observationDocument['settlement_response_digest'],
      'no settlement response was recorded by either document',
    );

    // The origin result is named by the result binding rather than by the record, so the comparison
    // is between that binding and the observation. A binding that was refused or is not an object
    // produces no comparison: the checks above already report it, and a value read out of a
    // document nobody could admit is not a side of anything.
    if (resultBinding.kind !== 'refused') {
      const boundBodyDigest =
        resultBinding.kind === 'parsed' && isJsonObject(resultBinding.value)
          ? resultBinding.value['bodyDigest']
          : undefined;
      if (resultBinding.kind === 'absent' || boundBodyDigest !== undefined) {
        agreeOnOptionalDigest(
          'result binding and observation name the same origin result digest',
          boundBodyDigest,
          observationDocument['service_result_digest'],
          'no origin result was recorded by either document',
        );
      }
    }

    /**
     * NATIVE-ARTIFACT AGREEMENT. Does the payment this evidence captured, decoded on its own
     * terms, actually say what the record and the observation say it says?
     *
     * Everything above this point treats the three captured x402 field values as opaque bytes: it
     * digests them and checks that the digest the record binds recomputes. That proves the bytes
     * are the ones the record named. It says nothing about their CONTENTS -- a producer can
     * re-issue a record whose native payment-signature names one amount while the record and the
     * observation both name another, refresh the bound digest, and every check above still
     * passes. These checks decode the captured artifacts and compare the decoded values against
     * the record and the observation directly, never re-serializing anything and never quoting
     * document text beyond `describeBound`.
     *
     * HELD VS PRESERVED. `held` asks whether this evidence describes a settled payment. When it
     * does, a native artifact disagreeing with the record or the observation is a verdict: two
     * things that should describe one payment do not. When it does not -- a rejected or malformed
     * payment attempt is exactly as legitimate a thing to hold evidence of as a settled one -- the
     * native content was never a settled payment for the expectation to have agreed or disagreed
     * with, so it is reported as preserved evidence of the attempt rather than measured against
     * an expectation it never had to satisfy.
     */
    const held = terminalState === 'response_write_attempted';

    /** A bounded rendering of one decode attempt's stage outcomes. */
    const stageSummary = (artifact: CapturedX402Artifact): string =>
      X402_STAGES.map((stage) => `${stage}=${artifact.stages[stage]}`).join(' ');

    type NativeDecode =
      | { readonly kind: 'absent' }
      | { readonly kind: 'undecodable'; readonly reason: string }
      | { readonly kind: 'decoded'; readonly artifact: CapturedX402Artifact };

    /**
     * Decode one present native artifact. Never throws: `captureObservedX402Artifact` throws only
     * for input that cannot be treated as an observed field value at all (non-visible-ASCII, or
     * past the declared size bound), which is refused here as "not decodable" rather than aborting
     * the whole verification run. Every other malformed shape is a captured, staged result.
     */
    const decodeNative = async (
      name: X402HeaderName,
      artifact: EvidenceArtifact,
      capturePoint: 'origin_request_after_http_parsing' | 'origin_response_before_gateway',
    ): Promise<NativeDecode> => {
      const bytes = present.get(artifact);
      if (bytes === undefined) return { kind: 'absent' };
      const text = decodeStrictUtf8(bytes);
      if (text === undefined) {
        return { kind: 'undecodable', reason: 'the artifact bytes are not valid UTF-8' };
      }
      try {
        const captured = await captureObservedX402Artifact({
          name,
          observedValue: text,
          capturePoint,
          httpVersion: '1.1',
        });
        return { kind: 'decoded', artifact: captured };
      } catch (e) {
        return {
          kind: 'undecodable',
          reason: e instanceof Error ? describeBound(e.message) : 'the artifact could not be captured',
        };
      }
    };

    const requiredDecode = await decodeNative(
      'payment-required',
      'artifacts/payment-required.txt',
      'origin_response_before_gateway',
    );
    const signatureDecode = await decodeNative(
      'payment-signature',
      'artifacts/payment-signature.txt',
      'origin_request_after_http_parsing',
    );
    const responseDecode = await decodeNative(
      'payment-response',
      'artifacts/payment-response.txt',
      'origin_response_before_gateway',
    );

    if (held) {
      const REQUIRED_STAGES = ['transport', 'json', 'duplicate-members', 'upstream-schema'] as const;
      const SIGNATURE_STAGES = [
        'transport',
        'json',
        'duplicate-members',
        'upstream-schema',
        'scheme-payload',
      ] as const;
      const RESPONSE_STAGES = ['transport', 'json', 'duplicate-members'] as const;

      /** Emit the one named decode check for a present artifact. Statement form, not a ternary
       * chain, so the discriminated union narrows on every branch. */
      const emitDecodeCheck = (checkName: string, decode: NativeDecode, ok: boolean): void => {
        if (decode.kind === 'absent') return;
        if (ok) {
          if (decode.kind === 'decoded') checks.push(pass(checkName, 'native', stageSummary(decode.artifact)));
          return;
        }
        if (decode.kind === 'undecodable') {
          checks.push(fail(checkName, 'native', decode.reason));
        } else {
          checks.push(
            fail(checkName, 'native', `stage requirements not satisfied: ${stageSummary(decode.artifact)}`),
          );
        }
      };

      const requiredOk =
        requiredDecode.kind === 'decoded' &&
        REQUIRED_STAGES.every((stage) => requiredDecode.artifact.stages[stage] === 'accepted');
      emitDecodeCheck('native payment-required decodes', requiredDecode, requiredOk);

      const signatureOk =
        signatureDecode.kind === 'decoded' &&
        SIGNATURE_STAGES.every((stage) => signatureDecode.artifact.stages[stage] === 'accepted') &&
        signatureDecode.artifact.stages.extensions !== 'rejected';
      emitDecodeCheck('native payment-signature decodes', signatureDecode, signatureOk);

      const responseOk =
        responseDecode.kind === 'decoded' &&
        RESPONSE_STAGES.every((stage) => responseDecode.artifact.stages[stage] === 'accepted') &&
        responseDecode.artifact.localStructural?.localStructuralStatus === 'accepted';
      emitDecodeCheck('native payment-response decodes', responseDecode, responseOk);

      // Dependent checks: no cascade. A decode failure already produced its one named failure
      // above, and none of the checks below is emitted for an artifact that did not decode.
      if (signatureOk && signatureDecode.kind === 'decoded') {
        const payload = signatureDecode.artifact.decoded as unknown as PaymentPayload;
        const accepted = payload.accepted as
          | {
              readonly scheme?: unknown;
              readonly network?: unknown;
              readonly asset?: unknown;
              readonly amount?: unknown;
              readonly payTo?: unknown;
            }
          | undefined;

        // 4. payment-signature terms match the expectation.
        const acceptedAsset = accepted?.asset;
        const acceptedPayTo = accepted?.payTo;
        const termsOk =
          accepted?.scheme === 'exact' &&
          accepted.network === expectation['network'] &&
          typeof acceptedAsset === 'string' &&
          typeof expectation['asset'] === 'string' &&
          sameAddress(acceptedAsset, expectation['asset']) &&
          accepted.amount === expectation['amount_base_units'] &&
          typeof acceptedPayTo === 'string' &&
          typeof expectation['recipient'] === 'string' &&
          sameAddress(acceptedPayTo, expectation['recipient']);
        checks.push(
          termsOk
            ? pass(
                'payment-signature terms match the expectation',
                'native',
                'scheme, network, asset, amount and recipient agree with the expectation',
              )
            : fail(
                'payment-signature terms match the expectation',
                'native',
                `the native accepted terms disagree with the expectation: scheme ${describeBound(accepted?.scheme)}, ` +
                  `network ${describeBound(accepted?.network)}, asset ${describeBound(acceptedAsset)}, ` +
                  `amount ${describeBound(accepted?.amount)}, payTo ${describeBound(acceptedPayTo)}`,
              ),
        );

        // 5. payment-signature authorization matches the expectation.
        const rawPayload = payload.payload as Record<string, unknown> | undefined;
        const rawAuthorization = isJsonObject(rawPayload?.['authorization'])
          ? (rawPayload['authorization'] as Record<string, unknown>)
          : undefined;
        const expectationPayer = expectation['payer'];
        const fromOk =
          typeof rawAuthorization?.['from'] === 'string' &&
          typeof expectationPayer === 'string' &&
          sameAddress(rawAuthorization['from'] as string, expectationPayer);
        const toOk =
          typeof rawAuthorization?.['to'] === 'string' &&
          typeof expectation['recipient'] === 'string' &&
          sameAddress(rawAuthorization['to'] as string, expectation['recipient'] as string);
        const valueOk = rawAuthorization?.['value'] === expectation['amount_base_units'];
        let digestOk = false;
        if (rawAuthorization !== undefined) {
          try {
            digestOk =
              coerceDigest(await computeJsonDocumentDigestJcs(rawAuthorization as JsonValue)) ===
              expectation['authorization_digest'];
          } catch {
            digestOk = false;
          }
        }
        checks.push(
          fromOk && toOk && valueOk && digestOk
            ? pass(
                'payment-signature authorization matches the expectation',
                'native',
                'from, to, value and the authorization digest agree with the expectation',
              )
            : fail(
                'payment-signature authorization matches the expectation',
                'native',
                `the native authorization disagrees with the expectation: from ${describeBound(rawAuthorization?.['from'])}, ` +
                  `to ${describeBound(rawAuthorization?.['to'])}, value ${describeBound(rawAuthorization?.['value'])}, ` +
                  `authorization digest agreement ${digestOk}`,
              ),
        );

        // 6. payment-signature identifier matches the record reference.
        const paymentIdentifier = extractPaymentIdentifier(payload);
        const recordReference = commerce['reference'];
        if (paymentIdentifier === null && recordReference === undefined) {
          checks.push(
            pass(
              'payment-signature identifier matches the record reference',
              'native',
              'no payment identifier was used',
            ),
          );
        } else if (paymentIdentifier === null || recordReference === undefined) {
          checks.push(
            fail(
              'payment-signature identifier matches the record reference',
              'native',
              `the identifier is present on one side and not the other: native ${describeBound(paymentIdentifier)}, ` +
                `record ${describeBound(recordReference)}`,
            ),
          );
        } else {
          checks.push(
            paymentIdentifier === recordReference
              ? pass(
                  'payment-signature identifier matches the record reference',
                  'native',
                  describeBound(paymentIdentifier),
                )
              : fail(
                  'payment-signature identifier matches the record reference',
                  'native',
                  `native names ${describeBound(paymentIdentifier)}, record names ${describeBound(recordReference)}`,
                ),
          );
        }

        // 7. payment-signature resource matches the request binding.
        const requestBindingRead = readJsonArtifact('request-binding.json');
        if (requestBindingRead.kind === 'parsed' && isJsonObject(requestBindingRead.value)) {
          const bindingComponents = isJsonObject(requestBindingRead.value['components'])
            ? (requestBindingRead.value['components'] as Record<string, unknown>)
            : undefined;
          const resourceUrl = isJsonObject(payload.resource)
            ? (payload.resource as { readonly url?: unknown }).url
            : undefined;
          if (bindingComponents === undefined || typeof resourceUrl !== 'string') {
            checks.push(
              fail(
                'payment-signature resource matches the request binding',
                'native',
                'the request binding carries no components, or the native resource carries no url',
              ),
            );
          } else {
            try {
              const method =
                typeof bindingComponents['@method'] === 'string'
                  ? (bindingComponents['@method'] as string)
                  : 'GET';
              const derived = componentsFromAbsoluteUri({ method, absoluteUri: resourceUrl });
              const agree =
                derived['@scheme'] === bindingComponents['@scheme'] &&
                derived['@authority'] === bindingComponents['@authority'] &&
                derived['@path'] === bindingComponents['@path'] &&
                derived['@query'] === bindingComponents['@query'];
              checks.push(
                agree
                  ? pass(
                      'payment-signature resource matches the request binding',
                      'native',
                      'scheme, authority, path and query agree',
                    )
                  : fail(
                      'payment-signature resource matches the request binding',
                      'native',
                      'the resource the native payment names does not match the request binding components',
                    ),
              );
            } catch (e) {
              checks.push(
                fail(
                  'payment-signature resource matches the request binding',
                  'native',
                  e instanceof ComponentError
                    ? `the native resource url could not be read as request components: ${describeBound(e.message)}`
                    : 'the native resource url could not be read as request components',
                ),
              );
            }
          }
        }

        // 8. payment-required advertises the accepted terms.
        if (requiredOk && requiredDecode.kind === 'decoded') {
          const required = requiredDecode.artifact.decoded as unknown as PaymentRequired;
          const requiredResourceUrl = isJsonObject(required.resource)
            ? (required.resource as { readonly url?: unknown }).url
            : undefined;
          const signatureResourceUrl = isJsonObject(payload.resource)
            ? (payload.resource as { readonly url?: unknown }).url
            : undefined;
          const accepts = Array.isArray(required.accepts) ? required.accepts : [];
          const advertised = accepts.some((entry) => {
            if (typeof entry !== 'object' || entry === null) return false;
            const candidate = entry as {
              readonly scheme?: unknown;
              readonly network?: unknown;
              readonly asset?: unknown;
              readonly amount?: unknown;
              readonly payTo?: unknown;
            };
            return (
              candidate.scheme === accepted?.scheme &&
              candidate.network === accepted?.network &&
              typeof candidate.asset === 'string' &&
              typeof acceptedAsset === 'string' &&
              sameAddress(candidate.asset, acceptedAsset) &&
              candidate.amount === accepted?.amount &&
              typeof candidate.payTo === 'string' &&
              typeof acceptedPayTo === 'string' &&
              sameAddress(candidate.payTo, acceptedPayTo)
            );
          });
          const urlsAgree =
            typeof requiredResourceUrl === 'string' && requiredResourceUrl === signatureResourceUrl;
          checks.push(
            urlsAgree && advertised
              ? pass(
                  'payment-required advertises the accepted terms',
                  'native',
                  'the resource url and the accepted terms both appear in the payment-required accepts list',
                )
              : fail(
                  'payment-required advertises the accepted terms',
                  'native',
                  `the payment-required document does not advertise the accepted terms: ` +
                    `resource url agreement ${urlsAgree}, terms advertised ${advertised}`,
                ),
          );
        }
      }

      // 9. payment-response matches the settlement observation.
      if (responseOk && responseDecode.kind === 'decoded') {
        const response = responseDecode.artifact.decoded as unknown as SettleResponse;
        const successOk = response.success === (report['settlement_outcome'] === 'succeeded');
        const transactionOk = response.transaction === report['transaction_hash'];
        const networkOk = response.network === report['network_reported'];
        const payerOk =
          response.payer === undefined ||
          (typeof response.payer === 'string' &&
            typeof report['payer_reported'] === 'string' &&
            sameAddress(response.payer, report['payer_reported'] as string));
        checks.push(
          successOk && transactionOk && networkOk && payerOk
            ? pass(
                'payment-response matches the settlement observation',
                'native',
                'success, transaction, network and payer agree with the settlement observation',
              )
            : fail(
                'payment-response matches the settlement observation',
                'native',
                `the native settlement response disagrees with the observation: success ${successOk}, ` +
                  `transaction ${transactionOk}, network ${networkOk}, payer ${payerOk}`,
              ),
        );
      }
    } else {
      for (const [artifact, decode] of [
        ['artifacts/payment-required.txt', requiredDecode],
        ['artifacts/payment-signature.txt', signatureDecode],
        ['artifacts/payment-response.txt', responseDecode],
      ] as const) {
        if (decode.kind === 'absent') continue;
        const stages =
          decode.kind === 'decoded' ? stageSummary(decode.artifact) : `not decodable (${decode.reason})`;
        checks.push(
          pass(
            `native ${artifact} preserved as presented`,
            'native',
            `not held to the expectation: the record's terminal state is ${terminalState}, so the ` +
              `presented payment is evidence of the attempt, not of a settled payment; stages ${stages}`,
          ),
        );
      }
    }

    // Always emitted: the request body itself is never part of the evidence directory, so there
    // is nothing here for a native check to recompute; only the digest the binding recorded of it.
    checks.push(
      pass(
        'request body preimage',
        'structure',
        'the request body digest is recorded in the binding; the body is not part of the evidence ' +
          'directory and is not recomputed',
      ),
    );
  }

  return { ok: checks.every((c) => c.ok), profile: VERIFIER_PROFILE, checks, warnings };
}

/** A command line this verifier cannot act on. Never raised for evidence that simply fails. */
export class UsageError extends Error {}

export const VERIFY_USAGE = [
  'Usage:',
  '  verify                                        verify the committed fixture evidence',
  '  verify --evidence <dir> --public-key <file>   verify any evidence directory',
].join('\n');

const HELP_ARGUMENTS = new Set(['--help', '-h', 'help']);

/**
 * Whether the arguments ask for the usage text rather than a verification.
 *
 * Asking for help is a request this verifier can answer, not a command it cannot act on, so it is
 * recognised before parsing rather than surfacing as an unrecognised argument. The separator is
 * skipped for the same reason it is skipped when parsing.
 */
export function isHelpRequest(argv: readonly string[]): boolean {
  const start = argv[0] === '--' ? 1 : 0;
  return argv.slice(start).some((argument) => HELP_ARGUMENTS.has(argument));
}

export interface VerifyRequest {
  /** Directory to read. */
  readonly directory: string;
  /** How that directory is named in output. Never an absolute machine-specific path. */
  readonly display: string;
  /** Public key file to verify under. Absent means the committed fixture and its test key. */
  readonly publicKeyFile?: string;
}

/**
 * Decide what to verify, from arguments alone.
 *
 * The two options are required together on purpose. `--evidence` without a key would fall back to
 * the fixture's test key, and a directory that failed for that reason would look like tampering
 * rather than like the wrong key. `--public-key` without a directory would verify the committed
 * fixture under someone else's key, which answers a question nobody asked.
 *
 * @param argv - Arguments after the script name.
 * @throws UsageError for anything this verifier cannot act on.
 */
export function parseVerifyArguments(argv: readonly string[]): VerifyRequest {
  let evidence: string | undefined;
  let publicKeyFile: string | undefined;

  // A leading `--` is the package manager's argument separator. Some versions consume it and some
  // forward it verbatim, so it is accepted and dropped here rather than making the documented
  // command depend on which one is installed.
  const start = argv[0] === '--' ? 1 : 0;

  for (let index = start; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument !== '--evidence' && argument !== '--public-key') {
      throw new UsageError(`unrecognised argument: ${argument.slice(0, 40)}`);
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new UsageError(`${argument} needs a value`);
    }
    if (argument === '--evidence') {
      if (evidence !== undefined) throw new UsageError('--evidence was given more than once');
      evidence = value;
    } else {
      if (publicKeyFile !== undefined) throw new UsageError('--public-key was given more than once');
      publicKeyFile = value;
    }
    index += 1;
  }

  if (evidence === undefined && publicKeyFile === undefined) {
    return { directory: EXPECTED_EVIDENCE_DIR, display: EXPECTED_EVIDENCE_DISPLAY };
  }
  if (evidence === undefined) {
    throw new UsageError('--public-key needs --evidence: it cannot verify the committed fixture');
  }
  if (publicKeyFile === undefined) {
    throw new UsageError('--evidence needs --public-key: the fixture key verifies only the fixture');
  }
  return { directory: evidence, display: evidence, publicKeyFile };
}

function requestFrom(argv: readonly string[]): VerifyRequest {
  try {
    return parseVerifyArguments(argv);
  } catch (e) {
    if (!(e instanceof UsageError)) throw e;
    console.error(`\n${e.message}\n\n${VERIFY_USAGE}\n`);
    process.exit(2);
  }
}

function keyFrom(path: string): LoadedIssuerPublicKey {
  try {
    return readIssuerPublicKeyFile(path);
  } catch (e) {
    if (!(e instanceof InvalidPublicKeyFileError)) throw e;
    console.error(`\n${e.message}\n`);
    process.exit(2);
  }
}

/**
 * Entry point for `pnpm verify`.
 *
 * With no arguments it verifies the committed fixture under the test key, which is the position a
 * reader of this repository is in. With `--evidence` and `--public-key` it verifies any directory
 * under any supplied key, which is the position someone handed a live run's output is in. Both read
 * files and a key and nothing else: no network, no origin, no state shared with whatever produced
 * the directory.
 */
export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<void> {
  if (isHelpRequest(argv)) {
    console.log(`\n${VERIFY_USAGE}\n`);
    return;
  }
  const request = requestFrom(argv);
  const supplied = request.publicKeyFile === undefined ? undefined : keyFrom(request.publicKeyFile);
  const publicKey = supplied?.publicKey ?? (await resolveIssuerKey('fixture')).publicKey;

  const report = await verifyEvidence(
    request.directory,
    publicKey,
    supplied === undefined
      ? undefined
      : { algorithm: supplied.algorithm, kid: supplied.kid, issuer: supplied.issuer },
  );
  console.log(formatReport(request.display, report));
  // Stated on every run under a supplied key, including a successful one, because success is
  // exactly where the claim is easiest to overstate.
  if (request.publicKeyFile !== undefined) console.log(`  ${SUPPLIED_KEY_CAVEAT}\n`);
  if (!report.ok) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}

/**
 * Render a report. The text is not bound by anything; it is a reading of the files.
 *
 * Warnings print under their own marker, after the checks and before the verdict, so a reader can
 * tell at a glance that something is being reported rather than decided. A report with no warnings
 * prints exactly as it did before they existed.
 */
export function formatReport(directory: string, report: EvidenceVerificationReport): string {
  const lines = ['', `Evidence verification: ${directory}`, `  profile: ${report.profile}`, ''];
  for (const check of report.checks) {
    lines.push(
      `  ${check.ok ? 'ok  ' : 'FAIL'}  [${check.category}] ${check.name}` +
        `${check.detail ? `: ${check.detail}` : ''}`,
    );
  }
  lines.push('');
  lines.push(
    '  Established by this verifier: signature and digest integrity under the supplied key; document ' +
      'structure; cross-document consistency; agreement between the captured native x402 artifacts and ' +
      'the record.',
  );
  lines.push(
    '  Not established: native payment validity (signature recovery, balances, authorization windows); ' +
      'issuer identity; a fresh chain observation; relying-party acceptance.',
  );
  for (const warning of report.warnings) {
    lines.push(`  warn  ${warning.name}: ${warning.detail}`);
  }
  lines.push('');
  lines.push(
    report.ok
      ? 'Verified. Contents are intact relative to the supplied key, every bound digest recomputes, ' +
        'and the checked cross-document fields are internally consistent.'
      : 'Not verified. See the failures above.',
  );
  if (report.warnings.length > 0) {
    lines.push('Warnings report what the observers said. They are not part of this verdict.');
  }
  lines.push('');
  return lines.join('\n');
}
