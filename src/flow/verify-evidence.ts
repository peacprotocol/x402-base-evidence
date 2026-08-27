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
import { coerceDigest, digestBytes, type Sha256Digest } from '../digest.ts';
import { decodeStrictUtf8, parseStrictJson, type StrictJsonRefusal } from '../strict-json.ts';
import { terminalSafe } from '../terminal-safe.ts';
import {
  requireValidX402Artifact,
  X402ValidationError,
  type SchemaValidatedPaymentRequiredArtifact,
  type SchemaValidatedPaymentPayloadArtifact,
} from '../x402-header.ts';
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
import {
  InvalidPublicKeyFileError,
  PUBLIC_KEY_ALGORITHM,
  readIssuerPublicKeyFile,
  SUPPLIED_KEY_CAVEAT,
  type LoadedIssuerPublicKey,
} from './public-key-file.ts';
import {
  deriveExpectedEvidenceProjection,
  type EvidenceProjectionV1,
  type ProjectedField,
} from './evidence-projection.ts';

/**
 * The one x402 scheme this example observes.
 *
 * Stated here so an observation naming another scheme is refused rather than read as though the
 * fields below meant what they mean under `exact`. It is a bound on what this example claims to
 * have looked at, not a judgement about any other scheme.
 */
const OBSERVED_SCHEME = 'exact';

export interface VerificationCheck {
  readonly name: string;
  readonly ok: boolean;
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

/**
 * The distinct questions a directory's checks answer, kept separate on purpose.
 *
 * A signature being valid says nothing about whether the record's claims agree with the bound
 * evidence; an x402 artifact being independently revalidated says nothing about whether the
 * chain-observation cross-checks agree; a supplied key's declared issuer matching the record says
 * nothing about whether that issuer is who it claims to be. Collapsing these into one boolean is
 * exactly the overstatement this split exists to prevent — a success in one authority never
 * implies a success, or even that anything was checked, in another.
 *
 *   artifact_integrity          every bound digest recomputes; the artifact set matches the
 *                                presence contract for the claimed terminal state.
 *   x402_native_validation      the observed x402 artifacts independently re-validate under the
 *                                pinned upstream x402 validators (never invented for an artifact
 *                                x402 defines no runtime validator for).
 *   peac_signature               the record's signature and Wire 0.2 schema are intact.
 *   evidence_projection          the record's claims agree with what this evidence set
 *                                independently derives, per `evidence-projection.ts`.
 *   chain_observation_consistency  the chain-observation document is internally well formed and
 *                                its cross-document fields agree with the record and each other.
 *   trust_policy                  a supplied key's declared algorithm, kid and issuer agree with
 *                                the record. Never an identity claim; see `SUPPLIED_KEY_CAVEAT`.
 */
export type AuthorityName =
  | 'artifact_integrity'
  | 'x402_native_validation'
  | 'peac_signature'
  | 'evidence_projection'
  | 'chain_observation_consistency'
  | 'trust_policy';

export const AUTHORITY_NAMES: readonly AuthorityName[] = [
  'artifact_integrity',
  'x402_native_validation',
  'peac_signature',
  'evidence_projection',
  'chain_observation_consistency',
  'trust_policy',
];

/** One authority's verdict: `valid` only if every check under it ran and passed. */
export type AuthorityVerdict = 'valid' | 'invalid' | 'not_evaluated';

/**
 * Which authority a check belongs to, decided from its name.
 *
 * A name-based classification, not a per-call-site tag, so every check — including the ones
 * report-only early exits construct inline — is classified the same way without threading an
 * authority parameter through every `pass`/`fail` call in this file.
 */
export function classifyAuthority(checkName: string): AuthorityName {
  if (checkName.startsWith('x402 native validation')) return 'x402_native_validation';
  if (checkName.startsWith('evidence projection') || checkName === 'record type') {
    return 'evidence_projection';
  }
  if (checkName.startsWith('supplied key')) return 'trust_policy';
  if (checkName === 'record signature and schema' || checkName === 'extension groups') {
    return 'peac_signature';
  }
  if (
    checkName.includes('digest') ||
    checkName.includes('local profile') ||
    checkName === 'chain observation schema' ||
    checkName === 'every artifact is readable' ||
    checkName === 'nested artifact directories are directories' ||
    checkName === 'record present' ||
    checkName === 'artifact presence contract' ||
    checkName === 'origin result body'
  ) {
    return 'artifact_integrity';
  }
  return 'chain_observation_consistency';
}

/** Roll a check list up into one verdict per authority. */
export function summarizeAuthorities(
  checks: readonly VerificationCheck[],
): Readonly<Record<AuthorityName, AuthorityVerdict>> {
  const summary = {} as Record<AuthorityName, AuthorityVerdict>;
  for (const authority of AUTHORITY_NAMES) summary[authority] = 'not_evaluated';
  for (const check of checks) {
    const authority = classifyAuthority(check.name);
    if (summary[authority] === 'invalid') continue;
    summary[authority] = check.ok ? (summary[authority] === 'not_evaluated' ? 'valid' : summary[authority]) : 'invalid';
  }
  return summary;
}

export interface EvidenceVerificationReport {
  readonly ok: boolean;
  readonly checks: readonly VerificationCheck[];
  /** Never affects `ok`. See `VerificationWarning`. */
  readonly warnings: readonly VerificationWarning[];
  /**
   * One verdict per authority, computed from `checks`. `ok` is never a substitute for reading
   * this: `ok` answers "was every check that ran satisfied", and this answers "which distinct
   * questions were actually asked, and what did each one conclude".
   */
  readonly authorities: Readonly<Record<AuthorityName, AuthorityVerdict>>;
}

/** Build a finished report: `ok`, the checks, the warnings, and the per-authority summary. */
function finishReport(
  ok: boolean,
  checks: readonly VerificationCheck[],
  warnings: readonly VerificationWarning[],
): EvidenceVerificationReport {
  return { ok, checks, warnings, authorities: summarizeAuthorities(checks) };
}

const pass = (name: string, detail = ''): VerificationCheck => ({ name, ok: true, detail });
const fail = (name: string, detail: string): VerificationCheck => ({ name, ok: false, detail });

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
 * A bounded, terminal-safe rendering of a value read out of a document.
 *
 * Report text is the one place attacker-controlled content could reach a reader's terminal: not
 * merely at whatever length it likes, but carrying whatever control characters it likes. Bounding
 * length alone does not stop a CR/LF from forging an extra report line or an ESC byte from opening
 * a terminal escape sequence, so every value that reaches this function is escaped, via
 * `terminalSafe`, before it is ever bounded.
 */
function describeBound(value: unknown): string {
  return terminalSafe(value, 80);
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

  /** Compare one derived projection field against what the record claims, in JSON terms. */
  const jsonEqual = (a: unknown, b: unknown): boolean => {
    if (Array.isArray(a) || Array.isArray(b)) {
      return Array.isArray(a) && Array.isArray(b) && a.length === b.length &&
        a.every((v, i) => jsonEqual(v, (b as readonly unknown[])[i]));
    }
    return a === b;
  };

  /**
   * Record one evidence-projection field.
   *
   * `derived` is the only status whose disagreement fails this check and therefore the whole
   * report: this evidence set independently supplies an expected value, and the record disagreeing
   * with it is exactly what `evidence_projection: inconsistent` means. The other two statuses never
   * fail: `not_derivable_for_this_evidence` and `issuer_assertion` both mean this evidence set has
   * no independent answer, and a check that failed for that reason would be reporting a defect in
   * the evidence rather than in the record.
   */
  const projectionCheck = (name: string, field: ProjectedField<unknown>, actual: unknown): void => {
    const label = `evidence projection: ${name}`;
    if (field.status === 'issuer_assertion') {
      checks.push(pass(label, 'issuer assertion; this evidence set does not independently establish it'));
      return;
    }
    if (field.status === 'not_derivable_for_this_evidence') {
      checks.push(pass(label, `not derivable from this evidence: ${field.reason}`));
      return;
    }
    checks.push(
      jsonEqual(field.expected, actual)
        ? pass(label, describeBound(JSON.stringify(field.expected)))
        : fail(
            label,
            `the evidence establishes ${describeBound(JSON.stringify(field.expected))}, ` +
              `the record carries ${describeBound(JSON.stringify(actual))}`,
          ),
    );
  };

  // The directories the artifact names descend through, before any of those names is read. A
  // symlink standing in for one would leave every path below it looking like it names this
  // evidence directory while the bytes came from somewhere else, so it is refused here rather than
  // producing a set of individually plausible reads.
  for (const container of ARTIFACT_CONTAINERS) {
    const state = checkContainerDirectory(join(directory, container));
    if (state.kind === 'refused') {
      return finishReport(
        false,
        [
          fail(
            'nested artifact directories are directories',
            `${container} was refused (${state.refusal}: ${state.detail})`,
          ),
        ],
        warnings,
      );
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
    return finishReport(
      false,
      [
        fail(
          'every artifact is readable',
          `refused, and absence must not be assumed: ${unreadable.join('; ')}`,
        ),
      ],
      warnings,
    );
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
    return finishReport(false, [fail('record present', 'record.jws is missing')], warnings);
  }
  // Decoded fatally, like every other document here. A record is base64url text, so bytes that are
  // not valid UTF-8 are not a record; replacing what is malformed would hand the verification
  // primitive a string nobody signed.
  const recordText = decodeStrictUtf8(recordBytes);
  if (recordText === undefined) {
    return finishReport(
      false,
      [fail('record signature and schema', 'the record bytes are not valid UTF-8')],
      warnings,
    );
  }
  const jws = recordText.trim();

  // The record is attacker-controlled bytes like everything else here, so a refusal from the
  // verification primitive is a result and a throw from it is still a verification failure.
  let verified: Awaited<ReturnType<typeof verifyLocal>>;
  try {
    verified = await verifyLocal(jws, publicKey);
  } catch {
    return finishReport(
      false,
      [fail('record signature and schema', 'the record could not be read as a PEAC record')],
      warnings,
    );
  }
  if (!verified.valid) {
    return finishReport(false, [fail('record signature and schema', `${verified.code}`)], warnings);
  }
  checks.push(pass('record signature and schema', `verified under kid ${describeBound(verified.kid)}`));

  const claims = verified.claims as unknown as {
    iss?: unknown;
    type?: string;
    kind?: unknown;
    pillars?: unknown;
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
        ? pass('supplied key algorithm', PUBLIC_KEY_ALGORITHM)
        : fail(
            'supplied key algorithm',
            `the key file declares ${describeBound(suppliedKey.algorithm)}, ` +
              `and this example verifies only ${PUBLIC_KEY_ALGORITHM}`,
          ),
    );
    checks.push(
      suppliedKey.kid === verified.kid
        ? pass('supplied key identifier matches the record', describeBound(verified.kid))
        : fail(
            'supplied key identifier matches the record',
            `the key file names ${describeBound(suppliedKey.kid)}, ` +
              `the record names ${describeBound(verified.kid)}`,
          ),
    );
    checks.push(
      suppliedKey.issuer === claims.iss
        ? pass('supplied key issuer matches the record', describeBound(suppliedKey.issuer))
        : fail(
            'supplied key issuer matches the record',
            `the key file names ${describeBound(suppliedKey.issuer)}, ` +
              `the record names ${describeBound(claims.iss)}`,
          ),
    );
  }
  checks.push(
    claims.type === RECORD_TYPE
      ? pass('record type', RECORD_TYPE)
      : fail('record type', `expected ${RECORD_TYPE}, record carries ${describeBound(claims.type)}`),
  );

  const commerce = claims.extensions?.[COMMERCE_GROUP];
  const evidence = claims.extensions?.[PAYMENT_EVIDENCE_GROUP];
  if (commerce === undefined || evidence === undefined) {
    checks.push(fail('extension groups', 'the record is missing a required extension group'));
    return finishReport(false, checks, warnings);
  }
  checks.push(pass('extension groups', `${COMMERCE_GROUP}, ${PAYMENT_EVIDENCE_GROUP}`));

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
          ? pass(name, 'not bound and not present')
          : fail(name, `${artifact} is present but the record binds no digest for it`),
      );
      return;
    }
    if (bytes === undefined) {
      checks.push(fail(name, `the record binds a digest but ${artifact} is missing`));
      return;
    }
    const parsed = readJsonArtifact(artifact);
    if (parsed.kind !== 'parsed') {
      // Reported without canonicalizing anything: a document that was refused never reaches the
      // digest computation below, so no digest is recomputed over a document nobody can pin down.
      checks.push(
        fail(
          name,
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
        ? pass(name, recomputed)
        : fail(name, `recomputed ${recomputed}, record binds ${describeBound(claimed)}`),
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
    checks.push(result.ok ? pass(name, 'matches the example-local schema') : fail(name, result.detail));
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

  /** Recompute an observed field value digest from the bytes recorded beside the record. */
  const recomputeObserved = (name: string, artifact: EvidenceArtifact, claimed: unknown): void => {
    const bytes = present.get(artifact);
    if (claimed === undefined) {
      checks.push(
        bytes === undefined
          ? pass(name, 'not bound and not present')
          : fail(name, `${artifact} is present but the record binds no digest for it`),
      );
      return;
    }
    if (bytes === undefined) {
      checks.push(fail(name, `the record binds a digest but ${artifact} is missing`));
      return;
    }
    const recomputed = digestBytes(bytes);
    checks.push(
      recomputed === claimed
        ? pass(name, recomputed)
        : fail(name, `recomputed ${recomputed}, record binds ${describeBound(claimed)}`),
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

  // x402 native validation: independently re-validate the observed x402 artifacts through the
  // SAME pinned upstream validators this repository calls at issuance and everywhere else it
  // handles x402 artifacts — never a bespoke reimplementation, and never a claim about an
  // artifact x402 v2 defines no runtime validator for. A digest recomputing only proves these are
  // the bytes the record bound; it says nothing about whether those bytes are themselves a
  // well-formed x402 object, which is the distinct question this authority answers.
  const decodedText = (artifact: EvidenceArtifact): string | undefined => {
    const bytes = present.get(artifact);
    return bytes === undefined ? undefined : decodeStrictUtf8(bytes);
  };

  let promotedRequired: SchemaValidatedPaymentRequiredArtifact | undefined;
  const requiredText = decodedText('artifacts/payment-required.txt');
  if (requiredText === undefined) {
    checks.push(pass('x402 native validation: payment-required', 'not present'));
  } else {
    try {
      const validated = await requireValidX402Artifact({
        name: 'payment-required',
        observedValue: requiredText,
        capturePoint: 'origin_response_before_gateway',
        httpVersion: '1.1',
      });
      if (validated.artifactType === 'PaymentRequired') {
        promotedRequired = validated;
        checks.push(
          pass(
            'x402 native validation: payment-required',
            'valid under the pinned upstream x402 v2 validator',
          ),
        );
      } else {
        checks.push(
          fail('x402 native validation: payment-required', 'did not validate as a PaymentRequired object'),
        );
      }
    } catch (e) {
      checks.push(
        fail(
          'x402 native validation: payment-required',
          e instanceof X402ValidationError ? describeBound(e.message) : 'refused by the upstream validator',
        ),
      );
    }
  }

  let promotedPayload: SchemaValidatedPaymentPayloadArtifact | undefined;
  const signatureText = decodedText('artifacts/payment-signature.txt');
  if (signatureText === undefined) {
    checks.push(pass('x402 native validation: payment-signature', 'not present'));
  } else {
    try {
      const validated = await requireValidX402Artifact({
        name: 'payment-signature',
        observedValue: signatureText,
        capturePoint: 'origin_request_after_http_parsing',
        httpVersion: '1.1',
      });
      if (validated.artifactType === 'PaymentPayload') {
        promotedPayload = validated;
        checks.push(
          pass(
            'x402 native validation: payment-signature',
            'valid Exact/EVM scheme shape under the pinned upstream x402 v2 validator',
          ),
        );
      } else {
        checks.push(
          fail('x402 native validation: payment-signature', 'did not validate as a PaymentPayload object'),
        );
      }
    } catch (e) {
      checks.push(
        fail(
          'x402 native validation: payment-signature',
          e instanceof X402ValidationError ? describeBound(e.message) : 'refused by the upstream validator',
        ),
      );
    }
  }

  // Term matching: the presented terms (`accepted`) must be exactly one of the entries the
  // PaymentRequired challenge advertised (`accepts`). Structural equality over both promoted,
  // upstream-validated objects; no chain read is needed to compare two documents this evidence
  // already carries. Cryptographic EIP-3009 signature recovery and the validAfter/validBefore
  // time-window check are NOT re-run here: both require the upstream facilitator's `.verify()`
  // path, which takes chain-read capabilities this offline verifier does not have and cannot
  // honestly stand in for; disclosed as a scope boundary, not an oversight.
  if (promotedRequired !== undefined && promotedPayload !== undefined) {
    const accepts = promotedRequired.decoded.accepts;
    const accepted = promotedPayload.decoded.accepted;
    const matches =
      Array.isArray(accepts) &&
      accepts.some((accept) => JSON.stringify(accept) === JSON.stringify(accepted));
    checks.push(
      matches
        ? pass('x402 native validation: term matching', 'the presented terms match an advertised accept entry')
        : fail(
            'x402 native validation: term matching',
            'the presented terms match no entry the payment-required challenge advertised',
          ),
    );
  }

  // payment-response: x402 v2 core defines no upstream runtime validator for SettleResponse (see
  // SETTLE_RESPONSE_LOCAL_AUTHORITY in x402-header.ts), so no upstream x402 authority is invented
  // for it here. Its digest is still checked above, under artifact_integrity.
  if (decodedText('artifacts/payment-response.txt') !== undefined) {
    checks.push(
      pass(
        'x402 native validation: payment-response',
        'not_evaluated: x402 v2 core defines no upstream runtime validator for SettleResponse',
      ),
    );
  }

  // The result binding names the body by digest, so the body is checked against the binding rather
  // than against the record: that is where the claim about the bytes actually lives.
  const resultBinding = readJsonArtifact('origin-result-binding.json');
  const bodyBytes = present.get('origin-result-body.bin');
  if (resultBinding.kind !== 'absent') {
    if (resultBinding.kind === 'refused') {
      const detail = refusedDetail('origin-result-binding.json', resultBinding.refusal);
      checks.push(fail('origin result body', detail));
    } else if (!isJsonObject(resultBinding.value)) {
      checks.push(fail('origin result body', 'the result binding is not a JSON object'));
    } else if (bodyBytes === undefined) {
      checks.push(fail('origin result body', 'the result binding exists but the body is missing'));
    } else {
      const boundBodyDigest = resultBinding.value['bodyDigest'];
      const recomputed: Sha256Digest = digestBytes(bodyBytes);
      checks.push(
        recomputed === boundBodyDigest
          ? pass('origin result body', recomputed)
          : fail(
              'origin result body',
              `recomputed ${recomputed}, binding names ${describeBound(boundBodyDigest)}`,
            ),
      );
    }
  }

  // The terminal state comes from inside the signed record, so the expected artifact set cannot be
  // chosen after the fact to match whatever files happen to be there.
  const terminalState = evidence['terminal_state'];
  if (!isTerminalState(terminalState)) {
    checks.push(fail('terminal state', 'the record carries no recognised terminal state'));
    return finishReport(false, checks, warnings);
  }
  const violations = checkPresence(terminalState, new Set(present.keys()));
  checks.push(
    violations.length === 0
      ? pass('artifact presence contract', `consistent with ${terminalState}`)
      : fail(
          'artifact presence contract',
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
      fail('chain observation', refusedDetail('chain-observation.json', observationRead.refusal)),
    );
  } else if (observationRead.kind === 'parsed' && !isJsonObject(observationRead.value)) {
    checks.push(fail('chain observation', 'chain-observation.json is not a JSON object'));
  } else if (observationRead.kind === 'parsed') {
    const observationDocument = observationRead.value as Record<string, unknown>;

    // The closed application/profile schema, run BEFORE anything below reads a single field out
    // of this document: additionalProperties:false, closed enums, exact CAIP-2/hash/address
    // grammar, bounded strings and arrays. This is not a PEAC normative schema — see
    // `schemas/base-chain-observation.v1.schema.json` — and satisfying it is not PEAC or x402
    // conformance; it only proves this document has the shape this example itself produces.
    const schemaResult = validateLocalProfile('base-chain-observation', observationDocument);
    checks.push(
      schemaResult.ok
        ? pass('chain observation schema', 'matches the example-local closed schema')
        : fail('chain observation schema', schemaResult.detail),
    );
    if (!schemaResult.ok) return finishReport(false, checks, warnings);

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
        ? pass('chain observation local profile', PROFILE_CHAIN_OBSERVATION)
        : fail(
            'chain observation local profile',
            `expected ${PROFILE_CHAIN_OBSERVATION}, the document names ` +
              `${describeBound(observationDocument['profile'])}`,
          ),
    );
    checks.push(
      observationDocument['scheme'] === OBSERVED_SCHEME
        ? pass('chain observation scheme', OBSERVED_SCHEME)
        : fail(
            'chain observation scheme',
            `this example records the ${OBSERVED_SCHEME} scheme only, the document names ` +
              `${describeBound(observationDocument['scheme'])}`,
          ),
    );
    checks.push(
      expectation !== undefined && report !== undefined
        ? pass(
            'expectation and observation are separately attributed',
            'payment_expectation and chain_observation both present with their sources',
          )
        : fail(
            'expectation and observation are separately attributed',
            'the document does not carry both attributed objects',
          ),
    );
    if (expectation === undefined || report === undefined) {
      return finishReport(false, checks, warnings);
    }

    // The evidence projection: every claim the record makes that this bound evidence set can
    // independently establish, derived the same way the issuer derived it, and compared here
    // against what the record actually carries. A record whose kind, pillars, payment rail,
    // network, asset, amount, environment, settlement event, or lifecycle positions disagree with
    // what the evidence independently implies is never trusted, regardless of its signature.
    const terminalStateForProjection = observationDocument['terminal_state'];
    if (!isTerminalState(terminalStateForProjection)) {
      checks.push(
        fail(
          'evidence projection',
          'the observation names no recognised terminal state, so no projection can be derived',
        ),
      );
    } else {
      const paymentSignatureBytes = present.get('artifacts/payment-signature.txt');
      const paymentSignatureText =
        paymentSignatureBytes === undefined ? undefined : decodeStrictUtf8(paymentSignatureBytes);
      const chainObservationForProjection = {
        profile: observationDocument['profile'],
        scheme: observationDocument['scheme'],
        payment_expectation: expectation,
        chain_observation: report,
        terminal_state: terminalStateForProjection,
      } as unknown as BaseChainObservationV1;

      const projection: EvidenceProjectionV1 = await deriveExpectedEvidenceProjection({
        chainObservation: chainObservationForProjection,
        x402Artifacts: { paymentSignature: paymentSignatureText },
      });

      projectionCheck('kind', projection.kind, claims.kind);
      projectionCheck('pillars', projection.pillars, claims.pillars);
      projectionCheck('payment_rail', projection.paymentRail, commerce['payment_rail']);
      projectionCheck('network', projection.network, evidence['network']);
      projectionCheck('asset', projection.asset, commerce['asset']);
      projectionCheck('amount_minor', projection.amountMinor, commerce['amount_minor']);
      projectionCheck('env', projection.env, commerce['env']);
      projectionCheck('event', projection.event, commerce['event']);
      projectionCheck('lifecycle_states', projection.lifecycleStates, evidence['lifecycle_states']);
      projectionCheck('reference', projection.reference, commerce['reference']);
      // currency, occurred_at, and jti are issuer assertions: no piece of this evidence set
      // establishes any of the three, so they are reported as exactly that and never compared.
      // The third argument is never read for an `issuer_assertion` field; `undefined` stands in
      // for "no independent value to compare against" honestly, rather than naming a record field
      // this check does not use.
      projectionCheck('currency', projection.currency, commerce['currency']);
      projectionCheck('occurred_at', projection.occurredAt, undefined);
      projectionCheck('jti', projection.jti, undefined);
    }

    const settled = report['settlement_outcome'] === 'succeeded';
    const hasTransaction = typeof report['transaction_hash'] === 'string';
    checks.push(
      settled === hasTransaction
        ? pass(
            'settlement facts match the outcome',
            settled ? 'settled, transaction recorded' : 'not settled, no transaction recorded',
          )
        : fail(
            'settlement facts match the outcome',
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
          ? pass('rpc observation transaction', 'it describes the transaction the settlement recorded')
          : fail(
              'rpc observation transaction',
              'it describes a transaction the settlement observation does not record',
            ),
      );
      const claimsInclusion = rpc['observation_level'] === 'l2_block_inclusion';
      checks.push(
        !claimsInclusion ||
          (typeof rpc['block_number'] === 'string' && typeof rpc['block_hash'] === 'string')
          ? pass(
              'rpc inclusion claim carries its basis',
              claimsInclusion
                ? 'l2_block_inclusion with sealed block placement recorded'
                : 'no inclusion level is claimed',
            )
          : fail(
              'rpc inclusion claim carries its basis',
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
      checks.push(fail('expectation comparison', 'the document records no comparison object'));
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
              Object.entries(recomputed)
                .map(([field, verdict]) => `${field}=${verdict}`)
                .join(' '),
            )
          : fail(
              'expectation comparison',
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
            ? pass('transfer event verdict evaluated', recomputed.transfer_event)
            : fail(
                'transfer event verdict evaluated',
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
        checks.push(fail(name, 'the value is absent on one side, so there is nothing to compare'));
        return;
      }
      checks.push(
        recorded === observed
          ? pass(name, describeBound(recorded))
          : fail(
              name,
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
        checks.push(pass(name, absentDetail));
        return;
      }
      if (typeof recorded !== 'string' || typeof observed !== 'string') {
        checks.push(fail(name, 'it is recorded in one of the two documents and not in the other'));
        return;
      }
      checks.push(
        recorded === observed
          ? pass(name, describeBound(recorded))
          : fail(
              name,
              `one document names ${describeBound(recorded)}, ` +
                `the other names ${describeBound(observed)}`,
            ),
      );
    };

    // Network, asset, and amount agreement between the record and the observation are covered by
    // the evidence projection above (`evidence projection: network` / `asset` / `amount_minor`),
    // which compares the record against the same expectation this check would have; a second,
    // separately named comparison of the identical fact would be a second path to the same
    // conclusion, not a second fact.
    agreeOnValue(
      'record and observation name the same terminal state',
      terminalState,
      observationDocument['terminal_state'],
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
  }

  return finishReport(checks.every((c) => c.ok), checks, warnings);
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
  const lines = ['', `Evidence verification: ${directory}`, ''];
  for (const check of report.checks) {
    lines.push(`  ${check.ok ? 'ok  ' : 'FAIL'}  ${check.name}${check.detail ? `: ${check.detail}` : ''}`);
  }
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
