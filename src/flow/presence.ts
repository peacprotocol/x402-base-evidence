/**
 * Which artifacts each terminal state should have produced.
 *
 * Without this, an evidence directory is ambiguous in the one way that matters: a verifier cannot
 * tell "this run never produced that artifact" from "someone removed it". Stating the expected set
 * per terminal state makes both detectable, because the terminal state is itself carried inside
 * the signed record, so it cannot be edited to excuse a missing file without breaking the
 * signature.
 *
 * Three expectations, not two. `absent` is as load-bearing as `required`: a settlement artifact
 * present in a run that recorded no settlement is inconsistent evidence, and saying so is the
 * point. `optional` exists only where the middleware's own behaviour is genuinely conditional, and
 * each use is justified where it appears.
 */
import type { TerminalState } from './lifecycle.ts';

export const EVIDENCE_ARTIFACTS = [
  'record.jws',
  'request-binding.json',
  'origin-result-binding.json',
  'origin-result-body.bin',
  'artifacts/payment-required.txt',
  'artifacts/payment-signature.txt',
  'artifacts/payment-response.txt',
  'chain-observation.json',
] as const;
export type EvidenceArtifact = (typeof EVIDENCE_ARTIFACTS)[number];

export type Expectation = 'required' | 'optional' | 'absent';

export type PresenceContract = Readonly<Record<EvidenceArtifact, Expectation>>;

/** Artifacts every run produces, whatever happened: the record and what was requested. */
const ALWAYS: Pick<
  PresenceContract,
  'record.jws' | 'request-binding.json' | 'chain-observation.json' | 'artifacts/payment-required.txt'
> = {
  'record.jws': 'required',
  'request-binding.json': 'required',
  'chain-observation.json': 'required',
  'artifacts/payment-required.txt': 'required',
};

const CONTRACTS: Readonly<Record<TerminalState, PresenceContract>> = {
  /** Paid, produced, written. Everything exists. */
  response_write_attempted: {
    ...ALWAYS,
    'artifacts/payment-signature.txt': 'required',
    'artifacts/payment-response.txt': 'required',
    'origin-result-binding.json': 'required',
    'origin-result-body.bin': 'required',
  },

  /**
   * A payment was presented and the resource server refused it before verification, so nothing
   * downstream of the requirements match ever ran.
   *
   * The presented payment field value is required: it is the artifact that makes the refusal
   * legible, and a run that recorded a refusal without it would be describing something nobody can
   * inspect. Nothing from verification onwards can exist.
   */
  payment_rejected_pre_verification: {
    ...ALWAYS,
    'artifacts/payment-signature.txt': 'required',
    'artifacts/payment-response.txt': 'absent',
    'origin-result-binding.json': 'absent',
    'origin-result-body.bin': 'absent',
  },

  /** F1. A payment was presented and refused, so the handler never ran. */
  verification_rejected: {
    ...ALWAYS,
    'artifacts/payment-signature.txt': 'required',
    'artifacts/payment-response.txt': 'absent',
    'origin-result-binding.json': 'absent',
    'origin-result-body.bin': 'absent',
  },

  /**
   * F2. The handler produced an error result, which is written to the client, so it is bound. The
   * payment was still canceled before settlement.
   */
  handler_error_status: {
    ...ALWAYS,
    'artifacts/payment-signature.txt': 'required',
    'artifacts/payment-response.txt': 'absent',
    'origin-result-binding.json': 'required',
    'origin-result-body.bin': 'required',
  },

  /**
   * F3. The resource was produced and settlement refused, so the middleware discarded the buffered
   * result and wrote an error response instead. The result binding is required precisely because
   * the work happened; the chain observation records that the result was never written.
   *
   * The settlement field value is optional because the middleware emits the failure response's
   * headers, and whether a settlement field appears among them depends on the failure. Recording
   * it when present is useful; requiring it would fail honest runs.
   */
  settlement_failed: {
    ...ALWAYS,
    'artifacts/payment-signature.txt': 'required',
    'artifacts/payment-response.txt': 'optional',
    'origin-result-binding.json': 'required',
    'origin-result-body.bin': 'required',
  },

  /** No payment was ever presented, so the challenge is the whole run. */
  payment_required_only: {
    ...ALWAYS,
    'artifacts/payment-signature.txt': 'absent',
    'artifacts/payment-response.txt': 'absent',
    'origin-result-binding.json': 'absent',
    'origin-result-body.bin': 'absent',
  },
};

export function presenceContractFor(state: TerminalState): PresenceContract {
  return CONTRACTS[state];
}

export interface PresenceViolation {
  readonly artifact: EvidenceArtifact;
  readonly expectation: Expectation;
  readonly present: boolean;
}

/**
 * Compare an observed artifact set against the contract for a terminal state.
 *
 * Both directions are violations. A missing required artifact is incomplete evidence; a present
 * artifact the state says cannot exist is inconsistent evidence, and the second is the more
 * interesting failure.
 */
export function checkPresence(
  state: TerminalState,
  present: ReadonlySet<string>,
): PresenceViolation[] {
  const contract = presenceContractFor(state);
  const violations: PresenceViolation[] = [];
  for (const artifact of EVIDENCE_ARTIFACTS) {
    const expectation = contract[artifact];
    const isPresent = present.has(artifact);
    if (expectation === 'required' && !isPresent) {
      violations.push({ artifact, expectation, present: false });
    }
    if (expectation === 'absent' && isPresent) {
      violations.push({ artifact, expectation, present: true });
    }
  }
  return violations;
}
