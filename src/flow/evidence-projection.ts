/**
 * One evidence projection, derived the same way by the issuer and by the verifier.
 *
 * A signed record makes many claims. Some of them this repository's own bound evidence — the
 * chain observation and the x402 artifacts it was built from — can independently establish, so a
 * verifier has no reason to trust the record for them at all: it can compute what the evidence
 * implies and compare. Others have no source in this evidence set but the issuer's own word, and a
 * verifier that quietly treated those the same way as the derived ones would be overstating what
 * it checked.
 *
 * This module draws that line once, in one place, so the issuer and the verifier can never drift
 * apart on where it falls. It takes ONLY the bound evidence — never the signed record — and
 * returns, for every claim the record makes about the interaction, either the value the evidence
 * independently implies, or an explicit statement that this evidence set has no authority over it.
 * Comparing that projection against a decoded record is the verifier's job, done in
 * `verify-evidence.ts`, because that comparison is the one place the record is allowed to enter the
 * picture — this function never sees it and never could.
 *
 * WHY THE ISSUER CALLS THIS TOO. Before signing, the issuer already holds exactly the evidence a
 * verifier will later reconstruct from the sidecar files: the chain observation, and the same raw
 * x402 field values. Deriving the record's claims from that evidence with the same function the
 * verifier will later run is what makes "the record matches what the evidence says" true by
 * construction rather than by two independently written pieces of logic staying in sync by luck.
 */
import { extractPaymentIdentifier } from '@x402/extensions/payment-identifier';
import type { PaymentPayload } from '@x402/core/types';
import { requireValidX402Artifact, X402ValidationError } from '../x402-header.ts';
import type { BaseChainObservationV1 } from './observe-settlement.ts';
import type { LifecycleState, TerminalState } from './lifecycle.ts';

/** The registered PEAC record type and structural fields this profile always issues under. */
export const PINNED_KIND = 'evidence' as const;
export const PINNED_TYPE = 'org.peacprotocol/payment' as const;
export const PINNED_PILLARS = ['commerce'] as const;
export const PINNED_PAYMENT_RAIL = 'x402' as const;

/**
 * Where one projected claim's value came from.
 *
 * `derived` is the only status a mismatch against the record may be reported as `inconsistent`
 * for: the evidence itself supplies an independent answer. `not_derivable_for_this_evidence` means
 * the evidence set on hand is missing what this specific claim would need (an optional artifact
 * was never captured, or does not carry the extension this claim depends on) — a fact about this
 * run, not a permanent property of the claim. `issuer_assertion` means no piece of this evidence
 * set, on any run, can establish the claim at all; it names only what the record says.
 */
export type ProjectedFieldStatus = 'derived' | 'not_derivable_for_this_evidence' | 'issuer_assertion';

export type ProjectedField<T> =
  | { readonly status: 'derived'; readonly expected: T }
  | { readonly status: 'not_derivable_for_this_evidence'; readonly reason: string }
  | { readonly status: 'issuer_assertion' };

/** Read the expected value of a `derived` field, or `undefined` for any other status. */
export function derivedValue<T>(field: ProjectedField<T>): T | undefined {
  return field.status === 'derived' ? field.expected : undefined;
}

/**
 * Every claim the record makes about the interaction, each classified by where its authority
 * actually comes from. Nothing here is optional to classify: a claim this module does not know
 * about is a claim the verifier has not yet decided how to treat, which is exactly the gap this
 * module exists to close.
 */
export interface EvidenceProjectionV1 {
  /** Registered PEAC structural fields this profile always issues under. Pinned, not computed. */
  readonly kind: ProjectedField<typeof PINNED_KIND>;
  readonly type: ProjectedField<typeof PINNED_TYPE>;
  readonly pillars: ProjectedField<typeof PINNED_PILLARS>;
  readonly paymentRail: ProjectedField<typeof PINNED_PAYMENT_RAIL>;
  /** From the chain observation's payment expectation, read off the native x402 artifact. */
  readonly network: ProjectedField<string>;
  readonly asset: ProjectedField<string>;
  readonly amountMinor: ProjectedField<string>;
  /**
   * Whether the observed CAIP-2 network is a known Base test or live network. Only the two Base
   * networks this repository's preflight check recognises are classified; any other network
   * leaves this claim without a source to derive it from, though the network claim itself is
   * still independently derived and compared above regardless.
   */
  readonly env: ProjectedField<'live' | 'test'>;
  /**
   * Whether the commerce group may record `event: 'settlement'`. Derived from the chain
   * observation's own settlement outcome: an expected value of `undefined` means the field must
   * be ABSENT, not merely unchecked, because recording it beside an outcome that never settled
   * would overstate what happened.
   */
  readonly event: ProjectedField<'settlement' | undefined>;
  /**
   * The lifecycle positions the observed terminal state implies, per the exact `enter`/`finish`
   * call sites the resource-server middleware runs (`server.ts`). A terminal state fixes this
   * sequence: nothing about which positions were reached is left for the issuer to additionally
   * assert once the terminal state is known.
   */
  readonly lifecycleStates: ProjectedField<readonly LifecycleState[]>;
  /**
   * The payment-identifier extension's `id`, when the observed x402 payment artifact carries the
   * payment-identifier extension. Absent that extension, or absent the artifact, this evidence set
   * has nothing to derive a reference from, and no reference is asserted in its place.
   */
  readonly reference: ProjectedField<string>;
  /**
   * No field of the x402 v2 `PaymentRequirements`/`PaymentPayload` shape is a currency ticker: an
   * asset is named by contract address, and the one adjacent string, `extra.name`, is the EIP-712
   * signing-domain name, which is not defined to equal the token's ticker (only coincides with it
   * for this profile's own USDC asset). This evidence set has no field to derive a currency from,
   * on any run, so currency is always an issuer assertion, and is never reported as independently
   * established.
   */
  readonly currency: ProjectedField<never>;
  /** No observed artifact records when the interaction occurred; the issuer's clock is the only source. */
  readonly occurredAt: ProjectedField<never>;
  /** No observed artifact names a record identifier; only the issuer assigns one. */
  readonly jti: ProjectedField<never>;
}

const derived = <T>(expected: T): ProjectedField<T> => ({ status: 'derived', expected });
const notDerivable = (reason: string): ProjectedField<never> => ({
  status: 'not_derivable_for_this_evidence',
  reason,
});
const issuerAssertion: ProjectedField<never> = { status: 'issuer_assertion' };

/** Base networks this profile's preflight check recognises, and the environment each one is. */
const KNOWN_NETWORK_ENVIRONMENTS: Readonly<Record<string, 'live' | 'test'>> = {
  'eip155:84532': 'test', // Base Sepolia
  'eip155:8453': 'live', // Base mainnet
};

/**
 * The lifecycle positions each terminal state implies, in the order the middleware in `server.ts`
 * actually reaches them (`recorder.enter(...)` / `recorder.finish(...)`, read there directly, not
 * inferred from this document's own prose elsewhere).
 *
 * `payment_rejected_pre_verification` and `verification_rejected` share one sequence: both end
 * before `payment_verified` is ever entered, and what tells them apart is the terminal state
 * itself, not which lifecycle positions were reached — this table does not have to duplicate that
 * distinction to be complete. Likewise `handler_error_status` and `settlement_failed` both end
 * after `resource_executed` and before `payment_settled`, because both cancel a verified payment
 * before settlement runs.
 */
const IMPLIED_LIFECYCLE_STATES: Readonly<Record<TerminalState, readonly LifecycleState[]>> = {
  payment_required_only: ['request_received', 'payment_required'],
  payment_rejected_pre_verification: ['request_received', 'payment_payload_received'],
  verification_rejected: ['request_received', 'payment_payload_received'],
  handler_error_status: [
    'request_received',
    'payment_payload_received',
    'payment_verified',
    'resource_executed',
  ],
  settlement_failed: [
    'request_received',
    'payment_payload_received',
    'payment_verified',
    'resource_executed',
  ],
  // `payment_required` is entered ONLY on the branch where no payment header was presented at all
  // (`server.ts`: `if (context.paymentHeader === undefined) recorder.enter('payment_required'); else
  // recorder.enter('payment_payload_received')`) — the two are mutually exclusive, and a run that
  // reaches `response_write_attempted` necessarily took the `payment_payload_received` branch.
  response_write_attempted: [
    'request_received',
    'payment_payload_received',
    'payment_verified',
    'resource_executed',
    'payment_settled',
    'response_prepared',
    'response_write_attempted',
  ],
};

/** The bound evidence a projection is derived from. Never the signed record. */
export interface BoundEvidenceForProjection {
  readonly chainObservation: BaseChainObservationV1;
  /**
   * Raw x402 field values exactly as bound beside the record, when each was observed. Only
   * `paymentSignature` is read today (for the payment-identifier extension); the other two are
   * accepted so a caller does not have to reshape its evidence set to this function's needs, and
   * so a future claim that does need them has somewhere to read them from.
   */
  readonly x402Artifacts: {
    readonly paymentRequired?: string;
    readonly paymentSignature?: string;
    readonly paymentResponse?: string;
  };
}

/**
 * The payment-identifier extension's `id`, re-validated from the observed payment-signature field
 * value through the same production x402 validator this repository uses everywhere else, never a
 * bespoke parse. `capturePoint` is nominal here: this call re-derives a structural fact from
 * already-bound bytes, and asserts nothing about how or where those bytes were first observed.
 */
async function derivedReference(paymentSignature: string | undefined): Promise<ProjectedField<string>> {
  if (paymentSignature === undefined) {
    return notDerivable('no payment-signature artifact is bound to this evidence');
  }
  let payload: PaymentPayload;
  try {
    const validated = await requireValidX402Artifact({
      name: 'payment-signature',
      observedValue: paymentSignature,
      capturePoint: 'origin_request_after_http_parsing',
      httpVersion: '2.0',
    });
    if (validated.artifactType !== 'PaymentPayload') {
      return notDerivable('the bound payment-signature artifact did not validate as a PaymentPayload');
    }
    payload = validated.decoded;
  } catch (e) {
    if (e instanceof X402ValidationError) {
      return notDerivable('the bound payment-signature artifact does not validate as a PaymentPayload');
    }
    throw e;
  }
  const id = extractPaymentIdentifier(payload);
  if (id === null) {
    return notDerivable('the bound payment artifact carries no payment-identifier extension');
  }
  return derived(id);
}

/**
 * Derive the evidence projection: every claim the record makes about the interaction, each
 * classified by whether THIS bound evidence set can independently establish it.
 *
 * Pure with respect to the record: nothing this function returns depends on, or was computed from,
 * a signed record. That is what lets the issuer call it before signing and the verifier call it
 * after reading the sidecar files back, over the same evidence, and get the same answer.
 */
export async function deriveExpectedEvidenceProjection(
  bound: BoundEvidenceForProjection,
): Promise<EvidenceProjectionV1> {
  const { chainObservation } = bound;
  const { payment_expectation: expectation, chain_observation: report } = chainObservation;
  const env = KNOWN_NETWORK_ENVIRONMENTS[expectation.network];

  return {
    kind: derived(PINNED_KIND),
    type: derived(PINNED_TYPE),
    pillars: derived(PINNED_PILLARS),
    paymentRail: derived(PINNED_PAYMENT_RAIL),
    network: derived(expectation.network),
    asset: derived(expectation.asset),
    amountMinor: derived(expectation.amount_base_units),
    env:
      env !== undefined
        ? derived(env)
        : notDerivable(`${expectation.network} is not a recognised Base test or live network`),
    event: derived(report.settlement_outcome === 'succeeded' ? 'settlement' : undefined),
    lifecycleStates: derived(IMPLIED_LIFECYCLE_STATES[chainObservation.terminal_state]),
    reference: await derivedReference(bound.x402Artifacts.paymentSignature),
    currency: issuerAssertion,
    occurredAt: issuerAssertion,
    jti: issuerAssertion,
  };
}
