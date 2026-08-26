/**
 * The fixed vocabulary of reasons this flow is willing to persist.
 *
 * WHY A VOCABULARY AT ALL. A failure reason travels further than it looks. It is recorded on the
 * lifecycle, it can be carried into the chain observation, and the chain observation is covered by
 * a digest inside a signed record. Anything that reaches it is therefore signed, published, and
 * permanent. The values available at those points come from a remote facilitator or from an
 * exception message, and neither is bounded, structured, or under this example's control: a
 * response body, a stack trace, an endpoint URL with a token in it, or several kilobytes of
 * whatever a server felt like returning would all arrive by the same path.
 *
 * So nothing is copied. Every reason persisted anywhere is one of the terms declared here.
 *
 * TWO KINDS OF TERM. The generic terms are decisions this flow makes about what it observed:
 * verification refused, verification raised, settlement refused, settlement raised, handler failed.
 * The upstream terms are machine codes this integration deliberately supports, and one of those
 * survives verbatim only if it is both shaped like a machine code and named in the allowlist. A
 * string that satisfies only the shape is still not adopted: a well-formed code nobody declared is
 * exactly how an unbounded value would slip in wearing a disguise.
 *
 * WHAT THIS IS NOT. It is not a redaction of the observed x402 field values. Those are captured
 * wire artifacts, bound by digest, and they carry whatever the facilitator actually sent, because
 * that is the thing the evidence exists to record. This is about the reasons this flow derives and
 * writes down in its own words.
 */

/** Terms this flow decides for itself, from what it observed. */
const DERIVED_REASONS = [
  /** The facilitator answered, and refused the payment as invalid. */
  'verification_rejected',
  /** The verification step raised rather than answering. */
  'verification_exception',
  /** Settlement answered, and reported that it did not succeed. */
  'settlement_rejected',
  /** The settlement step raised rather than answering. */
  'settlement_exception',
  /** The resource handler failed, so the verified payment was canceled without settling. */
  'handler_failed',
] as const;

/**
 * Machine codes from upstream that this integration deliberately supports.
 *
 * Each is a code this flow either produces itself or has seen the upstream declare. The list is
 * short on purpose: it is an allowlist, and a code that is not on it is not adopted merely because
 * it looks like one.
 */
export const SUPPORTED_UPSTREAM_REASONS = [
  'duplicate_settlement',
  'network_mismatch',
  'scheme_mismatch',
  'asset_mismatch',
  'amount_mismatch',
  'recipient_mismatch',
  'missing_authorization',
  'handler_failed',
] as const;

/** Every reason that may be persisted, from either source. */
export const FAILURE_REASONS = [...DERIVED_REASONS, ...SUPPORTED_UPSTREAM_REASONS] as const;

export type FailureReason = (typeof FAILURE_REASONS)[number];

/**
 * The shape a supported upstream code has to have.
 *
 * Lowercase snake case, at most 40 characters. Membership in the allowlist decides adoption; this
 * decides nothing on its own and exists so a malformed entry could never be added to the allowlist
 * unnoticed.
 */
export const UPSTREAM_REASON_PATTERN = /^[a-z][a-z0-9_]{0,39}$/;

const SUPPORTED = new Set<string>(SUPPORTED_UPSTREAM_REASONS);

/**
 * Decide what to persist for one failure.
 *
 * @param upstream - Whatever the remote party or the middleware supplied. Any type: it arrives from
 *   an interface that declares it as an optional free string, so it may be absent or not a string.
 * @param derived - The term to record when the upstream value is not one this flow supports. This
 *   is the normal outcome, not the exceptional one.
 * @returns A term from the fixed vocabulary, always.
 */
export function persistableFailureReason(upstream: unknown, derived: FailureReason): FailureReason {
  if (typeof upstream !== 'string') return derived;
  if (!UPSTREAM_REASON_PATTERN.test(upstream)) return derived;
  return SUPPORTED.has(upstream) ? (upstream as FailureReason) : derived;
}
