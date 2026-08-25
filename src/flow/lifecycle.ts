/**
 * The payment lifecycle as the x402 express middleware actually runs it, and the terminal states
 * an evidence record has to be able to say honestly.
 *
 * The ordering below is not a design: it is what the installed middleware does. Verification
 * happens first; the response methods are then intercepted and buffered; the resource handler
 * runs; a throw or an error status cancels the verified payment without settling; otherwise
 * settlement runs and only then is the buffered origin result released to the client.
 *
 * Two consequences shape everything downstream. Settlement happens after the resource has already
 * been produced, so "the work was done but the payment did not settle" is a real state rather than
 * an edge case. And the origin can only observe that it attempted to write a response, never that
 * the client received one, so the successful terminal state is `response_write_attempted` and
 * never anything that claims delivery.
 */

import type { FailureReason } from './failure-vocabulary.ts';

/** Lifecycle positions, in the order the middleware reaches them. */
export const LIFECYCLE_STATES = [
  'request_received',
  'payment_required',
  'payment_payload_received',
  'payment_verified',
  'resource_executed',
  'payment_settled',
  'response_prepared',
  'response_write_attempted',
] as const;
export type LifecycleState = (typeof LIFECYCLE_STATES)[number];

/**
 * Where a run ended.
 *
 * `response_write_attempted` is the only state in which settlement succeeded and the origin then
 * attempted to write the result. Whether the customer received it is not observable from here and
 * is not claimed. The rest are the failure branches; each is a legitimate outcome to record, and
 * none of them is an error in the evidence.
 *
 * ONLY WHAT THIS FLOW CAN OBSERVE. Every state below is reachable and exercised through the
 * express path this example runs. Distinctions the transport erases are not carried here as signed
 * values: a state nothing can produce would be an unfalsifiable field in the record, and a reader
 * has no way to tell one that never occurred from one that cannot occur.
 */
export const TERMINAL_STATES = [
  /** Settlement succeeded and the origin attempted to write the result. */
  'response_write_attempted',
  /**
   * A payment was presented and the resource server refused it before verification.
   *
   * MEASURED: when the presented payment's terms do not match the advertised requirements, the
   * resource server answers with a payment-required response and no verification hook fires at
   * all, so the facilitator is never asked. The name stays generic because the reason for the
   * refusal is not exposed to any hook this flow observes, and inventing one would be a claim the
   * origin cannot support.
   */
  'payment_rejected_pre_verification',
  /** F1: verification rejected. The handler never ran. */
  'verification_rejected',
  /**
   * F2: the handler failed, so the verified payment was canceled without settling.
   *
   * MEASURED: express catches a throw from a route handler and turns it into an error response
   * before the payment middleware sees it, so a throw and a returned error status arrive as the
   * same cancellation reason and are told apart by the status alone. This one state covers both.
   */
  'handler_error_status',
  /** F3: the resource was produced and settlement failed. The result was never written. */
  'settlement_failed',
  /** No payment was presented, so the challenge is the whole run. */
  'payment_required_only',
] as const;
export type TerminalState = (typeof TERMINAL_STATES)[number];

/** Whether a terminal state means the origin result reached the client's side of the wire. */
export function originResultWasWritten(state: TerminalState): boolean {
  return state === 'response_write_attempted' || state === 'handler_error_status';
}

/** Whether a terminal state means settlement succeeded. */
export function paymentWasSettled(state: TerminalState): boolean {
  return state === 'response_write_attempted';
}

/** One observation of the lifecycle, as seen from a named vantage point. */
export interface LifecycleObservation {
  /** Positions reached, in order, without duplicates. */
  readonly states: readonly LifecycleState[];
  readonly terminalState: TerminalState;
  /**
   * Why a verified payment was canceled, from the fixed vocabulary.
   *
   * Never text a remote party or an exception supplied: this value can be carried into a document
   * that gets signed and published, so only declared terms reach it.
   */
  readonly cancellationReason?: FailureReason;
  /** Why verification or settlement refused, from the same fixed vocabulary. */
  readonly failureReason?: FailureReason;
  /** Transaction reference reported by settlement, when settlement succeeded. */
  readonly transaction?: string;
  /** Payer reported by verification or settlement. */
  readonly payer?: string;
  /** HTTP status the origin attempted to write. */
  readonly responseStatus?: number;
}

/**
 * Accumulates lifecycle positions during one request.
 *
 * Deliberately dumb: it records what it is told, in order, and never infers a position that was
 * not reported. An inferred state would be indistinguishable in the evidence from an observed one.
 */
export class LifecycleRecorder {
  private readonly seen: LifecycleState[] = [];
  private terminal: TerminalState = 'payment_required_only';
  private terminalReported = false;
  private detail: {
    cancellationReason?: FailureReason;
    failureReason?: FailureReason;
    transaction?: string;
    payer?: string;
    responseStatus?: number;
  } = {};

  enter(state: LifecycleState): void {
    if (!this.seen.includes(state)) this.seen.push(state);
  }

  finish(state: TerminalState, detail: LifecycleRecorder['detail'] = {}): void {
    this.terminal = state;
    this.terminalReported = true;
    this.detail = { ...this.detail, ...detail };
  }

  /**
   * Whether any observer reported where the run ended.
   *
   * The default terminal state is the challenge-only one, which is the truth for a request that
   * carried no payment. Distinguishing "nothing reported it" from "an observer reported it" is
   * what lets a caller tell that default apart from a run that ended without any observer being
   * given the chance to speak, rather than inferring a position that was never observed.
   */
  hasTerminalState(): boolean {
    return this.terminalReported;
  }

  note(detail: LifecycleRecorder['detail']): void {
    this.detail = { ...this.detail, ...detail };
  }

  observation(): LifecycleObservation {
    const ordered = LIFECYCLE_STATES.filter((s) => this.seen.includes(s));
    return {
      states: ordered,
      terminalState: this.terminal,
      ...(this.detail.cancellationReason ? { cancellationReason: this.detail.cancellationReason } : {}),
      ...(this.detail.failureReason ? { failureReason: this.detail.failureReason } : {}),
      ...(this.detail.transaction ? { transaction: this.detail.transaction } : {}),
      ...(this.detail.payer ? { payer: this.detail.payer } : {}),
      ...(this.detail.responseStatus !== undefined ? { responseStatus: this.detail.responseStatus } : {}),
    };
  }
}
