/**
 * The facilitator used by the offline path.
 *
 * It is the upstream `x402Facilitator` driven by a scheme facilitator registered here, adapted to
 * the upstream `FacilitatorClient` interface and handed to the resource server through the
 * constructor. That is the supported injection point, so the offline run exercises the real
 * resource server, the real express middleware and the real settlement sequencing; only the thing
 * that would otherwise talk to a network is local.
 *
 * WHAT THIS IS NOT. It settles nothing. It performs no signature recovery, no chain read and no
 * simulation, and the transaction reference it returns is fixed placeholder text. The installed
 * upstream EVM facilitator performs those checks against real chain state and is exercised
 * separately, through its exported class, in the security matrix; rebuilding its checks here would
 * turn a stand-in into a second validity oracle, which is exactly what this file must not be. It
 * stands in for a facilitator so the lifecycle can be exercised without a network; it is never
 * evidence that a payment occurred, and no output derived from it may be presented as a settled
 * payment.
 */
import { x402Facilitator } from '@x402/core/facilitator';
import type { FacilitatorClient } from '@x402/core/server';
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  SupportedResponse,
  VerifyResponse,
} from '@x402/core/types';
import * as F from '../../fixtures/deterministic.ts';

/** How the fixture facilitator should behave, so failure branches can be exercised on purpose. */
export interface FixtureFacilitatorBehavior {
  /** Refuse verification, as a facilitator would for an unacceptable payment. */
  readonly rejectVerification?: string;
  /** Accept verification and refuse settlement, which is the branch that produces state F4. */
  readonly rejectSettlement?: string;
  /**
   * Raise from verification with this message, as a facilitator that failed rather than refused.
   *
   * A refusal is an answer; an exception is not, and the two reach different hooks. The message is
   * supplied by the caller so a case can prove that whatever it contains is not persisted.
   */
  readonly throwOnVerify?: string;
  /** Raise from settlement with this message, for the same reason. */
  readonly throwOnSettle?: string;
}

/**
 * How often the resource server actually asked this facilitator.
 *
 * Counted because "the payment was refused" and "the payment was refused before anyone was asked to
 * verify it" are different facts, and only the second shows that the refusal came from the
 * requirements matching the resource server performs before verification.
 */
export interface FixtureFacilitatorCalls {
  verify: number;
  settle: number;
}

/** Reason a settlement was refused because the same authorization had already been settled. */
export const DUPLICATE_SETTLEMENT_REASON = 'duplicate_settlement';

/**
 * Checks a payment against the requirements the server advertised.
 *
 * These are the terms comparisons an integration must not get wrong: the network, scheme, asset,
 * amount and recipient a payment claims have to be the ones that were advertised. Everything a
 * real facilitator does beyond that, above all deciding whether the authorization is authentically
 * signed and spendable, is absent here by design and is not simulated.
 */
function checkTerms(
  payload: PaymentPayload,
  requirements: PaymentRequirements,
): string | undefined {
  const accepted = payload.accepted;
  if (accepted.network !== requirements.network) return 'network_mismatch';
  if (accepted.scheme !== requirements.scheme) return 'scheme_mismatch';
  if (accepted.asset !== requirements.asset) return 'asset_mismatch';
  if (accepted.amount !== requirements.amount) return 'amount_mismatch';
  if (accepted.payTo !== requirements.payTo) return 'recipient_mismatch';
  const authorization = payload.payload['authorization'];
  const signature = payload.payload['signature'];
  if (
    typeof authorization !== 'object' ||
    authorization === null ||
    typeof signature !== 'string' ||
    signature.length === 0
  ) {
    return 'missing_authorization';
  }
  return undefined;
}

/**
 * The pair one EIP-3009 authorization is identified by: the authorizer together with its 32-byte
 * nonce. EIP-3009 keys authorization state as `authorizationState(address authorizer, bytes32
 * nonce)`, so the same nonce under a different authorizer names a different authorization, and a
 * nonce alone identifies nothing. Both halves are hex values and are lower-cased before keying,
 * so case variants of one authorization cannot read as distinct authorizations.
 */
function authorizationIdentity(payload: PaymentPayload): string | undefined {
  const authorization = payload.payload['authorization'];
  if (typeof authorization !== 'object' || authorization === null) return undefined;
  const record = authorization as Record<string, unknown>;
  const from = record['from'];
  const nonce = record['nonce'];
  if (typeof from !== 'string' || typeof nonce !== 'string') return undefined;
  return `${from.toLowerCase()}:${nonce.toLowerCase()}`;
}

/**
 * A scheme facilitator for the exact scheme on EVM networks that produces fixed results.
 *
 * The class shape, including the CAIP family, is the upstream interface; only the bodies are
 * local.
 */
class FixtureExactEvmFacilitator implements SchemeNetworkFacilitator {
  readonly scheme = 'exact';
  readonly caipFamily = 'eip155:*';

  /**
   * Authorizer-and-nonce pairs, keyed by where each one stands: absent (available), `'pending'`
   * (a settlement attempt is in flight for it), or `'consumed'` (a settlement of it has already
   * succeeded).
   *
   * On the network, EIP-3009 keys consumption by the pair `authorizationState(address authorizer,
   * bytes32 nonce)` — never by the nonce alone, since two authorizers may independently use the
   * same nonce value — and only a transfer that actually executes consumes it. This map models
   * that: an authorization is reserved as `'pending'` before any failure path in `settle` below
   * can run, so a duplicate attempt arriving while the first is still in flight is refused rather
   * than racing it, and the reservation is released back to available on every path except a
   * settlement that actually succeeds. A refusal, a thrown error, or a term mismatch must leave an
   * authorization exactly as spendable as it was before the attempt; only a successful settlement
   * may move it to `'consumed'`, which is permanent for this instance. It belongs to one
   * facilitator instance, applies within a run, and never carries state between runs. It is a
   * stand-in and is recorded as one: it does not claim to prove the network's replay mechanism,
   * and no output derived from it names the mechanism a real facilitator or the network enforces.
   */
  private readonly settledAuthorizations = new Map<string, 'pending' | 'consumed'>();

  private readonly behavior: FixtureFacilitatorBehavior;
  private readonly calls: FixtureFacilitatorCalls;

  constructor(behavior: FixtureFacilitatorBehavior, calls: FixtureFacilitatorCalls) {
    this.behavior = behavior;
    this.calls = calls;
  }

  getExtra(): Record<string, unknown> | undefined {
    return undefined;
  }

  getSigners(): string[] {
    return [];
  }

  async verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    this.calls.verify++;
    if (this.behavior.throwOnVerify !== undefined) throw new Error(this.behavior.throwOnVerify);
    if (this.behavior.rejectVerification !== undefined) {
      return { isValid: false, invalidReason: this.behavior.rejectVerification };
    }
    const problem = checkTerms(payload, requirements);
    if (problem !== undefined) return { isValid: false, invalidReason: problem };
    return { isValid: true, payer: F.PAYER };
  }

  /**
   * Settle one payment.
   *
   * Only a settlement that actually succeeds may consume the authorization it settled. Every
   * other path — a duplicate arriving while the first is still in flight, an injected throw, an
   * injected refusal, or an ordinary term mismatch — must leave the authorization exactly as
   * available as it was before this call, so a caller can safely retry it. The reservation is
   * taken before any of those paths can run and before this method's first `await` (there is none
   * today, but the reservation is written so that adding one later still cannot let two attempts
   * for the same identity both observe "available").
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    this.calls.settle++;
    const identity = authorizationIdentity(payload);

    if (identity !== undefined) {
      const state = this.settledAuthorizations.get(identity);
      if (state !== undefined) {
        // Already consumed by an earlier success, or currently reserved by an attempt still in
        // flight for the same identity: either way, this attempt must not proceed and must not
        // disturb what the other one recorded.
        return {
          success: false,
          errorReason: DUPLICATE_SETTLEMENT_REASON,
          transaction: '',
          network: requirements.network,
          payer: F.PAYER,
        };
      }
      this.settledAuthorizations.set(identity, 'pending');
    }
    // Releases the reservation back to available. Called on every path below except the one that
    // ends in success, which instead moves the identity to `'consumed'`.
    const release = (): void => {
      if (identity !== undefined) this.settledAuthorizations.delete(identity);
    };

    if (this.behavior.throwOnSettle !== undefined) {
      release();
      throw new Error(this.behavior.throwOnSettle);
    }
    if (this.behavior.rejectSettlement !== undefined) {
      release();
      return {
        success: false,
        errorReason: this.behavior.rejectSettlement,
        transaction: '',
        network: requirements.network,
        payer: F.PAYER,
      };
    }
    const problem = checkTerms(payload, requirements);
    if (problem !== undefined) {
      release();
      return {
        success: false,
        errorReason: problem,
        transaction: '',
        network: requirements.network,
        payer: F.PAYER,
      };
    }

    if (identity !== undefined) this.settledAuthorizations.set(identity, 'consumed');
    return {
      success: true,
      transaction: F.SETTLEMENT_TX_HASH,
      network: requirements.network,
      payer: F.PAYER,
    };
  }
}

/** An in-process facilitator client together with a record of what it was asked to do. */
export interface FixtureFacilitator {
  readonly client: FacilitatorClient;
  readonly calls: FixtureFacilitatorCalls;
}

/**
 * Build the in-process facilitator.
 *
 * `getSupported` is what the resource server calls during initialization to learn which
 * scheme and network combinations exist. Answering it locally is the whole reason the offline run
 * needs no socket.
 */
export function createFixtureFacilitator(
  network: Network,
  behavior: FixtureFacilitatorBehavior = {},
): FixtureFacilitator {
  const calls: FixtureFacilitatorCalls = { verify: 0, settle: 0 };
  const facilitator = new x402Facilitator().register(
    network,
    new FixtureExactEvmFacilitator(behavior, calls),
  );
  return {
    client: {
      verify: (payload, requirements) => facilitator.verify(payload, requirements),
      settle: (payload, requirements) => facilitator.settle(payload, requirements),
      getSupported: async (): Promise<SupportedResponse> =>
        facilitator.getSupported() as SupportedResponse,
    },
    calls,
  };
}

/** The client alone, for callers that do not need to observe what the facilitator was asked. */
export function createFixtureFacilitatorClient(
  network: Network,
  behavior: FixtureFacilitatorBehavior = {},
): FacilitatorClient {
  return createFixtureFacilitator(network, behavior).client;
}
