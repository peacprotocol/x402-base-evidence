/**
 * The network-specific observation seam.
 *
 * One function turns the artifacts a settlement produced into a chain observation document.
 * Everything upstream of it is the generic evidence path: request binding, result binding, record
 * issuance and verification know nothing about Base. Everything network-specific is here, which is
 * what makes a second network an additional observer rather than a second evidence model.
 *
 * EXPECTATION AND OBSERVATION, KEPT STRUCTURALLY APART. What the native x402 artifacts said should
 * happen and what was observed afterwards are different kinds of fact, so the document carries
 * them as two explicitly attributed objects rather than one flat field list. `payment_expectation`
 * is read from the native artifact: the network, asset, amount and recipient the payment named,
 * and a digest of the EIP-3009 authorization, digest only, never raw signature material.
 * `chain_observation` is what the settlement reporter said, attributed to the party that said it:
 * the facilitator, or the in-process stand-in an offline run injects. A separately sourced
 * sealed-L2 RPC account, when one was asked, sits under its own key with its own attribution and
 * is never merged into either.
 *
 * THE COMPARISON IS EXPLICIT, NOT A MERGE. The document records an expected-versus-observed
 * comparison with a verdict per field. Nothing here declares either source true: the point is that
 * their agreement or disagreement is independently inspectable, and the comparison is a pure
 * function of the rest of the document, so a verifier can recompute it rather than believe it.
 *
 * WHAT MATCHING REQUIRES, AND WHAT A RECEIPT IS NOT. An included transaction with a successful
 * receipt is not by itself evidence that the expected payment happened. The transfer-event verdict
 * is evaluated only from an observed transfer on the expected token contract matching the expected
 * from, to and value; a successful receipt without that event is a recorded mismatch, not a match.
 * No field here claims finality, and reading this document as proof of payment is a misreading.
 */
import type { PaymentPayload, PaymentRequirements, SettleResponse } from '@x402/core/types';
import { computeJsonDocumentDigestJcs } from '@peac/protocol';
import type { JsonValue } from '@peac/kernel';
import { coerceDigest, type Sha256Digest } from '../digest.ts';
import type { FailureReason } from './failure-vocabulary.ts';
import { paymentWasSettled, type LifecycleObservation, type TerminalState } from './lifecycle.ts';
import {
  sameAddress,
  transferMatchesExpected,
  type SealedRpcObservationV1,
} from './observe-transaction.ts';

export const PROFILE_CHAIN_OBSERVATION =
  'org.peacprotocol.examples.payment-evidence/base-chain-observation/1';

/** Where the settlement report came from, so a reader knows who was asked. */
export interface ObservationSource {
  /** `facilitator` when a settlement service reported it; the fixture names itself honestly. */
  readonly kind: 'facilitator' | 'in_process_fixture';
  /**
   * Endpoint origin, or the component that answered.
   *
   * Never a path, query, fragment or credential: an endpoint is named by its origin alone, so a
   * token carried in any other part of a configured URL cannot reach this document.
   */
  readonly reference: string;
}

/** How settlement ended, kept separate from the transaction facts it may or may not carry. */
export type SettlementOutcome = 'succeeded' | 'refused' | 'not_reached';

/** What the native x402 artifacts said should happen. Attributed to them, and to nothing else. */
export interface PaymentExpectationV1 {
  readonly source: 'native_x402_artifact';
  /** CAIP-2 identifier of the network the payment named. */
  readonly network: string;
  /** Token contract the payment was denominated in. */
  readonly asset: string;
  /** Amount in the asset's smallest unit, as a string, so no precision is lost. */
  readonly amount_base_units: string;
  readonly asset_decimals: number;
  readonly recipient: string;
  /**
   * The payer the EIP-3009 authorization named, when the payload carried one.
   *
   * Read from the same native artifact as everything else here. It is the `from` side of the
   * expected transfer, and it is an expectation about who authorized payment, never a claim about
   * who broadcast the transaction: the broadcaster is a separately observed fact that lives in the
   * RPC account.
   */
  readonly payer?: string;
  /**
   * Digest of the EIP-3009 authorization object the payment carried, when one did.
   *
   * A digest and nothing more: the raw authorization and its signature live in the captured
   * payment field value, bound by its own digest, and are never restated here.
   */
  readonly authorization_digest?: Sha256Digest;
}

/** The settlement reporter's account, attributed to the party that gave it. */
export interface SettlementReportV1 {
  readonly source: ObservationSource;
  readonly settlement_outcome: SettlementOutcome;
  /** Present only when settlement succeeded and reported one. */
  readonly transaction_hash?: string;
  /** Network the settlement response named, repeated as reported. */
  readonly network_reported?: string;
  /** Payer the settlement or verification reported, repeated as reported. */
  readonly payer_reported?: string;
  readonly observed_at_unix_seconds: number;
}

export type ComparisonVerdict = 'match' | 'mismatch' | 'not_evaluated';

/**
 * The expected-versus-observed comparison, one verdict per field.
 *
 * `not_evaluated` is a first-class verdict: a run that asked no chain observer has nothing to
 * compare against, and saying so is more honest than a match nobody measured. The asset,
 * recipient, amount and transfer-event verdicts are evaluated only from a separately sourced RPC
 * account, because the settlement reporter does not restate them and the expectation cannot be
 * compared against itself.
 */
export interface ExpectationComparisonV1 {
  readonly network: ComparisonVerdict;
  readonly asset: ComparisonVerdict;
  readonly recipient: ComparisonVerdict;
  readonly amount: ComparisonVerdict;
  /** Whether the expectation carries an authorization digest linking it to the native artifact. */
  readonly authorization: 'linked' | 'not_evaluated';
  /** Whether an observed transfer on the expected token matches the expectation exactly. */
  readonly transfer_event: ComparisonVerdict;
}

export interface BaseChainObservationV1 {
  readonly profile: typeof PROFILE_CHAIN_OBSERVATION;
  readonly scheme: string;
  readonly payment_expectation: PaymentExpectationV1;
  readonly chain_observation: SettlementReportV1;
  /**
   * A sealed-L2 RPC account of the same transaction, when one was asked.
   *
   * Structurally apart from the settlement report and never merged into it. Receipt status,
   * inclusion level and block placement are things only an RPC observer reports, so they exist
   * there and nowhere else: a reader can always tell which observer supplied which fact. Absent
   * whenever no endpoint was asked, which is every offline run and any run that settled nothing.
   */
  readonly rpc_observation?: SealedRpcObservationV1;
  readonly comparison: ExpectationComparisonV1;
  /** Where the run ended, so a reader can tell which artifacts should exist. */
  readonly terminal_state: TerminalState;
  /**
   * Why settlement refused, when it did, from the fixed vocabulary in `failure-vocabulary.ts`.
   *
   * This value is covered by a digest inside a signed record, so it is never text a facilitator or
   * an exception supplied. What the facilitator actually sent is kept where it belongs: in the
   * captured settlement field value, bound by its own digest.
   */
  readonly settlement_failure_reason?: FailureReason;
  /** Digest of the settlement response exactly as observed. */
  readonly settlement_response_digest?: Sha256Digest;
  /** Digest of the origin result this payment was for, linking payment to work. */
  readonly service_result_digest?: Sha256Digest;
  readonly observed_at_unix_seconds: number;
}

/** The native artifacts one run produced, before anything network-specific is read out of them. */
export interface NativeSettlementArtifacts {
  readonly requirements: PaymentRequirements;
  readonly paymentPayload: PaymentPayload;
  /** Present when settlement ran, whether it succeeded or refused. */
  readonly settleResponse?: SettleResponse;
  /** Digest of the observed settlement field value, when one was emitted. */
  readonly settlementResponseDigest?: Sha256Digest;
  /** Digest of the origin result the payment was for, when the handler produced one. */
  readonly serviceResultDigest?: Sha256Digest;
  readonly lifecycle: LifecycleObservation;
  readonly observationSource: ObservationSource;
  readonly observedAtUnixSeconds: number;
  readonly assetDecimals: number;
  /** A sealed-L2 RPC account of the settlement transaction, when one was asked. */
  readonly rpcObservation?: SealedRpcObservationV1;
}

/**
 * Recompute the comparison from the rest of the document.
 *
 * A pure function on purpose: the writer records its result, and the verifier runs the same
 * function over the document it was handed, so a comparison edited into something more flattering
 * disagrees with the fields beside it and is caught as exactly that.
 */
export function compareExpectationToObservation(
  document: Pick<BaseChainObservationV1, 'payment_expectation' | 'chain_observation' | 'rpc_observation'>,
): ExpectationComparisonV1 {
  const expectation = document.payment_expectation;
  const report = document.chain_observation;
  const transfer = document.rpc_observation?.token_transfer;

  // The transfer-event verdict requires the whole expected transfer at once: token, from, to and
  // value. Any piece the expectation cannot state, above all the authorized payer, leaves the
  // verdict a mismatch rather than a partial match, because "mostly the expected transfer" is not
  // a category this document is willing to invent.
  //
  // EXACTLY ONE, NOT "AT LEAST ONE". The pinned x402/EIP-3009 settlement path issues a single
  // `transferWithAuthorization` contract call, never a batch, so a standard ERC-20 token contract
  // emits exactly one Transfer event per settlement. `matching_transfer_count` carries the actual
  // count the observation found; requiring it to equal exactly 1 is what keeps two or more
  // matching events — which this document's shape can represent but never silently resolves by
  // picking one — from reading as an unambiguous match.
  const transferMatches =
    transfer !== undefined &&
    expectation.payer !== undefined &&
    document.rpc_observation?.matching_transfer_count === 1 &&
    transferMatchesExpected(transfer, {
      token_contract: expectation.asset,
      transfer_from: expectation.payer,
      transfer_to: expectation.recipient,
      transfer_amount: expectation.amount_base_units,
    });

  return {
    network:
      report.network_reported === undefined
        ? 'not_evaluated'
        : report.network_reported === expectation.network
          ? 'match'
          : 'mismatch',
    asset:
      transfer === undefined
        ? 'not_evaluated'
        : sameAddress(transfer.token_contract, expectation.asset)
          ? 'match'
          : 'mismatch',
    recipient:
      transfer === undefined
        ? 'not_evaluated'
        : sameAddress(transfer.transfer_to, expectation.recipient)
          ? 'match'
          : 'mismatch',
    amount:
      transfer === undefined
        ? 'not_evaluated'
        : transfer.transfer_amount === expectation.amount_base_units
          ? 'match'
          : 'mismatch',
    authorization: expectation.authorization_digest !== undefined ? 'linked' : 'not_evaluated',
    // Evaluated whenever an RPC account with a receipt exists: a successful receipt without the
    // expected transfer is a recorded mismatch, never silently unevaluated, because equating
    // "the transaction succeeded" with "the expected payment occurred" is the exact misreading
    // this verdict exists to prevent.
    transfer_event:
      document.rpc_observation === undefined || document.rpc_observation.receipt_status === undefined
        ? 'not_evaluated'
        : transferMatches
          ? 'match'
          : 'mismatch',
  };
}

/** The EIP-3009 authorization member of an exact EVM payload, when the payload carries one. */
function authorizationOf(payload: PaymentPayload): JsonValue | undefined {
  const authorization = (payload.payload as Record<string, unknown>)['authorization'];
  if (typeof authorization !== 'object' || authorization === null || Array.isArray(authorization)) {
    return undefined;
  }
  return authorization as JsonValue;
}

/**
 * Read a chain observation document out of the native artifacts.
 *
 * The transaction reference is recorded only when settlement actually succeeded. A reference
 * carried alongside a failure would read as a payment that happened, so a refused settlement
 * records the refusal and no transaction facts at all.
 */
export async function observeSettlement(
  artifacts: NativeSettlementArtifacts,
): Promise<BaseChainObservationV1> {
  const { requirements, lifecycle, settleResponse } = artifacts;
  const settled = paymentWasSettled(lifecycle.terminalState) && settleResponse?.success === true;
  const outcome: SettlementOutcome = settled
    ? 'succeeded'
    : settleResponse !== undefined || lifecycle.terminalState === 'settlement_failed'
      ? 'refused'
      : 'not_reached';

  const authorization = authorizationOf(artifacts.paymentPayload);
  const authorizationDigest =
    authorization === undefined
      ? undefined
      : coerceDigest(await computeJsonDocumentDigestJcs(authorization));
  const authorizedPayer =
    authorization !== undefined && typeof (authorization as Record<string, unknown>)['from'] === 'string'
      ? ((authorization as Record<string, unknown>)['from'] as string)
      : undefined;

  const expectation: PaymentExpectationV1 = {
    source: 'native_x402_artifact',
    network: requirements.network,
    asset: requirements.asset,
    amount_base_units: requirements.amount,
    asset_decimals: artifacts.assetDecimals,
    recipient: requirements.payTo,
    ...(authorizedPayer !== undefined ? { payer: authorizedPayer } : {}),
    ...(authorizationDigest !== undefined ? { authorization_digest: authorizationDigest } : {}),
  };

  const report: SettlementReportV1 = {
    source: artifacts.observationSource,
    settlement_outcome: outcome,
    ...(settled && settleResponse?.transaction
      ? { transaction_hash: settleResponse.transaction }
      : {}),
    ...(settled && settleResponse?.network !== undefined
      ? { network_reported: settleResponse.network }
      : {}),
    ...(lifecycle.payer !== undefined ? { payer_reported: lifecycle.payer } : {}),
    observed_at_unix_seconds: artifacts.observedAtUnixSeconds,
  };

  // Carried only alongside a settlement that succeeded and reported a transaction, so an RPC
  // account can never appear beside a payment this run did not observe settling.
  const rpcObservation =
    settled && settleResponse?.transaction && artifacts.rpcObservation !== undefined
      ? artifacts.rpcObservation
      : undefined;

  const partial = {
    payment_expectation: expectation,
    chain_observation: report,
    ...(rpcObservation !== undefined ? { rpc_observation: rpcObservation } : {}),
  };

  return {
    profile: PROFILE_CHAIN_OBSERVATION,
    scheme: requirements.scheme,
    ...partial,
    comparison: compareExpectationToObservation(partial),
    terminal_state: lifecycle.terminalState,
    ...(outcome === 'refused' && lifecycle.failureReason !== undefined
      ? { settlement_failure_reason: lifecycle.failureReason }
      : {}),
    ...(artifacts.settlementResponseDigest !== undefined
      ? { settlement_response_digest: artifacts.settlementResponseDigest }
      : {}),
    ...(artifacts.serviceResultDigest !== undefined
      ? { service_result_digest: artifacts.serviceResultDigest }
      : {}),
    observed_at_unix_seconds: artifacts.observedAtUnixSeconds,
  };
}

/** Digest of a chain observation, over its canonical JSON bytes. */
export async function chainObservationDigest(
  observation: BaseChainObservationV1,
): Promise<Sha256Digest> {
  return coerceDigest(await computeJsonDocumentDigestJcs(observation as unknown as JsonValue));
}
