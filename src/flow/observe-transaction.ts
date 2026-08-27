/**
 * A second observer of the same settlement: a Base RPC endpoint, asked directly.
 *
 * WHY A SECOND ONE. Everything else the evidence records about settlement comes from the
 * facilitator, which is a party to the payment. Asking an RPC endpoint as well does not make the
 * payment more true; it records that a different observer was asked and what it said, so a reader
 * can see two accounts instead of one and check either against the network themselves.
 *
 * WHAT A SEALED-L2 OBSERVATION IS, AND HOW IT IS ESTABLISHED. Base's documented public HTTP
 * JSON-RPC is Flashblocks-enabled: the caller's block tag selects the confirmation semantics, with
 * `pending` naming preconfirmation state and `latest` the most recently sealed block. This
 * observer therefore NEVER uses the `pending` tag, and it never infers sealed inclusion from the
 * mere existence of a transaction receipt: Base's own documentation is in conflict over whether
 * receipts are returned for transactions that are only in a Flashblock, so receipt existence is an
 * unresolved signal and carries no inclusion claim here. Sealed inclusion is recorded only after
 * the receipt's reported block placement, the transaction object's reported block placement, and
 * sealed block data queried by explicit block number all agree — including that the sealed
 * block's own transaction list contains this transaction hash — and only then does the
 * observation carry `observation_level: "l2_block_inclusion"`.
 *
 * `receipt_status` is the EVM execution result, success or revert, and nothing else: not an
 * inclusion level, not finality, and not by itself evidence that the expected payment occurred.
 * L1 batch inclusion and L1 finality are distinct properties that this observer does not query,
 * so no field here may be read as claiming either.
 *
 * FAILING SOFT, ON PURPOSE. An endpoint that is unreachable, slow, or does not know the
 * transaction must not cost a run its evidence: the settlement already happened, and the
 * facilitator's account of it is recorded either way. So an observation that could not be made is
 * recorded as one that could not be made, with the reason drawn from a fixed vocabulary rather
 * than from server text.
 *
 * The transaction source is an interface so a test can supply one without a socket. Only the live
 * run ever constructs the JSON-RPC-backed implementation.
 */
import {
  ADDRESS20,
  HASH32,
  JSON_RPC_FAILURE_TEXT,
  JsonRpcFailure,
  RPC_DATA,
  admitRpcQuantity,
  jsonRpcRequest,
} from './evm-json-rpc.ts';

/** A raw log entry as an endpoint reports it, before any interpretation. */
export interface ObservedLog {
  /** Contract that emitted the log. */
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}

/** What an endpoint reported about one transaction receipt. */
export interface ObservedReceipt {
  /** EVM execution result: success or revert. Never an inclusion or finality level. */
  readonly status: 'success' | 'reverted';
  /** Block placement as reported by the receipt. Null when the endpoint reported none. */
  readonly blockNumber: bigint | null;
  readonly blockHash: string | null;
  readonly logs: readonly ObservedLog[];
}

/** What an endpoint reported about the transaction object itself. */
export interface ObservedTransaction {
  /** The account that broadcast the transaction. An observed fact, never an inferred role. */
  readonly from: string;
  /** Block placement as reported by the transaction object. Null when the endpoint reported none. */
  readonly blockNumber: bigint | null;
  readonly blockHash: string | null;
}

/** One sealed block, queried by explicit block number. */
export interface SealedBlock {
  readonly number: bigint;
  readonly hash: string;
  /**
   * Every transaction hash the sealed block reports containing. Retained because a block that
   * carries the expected number and hash still says nothing about whether it contains a given
   * transaction; membership in this list is part of what an inclusion claim must establish.
   */
  readonly transactionHashes: readonly string[];
}

export interface SealedTransactionSource {
  /**
   * Endpoint identity, safe to publish: the origin only.
   *
   * Never a path, query, fragment or userinfo component, because any of them can carry a
   * credential and this value is signed into a document meant to be handed to someone else.
   */
  readonly reference: string;
  /** The endpoint's sealed chain head, from `eth_blockNumber`. */
  sealedHeadBlockNumber(): Promise<bigint>;
  /** The receipt for one transaction, or `undefined` when the endpoint reports none. */
  transactionReceipt(transactionHash: string): Promise<ObservedReceipt | undefined>;
  /** The transaction object, or `undefined` when the endpoint reports none. */
  transactionByHash(transactionHash: string): Promise<ObservedTransaction | undefined>;
  /**
   * One block queried by explicit block number, which names sealed block data.
   *
   * The `pending` tag is not part of this interface on purpose: preconfirmation state cannot
   * establish sealed inclusion, so no implementation of this source has a way to ask for it.
   */
  sealedBlockByNumber(blockNumber: bigint): Promise<SealedBlock | undefined>;
}

/** A token transfer read structurally out of a receipt log. All amounts are decimal strings. */
export interface ObservedTokenTransfer {
  readonly token_contract: string;
  readonly transfer_from: string;
  readonly transfer_to: string;
  readonly transfer_amount: string;
}

/**
 * The only observation level this observer can establish, present only after the sealed-block
 * comparison agreed. No further levels are declared here: a value exists only alongside an
 * implementation that can actually produce it.
 */
export type ObservationLevel = 'l2_block_inclusion';

export interface SealedRpcObservationV1 {
  /** Kept distinct from the facilitator's account of the same settlement, never merged with it. */
  readonly source: { readonly kind: 'rpc'; readonly reference: string };
  readonly transaction_hash: string;
  readonly observation_state: 'found' | 'not_found' | 'unavailable';
  /** Present only when the sealed-block comparison agreed. Never inferred from receipt existence. */
  readonly observation_level?: ObservationLevel;
  /** EVM execution result as reported. Separate from inclusion, and never finality. */
  readonly receipt_status?: 'success' | 'reverted';
  /** The account that broadcast the transaction, as observed. A fact, never a role. */
  readonly transaction_sender?: string;
  /** Sealed block placement, present only alongside `observation_level`. Decimal string. */
  readonly block_number?: string;
  readonly block_hash?: string;
  /**
   * The transfer event on the expected token contract, when the receipt carried one.
   *
   * Selected structurally: the event matching the expected transfer if one exists, otherwise the
   * first event on that contract, so a mismatched transfer is recorded rather than hidden. How
   * many such events were seen is stated in the sentence below.
   */
  readonly token_transfer?: ObservedTokenTransfer;
  /** Why nothing could be observed. Fixed vocabulary; never text an endpoint supplied. */
  readonly unavailable_reason?: string;
  readonly observed_at_unix_seconds: number;
  /** The observation in one sentence, phrased as a report and never as a finding. */
  readonly statement: string;
}

/**
 * The canonical ERC-20 Transfer event signature topic: keccak-256 of
 * `Transfer(address,address,uint256)`. Stated as a constant because it is a fixed property of the
 * event signature, and recomputing it would add a hashing dependency to a structural comparison.
 */
export const TRANSFER_EVENT_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

/** Exactly one 20-byte hex address. The RPC Data shape, shared with the JSON-RPC admissions. */
const HEX_ADDRESS = ADDRESS20;

/**
 * A 32-byte ABI word holding an indexed address: 12 zero bytes of padding, then the 20 address
 * bytes. Solidity's ABI event encoding zero-pads an indexed `address` on the left, so a topic
 * whose high 12 bytes are not zero is not a well-formed address topic and is never truncated
 * into one.
 */
const ADDRESS_TOPIC = /^0x0{24}[0-9a-fA-F]{40}$/;

/** Exactly one 32-byte ABI word, the encoding of a non-indexed `uint256`. */
const ABI_WORD = /^0x[0-9a-fA-F]{64}$/;

/**
 * Read the ERC-20 transfers on one token contract out of raw receipt logs.
 *
 * STRUCTURAL ONLY. This is local ABI structure parsing, not a token-validity or payment oracle:
 * it decodes the standard Transfer event layout — the signature topic, two indexed address topics
 * each zero-padded to 32 bytes, and the amount as exactly one ABI data word — and nothing else.
 * Each structural rule is checked before anything is decoded, and a log that does not match the
 * layout exactly is skipped rather than guessed at: a topic with non-zero padding bytes is never
 * sliced down to an address, and data that is not exactly one word is never read as an amount.
 */
export function transfersOnContract(
  logs: readonly ObservedLog[],
  tokenContract: string,
): ObservedTokenTransfer[] {
  const transfers: ObservedTokenTransfer[] = [];
  if (!HEX_ADDRESS.test(tokenContract)) return transfers;
  const contract = tokenContract.toLowerCase();
  for (const log of logs) {
    if (typeof log.address !== 'string' || !HEX_ADDRESS.test(log.address)) continue;
    if (log.address.toLowerCase() !== contract) continue;
    if (log.topics.length !== 3) continue;
    const [signatureTopic, fromTopic, toTopic] = log.topics;
    if (
      signatureTopic === undefined ||
      !ABI_WORD.test(signatureTopic) ||
      signatureTopic.toLowerCase() !== TRANSFER_EVENT_TOPIC
    ) {
      continue;
    }
    if (fromTopic === undefined || toTopic === undefined) continue;
    if (!ADDRESS_TOPIC.test(fromTopic) || !ADDRESS_TOPIC.test(toTopic)) continue;
    if (!ABI_WORD.test(log.data)) continue;
    transfers.push({
      token_contract: log.address,
      transfer_from: `0x${fromTopic.slice(-40)}`,
      transfer_to: `0x${toTopic.slice(-40)}`,
      transfer_amount: BigInt(log.data).toString(10),
    });
  }
  return transfers;
}

/** What the observation should treat as the expected transfer, for selection and comparison. */
export interface ExpectedTransfer {
  readonly token_contract: string;
  readonly transfer_from: string;
  readonly transfer_to: string;
  readonly transfer_amount: string;
}

/** Case-insensitive address equality, the only comparison hex addresses support. */
export const sameAddress = (a: string, b: string): boolean => a.toLowerCase() === b.toLowerCase();

/** Whether one observed transfer is exactly the expected one. */
export function transferMatchesExpected(
  observed: ObservedTokenTransfer,
  expected: ExpectedTransfer,
): boolean {
  return (
    sameAddress(observed.token_contract, expected.token_contract) &&
    sameAddress(observed.transfer_from, expected.transfer_from) &&
    sameAddress(observed.transfer_to, expected.transfer_to) &&
    observed.transfer_amount === expected.transfer_amount
  );
}

/**
 * Fixed reasons. An endpoint's own message is never retained: it can embed anything.
 *
 * The endpoint-failure reasons are the bounded JSON-RPC failure vocabulary, one wording per
 * condition everywhere it is reported: unreachable or timed out, answered with an RPC error, or
 * answered with something structurally unusable. `ENDPOINT_UNREACHABLE` is exported because the
 * preflight reports the same condition about the same kind of endpoint, and two wordings for one
 * outcome would read as two different outcomes. The final reason below is local: a transaction
 * reference that is not a 32-byte hash is refused before any endpoint is queried, because a
 * malformed reference can select nothing and querying with it would only launder the refusal into
 * an endpoint answer.
 */
export const ENDPOINT_UNREACHABLE = JSON_RPC_FAILURE_TEXT.unreachable;
export const ENDPOINT_TEMPORARILY_UNAVAILABLE = JSON_RPC_FAILURE_TEXT.temporarily_unavailable;
export const ENDPOINT_RPC_ERROR = JSON_RPC_FAILURE_TEXT.rpc_error;
export const ENDPOINT_RESPONSE_UNUSABLE = JSON_RPC_FAILURE_TEXT.unusable;
const UNKNOWN_TRANSACTION = 'the endpoint reported no receipt and no transaction for this hash';
export const MALFORMED_TRANSACTION_REFERENCE =
  'the transaction reference is not a 32-byte transaction hash, so no endpoint was queried';
/**
 * A failure this code raised locally, outside the classified JSON-RPC vocabulary. Terminal: a
 * local error is deterministic from the loop's point of view, and retrying it would rerun the
 * same defect while attributing the delay to the endpoint.
 */
export const OBSERVATION_LOCAL_FAILURE =
  'the observation failed locally before a usable endpoint answer';

/**
 * The unavailable-reasons a bounded observation loop may retry, fail-closed.
 *
 * Exactly the retryable JSON-RPC failure kinds: a transport-level failure and the explicitly
 * admitted temporary HTTP statuses. An RPC error, a structurally unusable response, a malformed
 * transaction reference and a local failure are terminal, and an unavailable-reason outside this
 * set is treated as terminal rather than retried on the strength of being unrecognized.
 */
export const RETRYABLE_UNAVAILABLE_REASONS: ReadonlySet<string> = new Set([
  ENDPOINT_UNREACHABLE,
  ENDPOINT_TEMPORARILY_UNAVAILABLE,
]);

/** The bounded reason for one caught observation failure. Never text a remote party supplied. */
function reasonFor(e: unknown): string {
  return e instanceof JsonRpcFailure ? JSON_RPC_FAILURE_TEXT[e.kind] : OBSERVATION_LOCAL_FAILURE;
}

function isoOf(observedAtUnixSeconds: number): string {
  return new Date(observedAtUnixSeconds * 1000).toISOString();
}

/**
 * Observe one transaction through a sealed transaction source.
 *
 * This is the sealed-L2 observation sequence, in full: query the receipt and the transaction,
 * treat their existence as observed facts and nothing more, query sealed block data by the
 * explicit block number the receipt reported, and record `l2_block_inclusion` only when the
 * receipt's placement, the transaction object's placement and the sealed block data all agree —
 * number, hash, and the sealed block's transaction list containing this transaction hash.
 * `receipt_status` is recorded separately as the execution result. No step uses preconfirmation
 * state, and no step claims L1 batch inclusion or L1 finality.
 *
 * Never throws: an observation that could not be made is a result, not a failure of the run.
 */
export async function observeSealedTransaction(input: {
  readonly source: SealedTransactionSource;
  readonly transactionHash: string;
  readonly expectedTransfer: ExpectedTransfer;
  readonly observedAtUnixSeconds: number;
}): Promise<SealedRpcObservationV1> {
  const { source, transactionHash, expectedTransfer, observedAtUnixSeconds } = input;
  const at = isoOf(observedAtUnixSeconds);

  const unavailable = (reason: string): SealedRpcObservationV1 => ({
    source: { kind: 'rpc', reference: source.reference },
    transaction_hash: transactionHash,
    observation_state: 'unavailable',
    unavailable_reason: reason,
    observed_at_unix_seconds: observedAtUnixSeconds,
    statement:
      `RPC ${source.reference} could not be observed for transaction ${transactionHash} ` +
      `at time ${at}: ${reason}.`,
  });

  // The transaction reference arrives from the facilitator's settlement response, which is remote
  // input. It is admitted as exactly one 32-byte hash BEFORE any endpoint is queried: a malformed
  // reference selects nothing, and an observation made with it could only misattribute the
  // refusal to the endpoint.
  if (!HASH32.test(transactionHash)) {
    return unavailable(MALFORMED_TRANSACTION_REFERENCE);
  }

  let receipt: ObservedReceipt | undefined;
  let transaction: ObservedTransaction | undefined;
  try {
    receipt = await source.transactionReceipt(transactionHash);
    transaction = await source.transactionByHash(transactionHash);
  } catch (e) {
    return unavailable(reasonFor(e));
  }

  if (receipt === undefined && transaction === undefined) {
    return {
      source: { kind: 'rpc', reference: source.reference },
      transaction_hash: transactionHash,
      observation_state: 'not_found',
      unavailable_reason: UNKNOWN_TRANSACTION,
      observed_at_unix_seconds: observedAtUnixSeconds,
      statement:
        `RPC ${source.reference} reported no receipt and no transaction for ` +
        `${transactionHash} at time ${at}.`,
    };
  }

  const sender = transaction?.from;
  if (receipt === undefined) {
    // The transaction object exists and no receipt does. What is known is who broadcast it; no
    // execution result and no inclusion level can be recorded from this state.
    return {
      source: { kind: 'rpc', reference: source.reference },
      transaction_hash: transactionHash,
      observation_state: 'found',
      ...(sender !== undefined ? { transaction_sender: sender } : {}),
      observed_at_unix_seconds: observedAtUnixSeconds,
      statement:
        `RPC ${source.reference} reported transaction ${transactionHash} without a receipt ` +
        `at time ${at}; no execution result and no inclusion level were observed.`,
    };
  }

  const transfers = transfersOnContract(receipt.logs, expectedTransfer.token_contract);
  const matching = transfers.find((t) => transferMatchesExpected(t, expectedTransfer));
  const recordedTransfer = matching ?? transfers[0];

  // Sealed-block comparison. Inclusion is recorded only when every placement fact agrees: the
  // receipt reports a block, the transaction object exists and reports the same block, sealed
  // block data queried by that explicit number carries the same number and hash, the sealed
  // block's own transaction list contains this transaction hash, and the block is at or below
  // the sealed head. Anything missing or disagreeing leaves the observation without an inclusion
  // level: the receipt and transaction stay recorded as observed facts and are not promoted into
  // a claim they cannot carry. A failed comparison is a factual gap in what could be observed —
  // never a signature failure — and no finality claim is derived from any branch of it.
  let inclusion: { block_number: string; block_hash: string } | undefined;
  let inclusionNote = 'sealed inclusion was not established';
  if (receipt.blockNumber === null || receipt.blockHash === null) {
    inclusionNote = 'the receipt reported no block placement, so no inclusion level is recorded';
  } else if (
    transaction === undefined ||
    transaction.blockNumber === null ||
    transaction.blockHash === null
  ) {
    inclusionNote =
      'the transaction object reported no block placement, so no inclusion level is recorded';
  } else if (
    transaction.blockNumber !== receipt.blockNumber ||
    transaction.blockHash.toLowerCase() !== receipt.blockHash.toLowerCase()
  ) {
    inclusionNote =
      'the transaction object and the receipt disagree on block placement, so no inclusion ' +
      'level is recorded';
  } else {
    try {
      const sealedBlock = await source.sealedBlockByNumber(receipt.blockNumber);
      const head = await source.sealedHeadBlockNumber();
      const wanted = transactionHash.toLowerCase();
      if (
        sealedBlock !== undefined &&
        sealedBlock.number === receipt.blockNumber &&
        sealedBlock.hash.toLowerCase() === receipt.blockHash.toLowerCase() &&
        sealedBlock.transactionHashes.some((hash) => hash.toLowerCase() === wanted) &&
        receipt.blockNumber <= head
      ) {
        inclusion = {
          block_number: receipt.blockNumber.toString(10),
          block_hash: receipt.blockHash,
        };
        inclusionNote =
          `sealed block ${inclusion.block_number} agreed with the reported placement and ` +
          'lists this transaction';
      } else {
        inclusionNote =
          'the sealed block data queried by explicit number did not agree with the reported ' +
          'placement or did not list this transaction, so no inclusion level is recorded';
      }
    } catch {
      inclusionNote = 'sealed block data could not be queried, so no inclusion level is recorded';
    }
  }

  const transferNote =
    transfers.length === 0
      ? 'no transfer event on the expected token contract'
      : `${transfers.length} transfer event(s) on the expected token contract, ` +
        `${matching !== undefined ? 'one matching the expectation' : 'none matching the expectation'}`;

  return {
    source: { kind: 'rpc', reference: source.reference },
    transaction_hash: transactionHash,
    observation_state: 'found',
    ...(inclusion !== undefined ? { observation_level: 'l2_block_inclusion' as const } : {}),
    receipt_status: receipt.status,
    ...(sender !== undefined ? { transaction_sender: sender } : {}),
    ...(inclusion ?? {}),
    ...(recordedTransfer !== undefined ? { token_transfer: recordedTransfer } : {}),
    observed_at_unix_seconds: observedAtUnixSeconds,
    statement:
      `RPC ${source.reference} reported transaction ${transactionHash} with execution status ` +
      `${receipt.status} at time ${at}; ${inclusionNote}; ${transferNote}.`,
  };
}

/**
 * A label a caller states outright, rather than one derived from a configured value.
 *
 * Bounded to characters that cannot be mistaken for structure, so a label can never smuggle in the
 * part of a URL this function exists to drop.
 */
const SAFE_LABEL = /^[A-Za-z0-9][A-Za-z0-9 ,.:_-]{0,79}$/;

/**
 * An endpoint named without anything that could be a credential.
 *
 * ONLY THE ORIGIN SURVIVES. Scheme, host and port, and nothing else. Userinfo, password, path,
 * query and fragment are all dropped rather than judged: hosted endpoint providers routinely put
 * an API token in the path, so a path is not a safer thing to publish than a query string, and
 * this value is signed into a document meant to be handed to someone else.
 *
 * A more specific human-readable identity is therefore never derived. It has to be supplied, as
 * `safeLabel`, by a caller stating what it wants published; a label that is not plainly safe is
 * refused rather than trimmed into shape.
 */
export function publicEndpointReference(
  configured: string | undefined,
  safeLabel?: string,
): string | undefined {
  if (safeLabel !== undefined) return SAFE_LABEL.test(safeLabel) ? safeLabel : undefined;
  if (configured === undefined || configured.trim().length === 0) return undefined;
  let url: URL;
  try {
    url = new URL(configured);
  } catch {
    return undefined;
  }
  // A non-HTTP scheme has no meaningful origin: `URL` reports it as the string "null", which would
  // be published as though it were an endpoint identity.
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
  return url.origin;
}

/**
 * The most receipt logs this observer will read.
 *
 * A deliberate bound, and a fail-closed one: a receipt reporting more logs than this is refused
 * whole rather than truncated, because a truncated log list can silently drop the very Transfer
 * event a match depends on and turn "not read" into a false "expected transfer absent".
 */
export const MAX_RECEIPT_LOGS = 256;

/**
 * Admit an `eth_getTransactionReceipt` result, or refuse the response as unusable.
 *
 * Exported for the offline suites, which exercise these admissions without a socket. Every field
 * is held to its actual RPC type: `status` to the two documented values, block placement to a
 * strict Quantity and a 32-byte hash (both may be null together for a pending placement), and
 * every log to a 20-byte address, 32-byte topics and even-byte data. A receipt that reports more
 * than `MAX_RECEIPT_LOGS` logs, or one malformed log, is refused WHOLE: logs are never silently
 * skipped or truncated, because an incomplete log list cannot support any claim about which
 * events the transaction did or did not emit.
 *
 * LOG PLACEMENT FIELDS ARE CHECKED WHEN PRESENT, NEVER REQUIRED. The live Base Sepolia endpoint
 * (measured 2026-08-27) reports `removed`, `transactionHash`, `blockHash` and `blockNumber` on
 * every receipt log; the EIP-1474 log object marks them optional, so their absence is admitted.
 * When present each must be well-formed and must agree with the receipt this claim rests on: a
 * log carrying `removed: true` can never satisfy the expected transfer — a removed log inside a
 * receipt queried for a sealed claim is an inconsistent response, and the receipt is refused
 * whole rather than read around — and a log whose placement names a different transaction or
 * block than the receipt's own is the same inconsistency.
 *
 * @param result - The raw `eth_getTransactionReceipt` result.
 * @param expectedTransactionHash - When supplied, a log's `transactionHash` (if present) must
 *   name this transaction; the receipt is refused whole otherwise.
 * @throws JsonRpcFailure `unusable` when the result is not an admissible receipt.
 */
export function admitReceiptResult(result: unknown, expectedTransactionHash?: string): ObservedReceipt {
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    throw new JsonRpcFailure('unusable');
  }
  const receipt = result as { status?: unknown; blockNumber?: unknown; blockHash?: unknown; logs?: unknown };
  // The status field is documented as 0x1 success and 0x0 failure; anything else is a receipt
  // this observer does not understand and refuses to reinterpret.
  const status =
    receipt.status === '0x1' ? ('success' as const) : receipt.status === '0x0' ? ('reverted' as const) : undefined;
  if (status === undefined) throw new JsonRpcFailure('unusable');

  let blockNumber: bigint | null = null;
  if (receipt.blockNumber !== null && receipt.blockNumber !== undefined) {
    const admitted = admitRpcQuantity(receipt.blockNumber);
    if (admitted === undefined) throw new JsonRpcFailure('unusable');
    blockNumber = admitted;
  }
  let blockHash: string | null = null;
  if (receipt.blockHash !== null && receipt.blockHash !== undefined) {
    if (typeof receipt.blockHash !== 'string' || !HASH32.test(receipt.blockHash)) {
      throw new JsonRpcFailure('unusable');
    }
    blockHash = receipt.blockHash;
  }

  if (!Array.isArray(receipt.logs)) throw new JsonRpcFailure('unusable');
  if (receipt.logs.length > MAX_RECEIPT_LOGS) throw new JsonRpcFailure('unusable');
  const logs: ObservedLog[] = [];
  for (const raw of receipt.logs) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new JsonRpcFailure('unusable');
    }
    const log = raw as {
      address?: unknown;
      topics?: unknown;
      data?: unknown;
      removed?: unknown;
      transactionHash?: unknown;
      blockHash?: unknown;
      blockNumber?: unknown;
    };
    if (typeof log.address !== 'string' || !ADDRESS20.test(log.address)) {
      throw new JsonRpcFailure('unusable');
    }
    if (!Array.isArray(log.topics) || !log.topics.every((t) => typeof t === 'string' && HASH32.test(t))) {
      throw new JsonRpcFailure('unusable');
    }
    if (typeof log.data !== 'string' || !RPC_DATA.test(log.data)) {
      throw new JsonRpcFailure('unusable');
    }
    // Placement fields: optional per EIP-1474, checked when the endpoint reports them. A log
    // marked removed, or placed in a different transaction or block than the receipt it arrived
    // in, makes the whole response inconsistent for the claim it exists to support.
    if (log.removed !== undefined) {
      if (typeof log.removed !== 'boolean') throw new JsonRpcFailure('unusable');
      if (log.removed) throw new JsonRpcFailure('unusable');
    }
    if (log.transactionHash !== undefined) {
      if (typeof log.transactionHash !== 'string' || !HASH32.test(log.transactionHash)) {
        throw new JsonRpcFailure('unusable');
      }
      if (
        expectedTransactionHash !== undefined &&
        log.transactionHash.toLowerCase() !== expectedTransactionHash.toLowerCase()
      ) {
        throw new JsonRpcFailure('unusable');
      }
    }
    if (log.blockHash !== undefined) {
      if (typeof log.blockHash !== 'string' || !HASH32.test(log.blockHash)) {
        throw new JsonRpcFailure('unusable');
      }
      if (blockHash !== null && log.blockHash.toLowerCase() !== blockHash.toLowerCase()) {
        throw new JsonRpcFailure('unusable');
      }
    }
    if (log.blockNumber !== undefined && log.blockNumber !== null) {
      const logBlockNumber = admitRpcQuantity(log.blockNumber);
      if (logBlockNumber === undefined) throw new JsonRpcFailure('unusable');
      if (blockNumber !== null && logBlockNumber !== blockNumber) {
        throw new JsonRpcFailure('unusable');
      }
    }
    logs.push({ address: log.address, topics: log.topics as string[], data: log.data });
  }
  return { status, blockNumber, blockHash, logs };
}

/**
 * Admit an `eth_getTransactionByHash` result, or refuse the response as unusable.
 *
 * @throws JsonRpcFailure `unusable` when the result is not an admissible transaction object.
 */
export function admitTransactionResult(result: unknown): ObservedTransaction {
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    throw new JsonRpcFailure('unusable');
  }
  const transaction = result as { from?: unknown; blockNumber?: unknown; blockHash?: unknown };
  if (typeof transaction.from !== 'string' || !ADDRESS20.test(transaction.from)) {
    throw new JsonRpcFailure('unusable');
  }
  let blockNumber: bigint | null = null;
  if (transaction.blockNumber !== null && transaction.blockNumber !== undefined) {
    const admitted = admitRpcQuantity(transaction.blockNumber);
    if (admitted === undefined) throw new JsonRpcFailure('unusable');
    blockNumber = admitted;
  }
  let blockHash: string | null = null;
  if (transaction.blockHash !== null && transaction.blockHash !== undefined) {
    if (typeof transaction.blockHash !== 'string' || !HASH32.test(transaction.blockHash)) {
      throw new JsonRpcFailure('unusable');
    }
    blockHash = transaction.blockHash;
  }
  return { from: transaction.from, blockNumber, blockHash };
}

/**
 * Admit an `eth_getBlockByNumber(..., false)` result, or refuse the response as unusable.
 *
 * `transactions` must be an array in which EVERY entry is a 32-byte transaction hash. A malformed
 * entry is never silently dropped: the list exists to answer whether the sealed block contains a
 * given transaction, and a list with an unreadable member cannot answer that for any transaction,
 * so the whole response is refused for the inclusion claim it would otherwise support.
 *
 * @throws JsonRpcFailure `unusable` when the result is not an admissible block.
 */
export function admitSealedBlockResult(result: unknown): SealedBlock {
  if (typeof result !== 'object' || result === null || Array.isArray(result)) {
    throw new JsonRpcFailure('unusable');
  }
  const block = result as { number?: unknown; hash?: unknown; transactions?: unknown };
  const number = admitRpcQuantity(block.number);
  if (number === undefined) throw new JsonRpcFailure('unusable');
  if (typeof block.hash !== 'string' || !HASH32.test(block.hash)) {
    throw new JsonRpcFailure('unusable');
  }
  if (!Array.isArray(block.transactions)) throw new JsonRpcFailure('unusable');
  const transactionHashes: string[] = [];
  for (const entry of block.transactions) {
    if (typeof entry !== 'string' || !HASH32.test(entry)) throw new JsonRpcFailure('unusable');
    transactionHashes.push(entry);
  }
  return { number, hash: block.hash, transactionHashes };
}

/**
 * A sealed transaction source backed by a Base JSON-RPC endpoint.
 *
 * Constructed only by the live run. Every exchange goes through the strict JSON-RPC envelope
 * reader, which THROWS a classified `JsonRpcFailure` for any failure — it does not return
 * `undefined` to mean one — and every result is admitted against the shape its RPC type defines
 * before it is interpreted. `undefined` from the transaction and receipt queries means exactly
 * one thing: the endpoint answered `null`, its well-formed way of reporting no such object.
 *
 * Block data is queried by `eth_blockNumber` and by explicit block number through
 * `eth_getBlockByNumber`; the `pending` block tag appears nowhere in this implementation, because
 * preconfirmation state cannot establish sealed inclusion.
 */
export function baseSealedRpcSource(rpcUrl: string, timeoutMs = 10_000): SealedTransactionSource {
  return {
    reference: publicEndpointReference(rpcUrl) ?? 'the configured Base RPC endpoint',
    async sealedHeadBlockNumber(): Promise<bigint> {
      const head = admitRpcQuantity(await jsonRpcRequest(rpcUrl, 'eth_blockNumber', [], timeoutMs));
      if (head === undefined) throw new JsonRpcFailure('unusable');
      return head;
    },
    async transactionReceipt(transactionHash: string): Promise<ObservedReceipt | undefined> {
      if (!HASH32.test(transactionHash)) throw new JsonRpcFailure('unusable');
      const result = await jsonRpcRequest(rpcUrl, 'eth_getTransactionReceipt', [transactionHash], timeoutMs);
      if (result === null) return undefined;
      return admitReceiptResult(result, transactionHash);
    },
    async transactionByHash(transactionHash: string): Promise<ObservedTransaction | undefined> {
      if (!HASH32.test(transactionHash)) throw new JsonRpcFailure('unusable');
      const result = await jsonRpcRequest(rpcUrl, 'eth_getTransactionByHash', [transactionHash], timeoutMs);
      if (result === null) return undefined;
      return admitTransactionResult(result);
    },
    async sealedBlockByNumber(blockNumber: bigint): Promise<SealedBlock | undefined> {
      // Asked with `false`, so `transactions` is the list of transaction hashes. That list is
      // parsed and retained because sealed inclusion requires the sealed block to actually
      // contain the transaction, not merely to carry the number and hash the receipt reported.
      const result = await jsonRpcRequest(
        rpcUrl,
        'eth_getBlockByNumber',
        [`0x${blockNumber.toString(16)}`, false],
        timeoutMs,
      );
      if (result === null) return undefined;
      return admitSealedBlockResult(result);
    },
  };
}
