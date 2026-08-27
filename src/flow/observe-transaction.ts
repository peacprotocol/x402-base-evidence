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
 * WHICH CHAIN ANSWERED. An endpoint's configured URL can be repointed to a different network
 * between the moment a run's preflight checked it and the moment this observation actually asks
 * it about a transaction, and a preflight check run once is not a property of the request made
 * later. So this observer asks `eth_chainId` as part of the SAME call that asks about the
 * transaction, every time, and nothing below that point may be attributed to the expected network
 * until the two agree. A mismatch — or an answer this observer cannot parse as a chain id — is
 * never a warning attached to otherwise-normal-looking Base evidence: the whole observation
 * abstains, because a receipt or a sealed block an endpoint reports on the wrong chain describes a
 * different transaction, not this one with a caveat.
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

import { parseStrictJson } from '../strict-json.ts';

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
  /**
   * The endpoint's chain identifier, from `eth_chainId`.
   *
   * Asked as part of THIS observation, every time, never only once by an earlier preflight check:
   * an endpoint's configured URL can be repointed between preflight and the run that actually asks
   * it about a transaction, and the two checks exist for different moments, not as one check done
   * twice. A malformed or unparseable answer is a failure of this call, the same way an
   * unparseable `eth_blockNumber` answer fails `sealedHeadBlockNumber` below.
   */
  chainId(): Promise<bigint>;
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
  /**
   * The CAIP-2 network identity this endpoint actually reported, normalized as `eip155:<chainId>`
   * (this observer only ever asks EVM endpoints). Present whenever the chain identity check
   * succeeded and matched what was expected; a run that never reaches that agreement records no
   * receipt, transaction or inclusion facts at all (see `observeSealedTransaction`), so this field
   * and the facts below it are present or absent together.
   */
  readonly observed_network?: string;
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
   * Selected structurally: the event exactly matching the expected transfer if exactly one such
   * event exists, otherwise the first event on that contract, so a mismatched or ambiguous
   * transfer is recorded rather than hidden. `matching_transfer_count` and
   * `expected_contract_transfer_count` below are what a reader checks the actual multiplicity
   * against; this field alone was never meant to represent count.
   */
  readonly token_transfer?: ObservedTokenTransfer;
  /**
   * How many transfer events were structurally decoded on the expected token contract, whether or
   * not they matched the expectation. Present whenever a receipt was read, including zero.
   */
  readonly expected_contract_transfer_count?: number;
  /**
   * How many of those events exactly matched the expected transfer (token, from, to, amount).
   *
   * `settleEIP3009` in the pinned `@x402/evm@2.23.0` issues one `transferWithAuthorization` call
   * per settlement — a single contract call, never a batch — so exactly one matching Transfer
   * event is the expected shape for a standard, unmodified ERC-20/EIP-3009 token. That is a fact
   * about the pinned Base Sepolia USDC contract's own implementation, not a guarantee the x402
   * settlement path or the EVM itself enforces, so this count is recorded rather than assumed:
   * zero, one or several are all representable, and the comparison in `observe-settlement.ts`
   * treats only a count of exactly one as a match.
   */
  readonly matching_transfer_count?: number;
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

/** Exactly one 20-byte hex address. */
const HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/** Exactly one 32-byte hex hash: a transaction hash or a block hash. */
const HEX_HASH_32 = /^0x[0-9a-fA-F]{64}$/;

/**
 * The canonical Ethereum JSON-RPC quantity grammar: `0x0` for zero, or `0x` followed by hex
 * digits with no leading zero. `0x0123` is well-formed hex but not a canonical quantity — the spec
 * requires the shortest representation — so it is refused rather than parsed leniently; an
 * endpoint answering with a non-canonical quantity is an endpoint this observer does not trust to
 * have encoded anything else correctly either.
 */
const CANONICAL_QUANTITY = /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/;

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
 * The first is exported because the preflight reports the same condition about the same kind of
 * endpoint, and two wordings for one outcome would read as two different outcomes.
 */
export const ENDPOINT_UNREACHABLE = 'the endpoint could not be reached or did not answer in time';
const UNKNOWN_TRANSACTION = 'the endpoint reported no receipt and no transaction for this hash';
/**
 * The endpoint's chain identity could not be established at all: unreachable, or an answer this
 * observer could not parse as a chain id. Distinct from `ENDPOINT_UNREACHABLE` above so a reader
 * can tell "nothing answered" apart from "something answered, but not usably" without either one
 * being read as evidence about Base.
 */
export const CHAIN_IDENTITY_UNESTABLISHED =
  "the endpoint's chain identity could not be established, so no observation can be attributed " +
  'to the expected network';

/**
 * The endpoint answered `eth_chainId`, but not with the expected network. Both halves are this
 * observer's own normalized `eip155:<chainId>` strings, never endpoint-supplied text, so the
 * reason is safe to publish as written.
 */
function chainMismatchReason(observedNetwork: string, expectedNetwork: string): string {
  return (
    `the endpoint reports ${observedNetwork}, not the expected ${expectedNetwork}, so no ` +
    'observation can be attributed to the expected network'
  );
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
  /** CAIP-2 network this observation must be attributed to, e.g. `eip155:84532` (Base Sepolia). */
  readonly expectedNetwork: string;
  readonly observedAtUnixSeconds: number;
}): Promise<SealedRpcObservationV1> {
  const { source, transactionHash, expectedTransfer, expectedNetwork, observedAtUnixSeconds } = input;
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

  // The chain-identity gate. Asked first, every call, regardless of what an earlier preflight
  // check established: this is a different moment, potentially a different endpoint answer, and
  // nothing below this point may be attributed to `expectedNetwork` until this agrees. A mismatch
  // (or an unparseable answer) is not a warning attached to otherwise-normal evidence; it is the
  // whole observation abstaining, because a receipt or a sealed block reported by an endpoint on
  // the wrong chain is not evidence about this one.
  let observedNetwork: string;
  try {
    const chainId = await source.chainId();
    observedNetwork = `eip155:${chainId}`;
  } catch {
    return unavailable(CHAIN_IDENTITY_UNESTABLISHED);
  }
  if (observedNetwork !== expectedNetwork) {
    return unavailable(chainMismatchReason(observedNetwork, expectedNetwork));
  }

  let receipt: ObservedReceipt | undefined;
  let transaction: ObservedTransaction | undefined;
  try {
    receipt = await source.transactionReceipt(transactionHash);
    transaction = await source.transactionByHash(transactionHash);
  } catch {
    return unavailable(ENDPOINT_UNREACHABLE);
  }

  if (receipt === undefined && transaction === undefined) {
    return {
      source: { kind: 'rpc', reference: source.reference },
      transaction_hash: transactionHash,
      observation_state: 'not_found',
      observed_network: observedNetwork,
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
      observed_network: observedNetwork,
      ...(sender !== undefined ? { transaction_sender: sender } : {}),
      observed_at_unix_seconds: observedAtUnixSeconds,
      statement:
        `RPC ${source.reference} reported transaction ${transactionHash} without a receipt ` +
        `at time ${at}; no execution result and no inclusion level were observed.`,
    };
  }

  const transfers = transfersOnContract(receipt.logs, expectedTransfer.token_contract);
  const exactMatches = transfers.filter((t) => transferMatchesExpected(t, expectedTransfer));
  const recordedTransfer = exactMatches[0] ?? transfers[0];

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
        `${exactMatches.length} matching the expectation exactly`;

  return {
    source: { kind: 'rpc', reference: source.reference },
    transaction_hash: transactionHash,
    observation_state: 'found',
    observed_network: observedNetwork,
    ...(inclusion !== undefined ? { observation_level: 'l2_block_inclusion' as const } : {}),
    receipt_status: receipt.status,
    ...(sender !== undefined ? { transaction_sender: sender } : {}),
    ...(inclusion ?? {}),
    ...(recordedTransfer !== undefined ? { token_transfer: recordedTransfer } : {}),
    expected_contract_transfer_count: transfers.length,
    matching_transfer_count: exactMatches.length,
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
 * A JSON-RPC response over this endpoint's transport failed one of the bounded-admission checks
 * below. Never carries the endpoint's own text: every message here is fixed and written by this
 * repository, so it is safe to print without going through the terminal-safe renderer, and every
 * catch site that turns this into observation state still routes it through the fixed
 * `unavailable_reason` vocabulary rather than restating it.
 */
class RpcTransportError extends Error {}

/**
 * Response size bound, enforced BEFORE any unbounded allocation, whether or not the endpoint's
 * `Content-Length` is present or accurate.
 *
 * Every call this observer makes asks for exactly one transaction's receipt, one transaction
 * object, one block header (with a bounded transaction-hash list, see `MAX_TRANSACTIONS_PER_BLOCK`
 * below), or a single quantity — never a range query or a bulk export, which are the shapes a JSON-
 * RPC endpoint response can otherwise grow without bound for. 4 MiB is far larger than any single
 * one of those objects legitimately reaches (a receipt for a transaction with a very large number
 * of logs, bounded itself by `MAX_LOGS_PER_RECEIPT`, is on the order of tens of kilobytes as JSON)
 * while still small enough that reading it into memory, then decoding and admitting it, is
 * unconditionally cheap.
 */
const MAX_RPC_RESPONSE_BYTES = 4 * 1024 * 1024;

/**
 * Read a response body up to `maxBytes`, or refuse it. Never allocates past the bound: a
 * `Content-Length` that already exceeds it is rejected before the body is read at all, and the
 * body is otherwise read incrementally so a response with no `Content-Length` (or one that
 * understates the real size) is still bounded by the running count of bytes actually received,
 * not by whatever the header claimed.
 */
async function readBoundedResponseBytes(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const declaredBytes = Number(declared);
    if (!Number.isFinite(declaredBytes) || declaredBytes < 0) {
      throw new RpcTransportError('rpc response declares an unusable content-length');
    }
    if (declaredBytes > maxBytes) {
      throw new RpcTransportError('rpc response declares a size beyond the bound');
    }
  }
  if (response.body === null) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > maxBytes) {
        throw new RpcTransportError('rpc response exceeds the size bound while streaming');
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return combined;
}

/**
 * Admit a JSON-RPC 2.0 response envelope: fatal UTF-8, strict JSON (duplicate-member rejection,
 * the declared depth bound, and I-JSON string-content validity, all via `parseStrictJson`), the
 * declared protocol version, the request id echoed back exactly, and a closed disposition — a
 * response carries `result` XOR `error`, never both and never neither. An error is never relayed:
 * an endpoint's error message can say anything, so this rejects with a fixed reason and nothing
 * from the response reaches a caller.
 */
function admitRpcEnvelope(bytes: Uint8Array, expectedId: number): unknown {
  const admitted = parseStrictJson(bytes);
  if (admitted.status !== 'parsed') {
    throw new RpcTransportError('rpc response failed strict JSON admission');
  }
  const value = admitted.value;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new RpcTransportError('rpc response is not a JSON object');
  }
  const envelope = value as Record<string, unknown>;
  if (envelope['jsonrpc'] !== '2.0') {
    throw new RpcTransportError('rpc response does not declare jsonrpc 2.0');
  }
  if (envelope['id'] !== expectedId) {
    throw new RpcTransportError('rpc response id does not match the request');
  }
  const hasResult = Object.prototype.hasOwnProperty.call(envelope, 'result');
  const hasError = Object.prototype.hasOwnProperty.call(envelope, 'error');
  if (hasResult === hasError) {
    throw new RpcTransportError('rpc response must carry exactly one of result or error');
  }
  if (hasError) {
    throw new RpcTransportError('rpc endpoint reported an error');
  }
  return envelope['result'];
}

/**
 * One JSON-RPC call, under a deadline, admitted through the bounded transport above.
 *
 * The request id is fixed at 1: calls from one source are made sequentially, never pipelined, so
 * there is nothing for the id to disambiguate; it exists so `admitRpcEnvelope` can prove the
 * response answers this request rather than trusting an object shaped like one.
 */
async function rpcCall(
  rpcUrl: string,
  method: string,
  params: readonly unknown[],
  timeoutMs: number,
): Promise<unknown> {
  const id = 1;
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new RpcTransportError(`rpc status ${response.status}`);
  const bytes = await readBoundedResponseBytes(response, MAX_RPC_RESPONSE_BYTES);
  return admitRpcEnvelope(bytes, id);
}

const hexQuantity = (value: unknown): bigint | null =>
  typeof value === 'string' && CANONICAL_QUANTITY.test(value) ? BigInt(value) : null;

/**
 * Log entries per transaction receipt, checked BEFORE any entry is read.
 *
 * This observer reads the receipt of exactly one `transferWithAuthorization` settlement call — a
 * single, non-batched contract call (see the `matching_transfer_count` doc comment above) — so its
 * realistic log count is on the order of a handful of `Transfer`/`Approval`-style events. The
 * bound here is not sized to that realistic case; it is sized to remain far above it while still
 * making an arbitrarily large or adversarial response cheap to reject: at tens of bytes per log
 * entry, ten thousand of them is a few hundred kilobytes, well inside `MAX_RPC_RESPONSE_BYTES`,
 * and rejecting outright rather than silently truncating (the prior behavior) matters because a
 * truncated list can hide a real matching transfer past the cut point, turning a genuine match
 * into a false mismatch.
 */
const MAX_LOGS_PER_RECEIPT = 10_000;

/**
 * Topics per log entry. Not a policy choice: the EVM instruction set defines `LOG0` through
 * `LOG4`, so a well-formed log carries zero to four topics and no more; there is no `LOG5`. A log
 * reporting more than four topics is not a large log, it is a malformed one, and is rejected on
 * that basis before its topics are read.
 */
const MAX_TOPICS_PER_LOG = 4;

/**
 * Transaction-hash entries in a block's transaction list, checked BEFORE any entry is read.
 *
 * Every Ethereum-family transaction carries a fixed intrinsic cost of 21,000 gas before any of its
 * own execution runs (EIP-2028 and its predecessors), so no block can contain more transactions
 * than its gas limit divided by 21,000, regardless of how high a network's gas limit is ever
 * raised. 50,000 is chosen well above that ratio even for a gas limit an order of magnitude past
 * any deployed today, so a legitimate block is never rejected by this bound; a response claiming
 * more entries than that is rejected outright rather than processed.
 */
const MAX_TRANSACTIONS_PER_BLOCK = 50_000;

/**
 * Hex characters permitted in one log's `data` field (bytes = half this count).
 *
 * `receipt.logs` here is generic — this observer reads every log on the expected contract, not
 * only `Transfer` events, so a data field of any word count must be admitted at this layer; the
 * exactly-one-ABI-word shape `Transfer` requires is `transfersOnContract`'s concern, applied after
 * admission. 1,048,576 hex characters (512 KiB of data) is already a large fraction of
 * `MAX_RPC_RESPONSE_BYTES` for a single field and far beyond any standard ERC-20 event's payload,
 * which is why it is bounded explicitly rather than left to the overall response cap alone.
 */
const MAX_LOG_DATA_HEX_CHARS = 1_048_576;

/**
 * A sealed transaction source backed by a Base JSON-RPC endpoint.
 *
 * Constructed only by the live run. Block data is queried by `eth_blockNumber` and by explicit
 * block number through `eth_getBlockByNumber`; the `pending` block tag appears nowhere in this
 * implementation, because preconfirmation state cannot establish sealed inclusion.
 *
 * Every field this observer reads off an endpoint's answer is validated against its exact grammar
 * — a 20-byte address, a 32-byte hash, a canonical quantity — before it is trusted as that kind of
 * value; a string that merely happens to be hex is not treated as an address or a hash just
 * because it looks like one, and only the minimal facts the profile needs are extracted, never an
 * arbitrary full object retained past this boundary.
 */
export function baseSealedRpcSource(rpcUrl: string, timeoutMs = 10_000): SealedTransactionSource {
  return {
    reference: publicEndpointReference(rpcUrl) ?? 'the configured Base RPC endpoint',
    async chainId(): Promise<bigint> {
      const id = hexQuantity(await rpcCall(rpcUrl, 'eth_chainId', [], timeoutMs));
      if (id === null) throw new Error('the endpoint reported no usable chain id');
      return id;
    },
    async sealedHeadBlockNumber(): Promise<bigint> {
      const head = hexQuantity(await rpcCall(rpcUrl, 'eth_blockNumber', [], timeoutMs));
      if (head === null) throw new Error('the endpoint reported no usable head block number');
      return head;
    },
    async transactionReceipt(transactionHash: string): Promise<ObservedReceipt | undefined> {
      const result = await rpcCall(rpcUrl, 'eth_getTransactionReceipt', [transactionHash], timeoutMs);
      if (result === null || result === undefined) return undefined;
      const receipt = result as {
        status?: unknown;
        blockNumber?: unknown;
        blockHash?: unknown;
        logs?: unknown;
      };
      // The status field is documented as 0x1 success and 0x0 failure; anything else is a receipt
      // this observer does not understand and refuses to reinterpret.
      const status =
        receipt.status === '0x1' ? 'success' : receipt.status === '0x0' ? 'reverted' : undefined;
      if (status === undefined) return undefined;
      if (receipt.blockHash !== undefined && receipt.blockHash !== null) {
        if (typeof receipt.blockHash !== 'string' || !HEX_HASH_32.test(receipt.blockHash)) {
          return undefined;
        }
      }
      if (receipt.logs !== undefined && !Array.isArray(receipt.logs)) return undefined;
      const rawLogs = Array.isArray(receipt.logs) ? receipt.logs : [];
      // Checked before any entry is read: a response claiming more logs than the bound is refused
      // outright, never silently truncated (see `MAX_LOGS_PER_RECEIPT`).
      if (rawLogs.length > MAX_LOGS_PER_RECEIPT) return undefined;
      const logs: ObservedLog[] = [];
      for (const raw of rawLogs) {
        const log = raw as { address?: unknown; topics?: unknown; data?: unknown };
        if (
          typeof log.address === 'string' &&
          HEX_ADDRESS.test(log.address) &&
          Array.isArray(log.topics) &&
          log.topics.length <= MAX_TOPICS_PER_LOG &&
          log.topics.every((t) => typeof t === 'string' && HEX_HASH_32.test(t)) &&
          typeof log.data === 'string' &&
          log.data.length <= MAX_LOG_DATA_HEX_CHARS + 2 && // + 2 for the '0x' prefix
          /^0x[0-9a-fA-F]*$/.test(log.data) &&
          log.data.length % 2 === 0
        ) {
          logs.push({ address: log.address, topics: log.topics as string[], data: log.data });
        }
      }
      return {
        status,
        blockNumber: hexQuantity(receipt.blockNumber),
        blockHash:
          typeof receipt.blockHash === 'string' && HEX_HASH_32.test(receipt.blockHash)
            ? receipt.blockHash
            : null,
        logs,
      };
    },
    async transactionByHash(transactionHash: string): Promise<ObservedTransaction | undefined> {
      const result = await rpcCall(rpcUrl, 'eth_getTransactionByHash', [transactionHash], timeoutMs);
      if (result === null || result === undefined) return undefined;
      const transaction = result as { from?: unknown; blockNumber?: unknown; blockHash?: unknown };
      if (typeof transaction.from !== 'string' || !HEX_ADDRESS.test(transaction.from)) {
        return undefined;
      }
      if (
        transaction.blockHash !== undefined &&
        transaction.blockHash !== null &&
        (typeof transaction.blockHash !== 'string' || !HEX_HASH_32.test(transaction.blockHash))
      ) {
        return undefined;
      }
      return {
        from: transaction.from,
        blockNumber: hexQuantity(transaction.blockNumber),
        blockHash:
          typeof transaction.blockHash === 'string' && HEX_HASH_32.test(transaction.blockHash)
            ? transaction.blockHash
            : null,
      };
    },
    async sealedBlockByNumber(blockNumber: bigint): Promise<SealedBlock | undefined> {
      // Asked with `false`, so `transactions` is the list of transaction hashes. That list is
      // parsed and retained because sealed inclusion requires the sealed block to actually
      // contain the transaction, not merely to carry the number and hash the receipt reported.
      const result = await rpcCall(
        rpcUrl,
        'eth_getBlockByNumber',
        [`0x${blockNumber.toString(16)}`, false],
        timeoutMs,
      );
      if (result === null || result === undefined) return undefined;
      const block = result as { number?: unknown; hash?: unknown; transactions?: unknown };
      const number = hexQuantity(block.number);
      if (number === null || typeof block.hash !== 'string' || !HEX_HASH_32.test(block.hash)) {
        return undefined;
      }
      if (!Array.isArray(block.transactions)) return undefined;
      // Checked before any entry is read: a block claiming more transactions than the bound is
      // refused outright (see `MAX_TRANSACTIONS_PER_BLOCK`), never silently truncated.
      if (block.transactions.length > MAX_TRANSACTIONS_PER_BLOCK) return undefined;
      const transactionHashes: string[] = [];
      for (const entry of block.transactions) {
        if (typeof entry === 'string' && HEX_HASH_32.test(entry)) transactionHashes.push(entry);
      }
      return { number, hash: block.hash, transactionHashes };
    },
  };
}
