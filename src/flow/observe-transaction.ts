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
 * the transaction's reported block number and block hash are compared against sealed block data
 * queried by explicit block number, and only when the two agree does the observation carry
 * `observation_level: "l2_block_inclusion"`.
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
}

/** One sealed block, queried by explicit block number. */
export interface SealedBlock {
  readonly number: bigint;
  readonly hash: string;
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

/** A 0x-prefixed sequence of hex digits, the only shape a hex quantity or address arrives in. */
const HEX_VALUE = /^0x[0-9a-fA-F]*$/;

/**
 * Read the ERC-20 transfers on one token contract out of raw receipt logs.
 *
 * STRUCTURAL ONLY. This decodes the standard Transfer event layout: the signature topic, two
 * indexed address topics padded to 32 bytes, and the amount as the data word. It interprets
 * nothing else and validates nothing about the token, and a log that does not match the layout
 * exactly is skipped rather than guessed at.
 */
export function transfersOnContract(
  logs: readonly ObservedLog[],
  tokenContract: string,
): ObservedTokenTransfer[] {
  const transfers: ObservedTokenTransfer[] = [];
  const contract = tokenContract.toLowerCase();
  for (const log of logs) {
    if (typeof log.address !== 'string' || log.address.toLowerCase() !== contract) continue;
    if (log.topics.length !== 3 || log.topics[0] !== TRANSFER_EVENT_TOPIC) continue;
    const [, fromTopic, toTopic] = log.topics;
    if (
      fromTopic === undefined ||
      toTopic === undefined ||
      !/^0x[0-9a-fA-F]{64}$/.test(fromTopic) ||
      !/^0x[0-9a-fA-F]{64}$/.test(toTopic) ||
      !HEX_VALUE.test(log.data)
    ) {
      continue;
    }
    transfers.push({
      token_contract: log.address,
      transfer_from: `0x${fromTopic.slice(-40)}`,
      transfer_to: `0x${toTopic.slice(-40)}`,
      transfer_amount: BigInt(log.data === '0x' ? '0x0' : log.data).toString(10),
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

function isoOf(observedAtUnixSeconds: number): string {
  return new Date(observedAtUnixSeconds * 1000).toISOString();
}

/**
 * Observe one transaction through a sealed transaction source.
 *
 * This is the sealed-L2 observation sequence, in full: query the receipt and the transaction,
 * treat receipt existence as an observed fact and nothing more, query sealed block data by the
 * explicit block number the receipt reported, compare the reported number and hash against that
 * sealed data, and record `l2_block_inclusion` only when they agree. `receipt_status` is recorded
 * separately as the execution result. No step uses preconfirmation state, and no step claims L1
 * batch inclusion or L1 finality.
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

  // Sealed-block comparison. A receipt without block placement, or a sealed-block query that does
  // not answer or does not agree, leaves the observation without an inclusion level: the receipt's
  // existence has already been recorded above and is not promoted into a claim it cannot carry.
  let inclusion: { block_number: string; block_hash: string } | undefined;
  let inclusionNote = 'sealed inclusion was not established';
  if (receipt.blockNumber !== null && receipt.blockHash !== null) {
    try {
      const sealedBlock = await source.sealedBlockByNumber(receipt.blockNumber);
      const head = await source.sealedHeadBlockNumber();
      if (
        sealedBlock !== undefined &&
        sealedBlock.number === receipt.blockNumber &&
        sealedBlock.hash.toLowerCase() === receipt.blockHash.toLowerCase() &&
        receipt.blockNumber <= head
      ) {
        inclusion = {
          block_number: receipt.blockNumber.toString(10),
          block_hash: receipt.blockHash,
        };
        inclusionNote = `sealed block ${inclusion.block_number} agreed with the reported placement`;
      } else {
        inclusionNote =
          'the sealed block data queried by explicit number did not agree with the placement ' +
          'the receipt reported';
      }
    } catch {
      inclusionNote = 'sealed block data could not be queried, so no inclusion level is recorded';
    }
  } else {
    inclusionNote = 'the receipt reported no block placement, so no inclusion level is recorded';
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

/** One JSON-RPC call, under a deadline, returning `undefined` for any failure. */
async function rpcCall(
  rpcUrl: string,
  method: string,
  params: readonly unknown[],
  timeoutMs: number,
): Promise<unknown> {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`rpc status ${response.status}`);
  const body = (await response.json()) as { result?: unknown; error?: unknown };
  if (body.error !== undefined) throw new Error('rpc error');
  return body.result;
}

const hexQuantity = (value: unknown): bigint | null =>
  typeof value === 'string' && HEX_VALUE.test(value) && value.length > 2 ? BigInt(value) : null;

/**
 * A sealed transaction source backed by a Base JSON-RPC endpoint.
 *
 * Constructed only by the live run. Block data is queried by `eth_blockNumber` and by explicit
 * block number through `eth_getBlockByNumber`; the `pending` block tag appears nowhere in this
 * implementation, because preconfirmation state cannot establish sealed inclusion.
 */
export function baseSealedRpcSource(rpcUrl: string, timeoutMs = 10_000): SealedTransactionSource {
  return {
    reference: publicEndpointReference(rpcUrl) ?? 'the configured Base RPC endpoint',
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
      const logs: ObservedLog[] = [];
      if (Array.isArray(receipt.logs)) {
        for (const raw of receipt.logs.slice(0, 256)) {
          const log = raw as { address?: unknown; topics?: unknown; data?: unknown };
          if (
            typeof log.address === 'string' &&
            Array.isArray(log.topics) &&
            log.topics.every((t) => typeof t === 'string') &&
            typeof log.data === 'string'
          ) {
            logs.push({ address: log.address, topics: log.topics as string[], data: log.data });
          }
        }
      }
      return {
        status,
        blockNumber: hexQuantity(receipt.blockNumber),
        blockHash: typeof receipt.blockHash === 'string' ? receipt.blockHash : null,
        logs,
      };
    },
    async transactionByHash(transactionHash: string): Promise<ObservedTransaction | undefined> {
      const result = await rpcCall(rpcUrl, 'eth_getTransactionByHash', [transactionHash], timeoutMs);
      if (result === null || result === undefined) return undefined;
      const transaction = result as { from?: unknown };
      return typeof transaction.from === 'string' ? { from: transaction.from } : undefined;
    },
    async sealedBlockByNumber(blockNumber: bigint): Promise<SealedBlock | undefined> {
      const result = await rpcCall(
        rpcUrl,
        'eth_getBlockByNumber',
        [`0x${blockNumber.toString(16)}`, false],
        timeoutMs,
      );
      if (result === null || result === undefined) return undefined;
      const block = result as { number?: unknown; hash?: unknown };
      const number = hexQuantity(block.number);
      if (number === null || typeof block.hash !== 'string') return undefined;
      return { number, hash: block.hash };
    },
  };
}
