/**
 * Strict shapes for the JSON-RPC values this example reads, and the one envelope reader.
 *
 * NOT A GENERAL RPC LIBRARY. This module exists so the handful of RPC reads this example performs
 * admit exactly the value shapes EIP-1474 defines, instead of whatever a lenient regex happens to
 * accept. It carries no method table, no client state and no retry policy; callers own those.
 *
 * QUANTITY AND DATA ARE DIFFERENT TYPES. EIP-1474 encodes a Quantity (a number: chain ids, block
 * numbers, counters) as `0x` followed by the shortest hex form with no leading zeroes, `0x0` for
 * zero. It encodes Data (a byte string: hashes, addresses, ABI words, log payloads) as `0x`
 * followed by two hex digits per byte, leading zero bytes intact. `0x0400` is a malformed Quantity
 * and a well-formed two-byte Data value; the result of `eth_call` against `balanceOf(address)` is
 * a 32-byte ABI Data word, not a Quantity, and reading it with a Quantity rule admits values the
 * type forbids while refusing values it requires. Every admission below is therefore chosen by the
 * actual RPC type of the field being read, never by what a value happens to look like.
 *
 * NOTHING IS NORMALIZED INTO VALIDITY. A malformed value is refused where it is read. It is never
 * trimmed, padded, lower-cased into shape, or silently dropped from a list it belongs to.
 */

/** EIP-1474 Quantity: `0x0`, or `0x` then hex with no leading zero digit. Rejects `0x00`, `0x01`. */
export const RPC_QUANTITY = /^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/;

/** EIP-1474 Data: `0x` then an even number of hex digits, zero bytes included. `0x` is empty Data. */
export const RPC_DATA = /^0x(?:[0-9a-fA-F]{2})*$/;

/** Exactly 32 bytes of Data: a transaction hash, a block hash, or a log topic. */
export const HASH32 = /^0x[0-9a-fA-F]{64}$/;

/** Exactly 20 bytes of Data: an EVM address. */
export const ADDRESS20 = /^0x[0-9a-fA-F]{40}$/;

/** Exactly one 32-byte ABI word: the `eth_call` result shape of a `uint256` return value. */
export const ABI_UINT256_DATA = /^0x[0-9a-fA-F]{64}$/;

/** Parse an EIP-1474 Quantity, or refuse it. Never accepts a leading-zero encoding. */
export function admitRpcQuantity(value: unknown): bigint | undefined {
  if (typeof value !== 'string' || !RPC_QUANTITY.test(value)) return undefined;
  return BigInt(value);
}

/** Parse a 32-byte ABI `uint256` word, the `balanceOf` result shape, or refuse it. */
export function admitAbiUint256Word(value: unknown): bigint | undefined {
  if (typeof value !== 'string' || !ABI_UINT256_DATA.test(value)) return undefined;
  return BigInt(value);
}

/**
 * How one JSON-RPC exchange failed, in a bounded vocabulary.
 *
 * `unreachable`  the endpoint could not be reached, refused the HTTP exchange, or did not answer
 *                within the deadline
 * `rpc_error`    the endpoint answered with a JSON-RPC error object
 * `unusable`     the endpoint answered, and the response is structurally unusable: not the JSON-RPC
 *                envelope, ambiguous about result versus error, or carrying a result whose shape
 *                the caller's admission rules refuse
 *
 * "Transaction not found" is deliberately NOT a failure kind: an endpoint that answers `null` for
 * a transaction query has answered, and the caller reports that as its own observed state.
 */
export type JsonRpcFailureKind = 'unreachable' | 'rpc_error' | 'unusable';

/** Fixed prose per failure kind. Never text a remote party supplied. */
export const JSON_RPC_FAILURE_TEXT: Readonly<Record<JsonRpcFailureKind, string>> = {
  unreachable: 'the endpoint could not be reached or did not answer in time',
  rpc_error: 'the endpoint answered with an RPC error',
  unusable: 'the endpoint response was structurally unusable',
};

/**
 * A failed JSON-RPC exchange. The message is drawn from the fixed vocabulary above, never from the
 * response: an endpoint's own error text can embed anything, and diagnostics from this path are
 * written to terminals and persisted in run notes.
 */
export class JsonRpcFailure extends Error {
  readonly kind: JsonRpcFailureKind;
  constructor(kind: JsonRpcFailureKind) {
    super(JSON_RPC_FAILURE_TEXT[kind]);
    this.name = 'JsonRpcFailure';
    this.kind = kind;
  }
}

/** The request identifier every call sends, and the one the response must repeat. */
const REQUEST_ID = 1;

/**
 * One JSON-RPC exchange under a deadline, returning the envelope's `result` member.
 *
 * THROWS `JsonRpcFailure` FOR EVERY FAILURE; it never returns `undefined` to mean one. The
 * envelope is admitted strictly before the result is handed back:
 *
 *   - the HTTP exchange must complete with a success status within the deadline (`unreachable`);
 *   - the body must parse as a JSON object, not an array (`unusable`);
 *   - `jsonrpc` must be exactly `"2.0"` and `id` must repeat the request id (`unusable`);
 *   - exactly one of `result` and `error` must be present. An `error` member alone is `rpc_error`;
 *     both present, or neither, is an ambiguity and fails closed as `unusable`.
 *
 * A `result` of `null` is returned as `null`: for the transaction queries this example makes, that
 * is the endpoint's well-formed way of answering "not found", and it is the CALLER's fact to
 * report. A non-null result whose shape the caller then refuses is a structurally unusable
 * response, not a not-found, and callers must refuse it as such rather than degrade it.
 */
export async function jsonRpcRequest(
  rpcUrl: string,
  method: string,
  params: readonly unknown[],
  timeoutMs: number,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: REQUEST_ID, method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    throw new JsonRpcFailure('unreachable');
  }
  if (!response.ok) throw new JsonRpcFailure('unreachable');

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new JsonRpcFailure('unusable');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new JsonRpcFailure('unusable');
  }
  const envelope = body as Record<string, unknown>;
  if (envelope['jsonrpc'] !== '2.0') throw new JsonRpcFailure('unusable');
  if (envelope['id'] !== REQUEST_ID) throw new JsonRpcFailure('unusable');

  const hasResult = Object.hasOwn(envelope, 'result');
  const hasError = Object.hasOwn(envelope, 'error');
  // Exactly one of the two, per JSON-RPC 2.0. A response carrying both members, whatever their
  // values, is ambiguous about what it is asserting, and an ambiguous answer is refused rather
  // than resolved by guessing which member the server meant.
  if (hasError && hasResult) throw new JsonRpcFailure('unusable');
  if (hasError) throw new JsonRpcFailure('rpc_error');
  if (!hasResult) throw new JsonRpcFailure('unusable');
  return envelope['result'];
}
