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
 * `unreachable`              the endpoint could not be reached at the transport level: the
 *                            connection failed, was refused, or did not answer within the deadline
 * `temporarily_unavailable`  the endpoint answered with an HTTP status this example explicitly
 *                            admits as temporary: 429 (rate limited) or 503 (service unavailable)
 * `rpc_error`                the endpoint answered with a well-formed JSON-RPC error object
 * `unusable`                 the endpoint answered, and the response is structurally unusable: an
 *                            HTTP error status outside the admitted temporary set, a body over the
 *                            response byte budget, not the JSON-RPC envelope, a malformed error
 *                            object, ambiguity about result versus error, or a result whose shape
 *                            the caller's admission rules refuse
 *
 * "Transaction not found" is deliberately NOT a failure kind: an endpoint that answers `null` for
 * a transaction query has answered, and the caller reports that as its own observed state.
 *
 * RETRYABILITY IS CLASSIFIED HERE, FAIL-CLOSED. Only `unreachable` (a transport failure) and
 * `temporarily_unavailable` (an explicitly admitted temporary HTTP status) are retryable. A
 * well-formed RPC error is terminal: no RPC error code is currently classified as temporary, and
 * an unclassified error must not be retried into meaning something it did not say. Everything
 * structurally unusable is terminal: a malformed response does not become well-formed by asking
 * again, and retrying it would only re-read the same defect.
 */
export type JsonRpcFailureKind = 'unreachable' | 'temporarily_unavailable' | 'rpc_error' | 'unusable';

/** Fixed prose per failure kind. Never text a remote party supplied. */
export const JSON_RPC_FAILURE_TEXT: Readonly<Record<JsonRpcFailureKind, string>> = {
  unreachable: 'the endpoint could not be reached or did not answer in time',
  temporarily_unavailable: 'the endpoint reported a temporary condition (rate limited or unavailable)',
  rpc_error: 'the endpoint answered with an RPC error',
  unusable: 'the endpoint response was structurally unusable',
};

/** The HTTP statuses this example admits as temporary. Fixed set; everything else fails closed. */
const TEMPORARY_HTTP_STATUSES: ReadonlySet<number> = new Set([429, 503]);

/**
 * A failed JSON-RPC exchange. The message is drawn from the fixed vocabulary above, never from the
 * response: an endpoint's own error text can embed anything, and diagnostics from this path are
 * written to terminals and persisted in run notes.
 *
 * `retryable` is derived from the kind, never supplied: transport failures and explicitly admitted
 * temporary HTTP statuses are the only conditions a caller may retry. `httpStatus` is retained only
 * for the admitted temporary statuses (a fixed safe set), and `rpcErrorCode` retains the bounded
 * integer code of a well-formed RPC error for internal classification; neither is ever persisted
 * into evidence, and no remote text accompanies them.
 */
export class JsonRpcFailure extends Error {
  readonly kind: JsonRpcFailureKind;
  readonly retryable: boolean;
  /** Present only for `temporarily_unavailable`: 429 or 503, nothing else. */
  readonly httpStatus?: number;
  /** Present only for `rpc_error`: the error object's integer `code`, retained internally. */
  readonly rpcErrorCode?: number;
  constructor(kind: JsonRpcFailureKind, detail: { httpStatus?: number; rpcErrorCode?: number } = {}) {
    super(JSON_RPC_FAILURE_TEXT[kind]);
    this.name = 'JsonRpcFailure';
    this.kind = kind;
    this.retryable = kind === 'unreachable' || kind === 'temporarily_unavailable';
    if (kind === 'temporarily_unavailable' && detail.httpStatus !== undefined) {
      this.httpStatus = detail.httpStatus;
    }
    if (kind === 'rpc_error' && detail.rpcErrorCode !== undefined) {
      this.rpcErrorCode = detail.rpcErrorCode;
    }
  }
}

/**
 * The most response bytes this example will read from one JSON-RPC exchange.
 *
 * AN IMPLEMENTATION SAFETY BOUND OF THIS EXAMPLE, NOT A BASE LIMIT. Measured generously against
 * the largest responses this example actually consumes from Base Sepolia (2026-08-27, public
 * endpoint): a latest block with hashes-only transactions was ~4 KB and a single-log transaction
 * receipt ~2 KB; a receipt at this example's own 256-log admission bound is estimated well under
 * 512 KB. The budget leaves two orders of magnitude of headroom over anything measured. A response
 * over the budget is refused whole as structurally unusable — it is never truncated into a shorter
 * response that might then parse, because a truncated body admitted as valid would be exactly the
 * kind of silent reshaping this module exists to refuse.
 */
export const MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024;

/**
 * Read a response body under the byte budget, or refuse it.
 *
 * Streams the body and stops reading the moment the running total exceeds the budget, so an
 * oversized response costs bounded memory rather than being buffered whole before the check.
 *
 * @throws JsonRpcFailure `unusable` when the body exceeds the budget.
 * @throws JsonRpcFailure `unreachable` when the stream fails mid-read (a transport failure).
 */
export async function readBodyWithinBudget(
  response: Response,
  budgetBytes: number = MAX_RPC_RESPONSE_BYTES,
): Promise<Uint8Array> {
  const body = response.body;
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    let step: ReadableStreamReadResult<Uint8Array>;
    try {
      step = await reader.read();
    } catch {
      throw new JsonRpcFailure('unreachable');
    }
    if (step.done) break;
    total += step.value.byteLength;
    if (total > budgetBytes) {
      await reader.cancel().catch(() => undefined);
      throw new JsonRpcFailure('unusable');
    }
    chunks.push(step.value);
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return joined;
}

/**
 * Admit a JSON-RPC 2.0 error member, or refuse the envelope as unusable.
 *
 * JSON-RPC 2.0 defines the error member as an object carrying an integer `code` and a string
 * `message`, with optional `data`. A response whose error member is null, an array, a scalar, or
 * an object missing either required field in its required type is not a well-formed JSON-RPC
 * error — it is a structurally unusable response, and classifying it as an RPC error would report
 * the server as having said something it did not say. Only the integer code is retained, for
 * internal retry classification; the message is validated for type and then dropped, never
 * persisted.
 *
 * @returns The bounded integer error code.
 * @throws JsonRpcFailure `unusable` when the error member is not a well-formed error object.
 */
export function admitRpcErrorObject(error: unknown): number {
  if (typeof error !== 'object' || error === null || Array.isArray(error)) {
    throw new JsonRpcFailure('unusable');
  }
  const record = error as { code?: unknown; message?: unknown };
  if (typeof record.code !== 'number' || !Number.isInteger(record.code)) {
    throw new JsonRpcFailure('unusable');
  }
  if (typeof record.message !== 'string') {
    throw new JsonRpcFailure('unusable');
  }
  // Optional `data` is deliberately ignored: whatever it holds is remote-supplied and unbounded.
  return record.code;
}

/** The request identifier every call sends, and the one the response must repeat. */
const REQUEST_ID = 1;

/**
 * One JSON-RPC exchange under a deadline, returning the envelope's `result` member.
 *
 * THROWS `JsonRpcFailure` FOR EVERY FAILURE; it never returns `undefined` to mean one. The
 * envelope is admitted strictly before the result is handed back:
 *
 *   - the connection must succeed within the deadline (`unreachable`, retryable);
 *   - an HTTP 429 or 503 is the explicitly admitted temporary set (`temporarily_unavailable`,
 *     retryable, with only the safe status code retained); any other non-success HTTP status is
 *     terminal (`unusable`) — this example does not guess which server errors are transient;
 *   - the body must fit the response byte budget (`unusable`);
 *   - the body must parse as a JSON object, not an array (`unusable`);
 *   - `jsonrpc` must be exactly `"2.0"` and `id` must repeat the request id (`unusable`);
 *   - exactly one of `result` and `error` must be present. Both present, or neither, is an
 *     ambiguity and fails closed as `unusable`. An `error` member alone is admitted against the
 *     JSON-RPC 2.0 error-object shape first: a well-formed error object is `rpc_error` (terminal,
 *     integer code retained internally, message dropped), and a malformed one is `unusable`.
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
  if (!response.ok) {
    if (TEMPORARY_HTTP_STATUSES.has(response.status)) {
      throw new JsonRpcFailure('temporarily_unavailable', { httpStatus: response.status });
    }
    // Terminal by default: a 500-class page or a 404 is not a JSON-RPC answer, and this example
    // does not retry conditions it cannot classify as temporary.
    throw new JsonRpcFailure('unusable');
  }

  const bytes = await readBodyWithinBudget(response);
  let body: unknown;
  try {
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
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
  if (hasError) {
    // The error member is admitted before it is believed: a malformed error object is a
    // structurally unusable response, not a report of an RPC error the server never validly made.
    const code = admitRpcErrorObject(envelope['error']);
    throw new JsonRpcFailure('rpc_error', { rpcErrorCode: code });
  }
  if (!hasResult) throw new JsonRpcFailure('unusable');
  return envelope['result'];
}
