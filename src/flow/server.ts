/**
 * The paid resource: one express endpoint behind the x402 payment middleware.
 *
 * OBSERVATION. The lifecycle is observed through the upstream hooks. `onProtectedRequest` sees the
 * request before payment processing and carries the payment field value the middleware itself
 * read; `onAfterVerify`, `onBeforeSettle`, `onAfterSettle`, `onSettleFailure`, `onVerifyFailure`
 * and `onVerifiedPaymentCanceled` report each lifecycle transition with its result. Nothing here
 * wraps, replaces or re-implements the middleware in order to watch it.
 *
 * Two facts are not exposed by any hook, and only those two are taken from the application
 * boundary instead. The field values the middleware emits on the response, `PAYMENT-REQUIRED` and
 * `PAYMENT-RESPONSE`, are read once the response has finished, through the ordinary express
 * response API, because the hooks report decoded objects while evidence binds the value that was
 * actually observed. And that a write was attempted at all is a property of the response rather
 * than of the payment, so it comes from the response `finish` event.
 *
 * The hooks are registered on a shared server instance but report per-request facts, so the
 * recorder for the request in flight is carried in asynchronous context rather than in a variable
 * that a second concurrent request would overwrite.
 *
 * STREAMING IS OUT OF SCOPE. The middleware buffers the handler's output so settlement can run
 * before the client sees anything, which is exactly what makes the "resource produced, payment not
 * settled" state observable. A streaming handler defeats that, so this reference flow serves one
 * buffered response and says so rather than appearing to support both.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { isIP, type Socket } from 'node:net';
import express, { type Express, type Request, type Response } from 'express';
import { paymentMiddlewareFromHTTPServer } from '@x402/express';
import { decodePaymentSignatureHeader } from '@x402/core/http';
import {
  x402HTTPResourceServer,
  x402ResourceServer,
  type FacilitatorClient,
  type RouteConfig,
} from '@x402/core/server';
import type { Network, PaymentPayload } from '@x402/core/types';
import {
  PAYMENT_IDENTIFIER,
  extractPaymentIdentifier,
  isPaymentIdentifierRequired,
  validatePaymentIdentifierRequirement,
} from '@x402/extensions/payment-identifier';
import {
  captureRequestComponents,
  ComponentError,
  type HttpRequestComponentsV1,
} from '../components.ts';
import { persistableFailureReason } from './failure-vocabulary.ts';
import { LifecycleRecorder, type LifecycleObservation } from './lifecycle.ts';

/** The bytes an origin handler produced, before any transfer encoding. */
export interface OriginResult {
  readonly status: number;
  readonly contentType: string;
  readonly body: Uint8Array;
}

/** What one request produced, from the origin's point of view. */
export interface RequestObservation {
  readonly method: string;
  readonly path: string;
  readonly query: string;
  readonly lifecycle: LifecycleObservation;
  /** Field values exactly as observed at the application boundary. */
  readonly observedHeaders: {
    readonly 'payment-required'?: string;
    readonly 'payment-signature'?: string;
    readonly 'payment-response'?: string;
  };
  /** The bytes the handler produced, present only when the handler ran. */
  readonly originResult?: OriginResult;
  /**
   * RFC 9421 components of this request, as the origin observed it.
   *
   * Absent only when the request target is one this profile refuses to describe, which is a
   * rejection rather than an omission: a caller must not fall back to some other identity for it.
   */
  readonly components?: HttpRequestComponentsV1;
}

export interface PaidResourceOptions {
  /** Injected rather than constructed, so an offline run can supply an in-process facilitator. */
  readonly facilitatorClient: FacilitatorClient;
  /** Registers the scheme servers on the resource server, before initialization. */
  readonly registerSchemes: (server: x402ResourceServer) => void;
  readonly network: Network;
  readonly payTo: string;
  /** Exact-scheme price, in the asset's smallest unit, with the asset named. */
  readonly price: {
    readonly asset: string;
    readonly amount: string;
    /** Scheme metadata the requirements advertise, above all the EIP-712 domain fields. */
    readonly extra?: Record<string, unknown>;
  };
  readonly method: 'GET';
  readonly path: string;
  readonly resourceUrl: string;
  readonly maxTimeoutSeconds: number;
  /** Extensions the resource declares, built with the upstream declaration APIs. */
  readonly declaredExtensions?: Record<string, unknown>;
  /** Produces the paid result. Throwing exercises the handler-threw branch. */
  readonly handler: (request: { readonly path: string; readonly query: string }) => OriginResult;
  /**
   * Maximum number of distinct payment identifiers the idempotency store holds at once.
   *
   * A first use of a new identifier is refused, before verification, once the store already
   * holds this many entries. Nothing is ever evicted to make room: eviction would let a consumed
   * identifier be reused, which is exactly the read-credential problem this store exists to close.
   */
  readonly identifierCapacity?: number;
}

/** Default value of {@link PaidResourceOptions.identifierCapacity}. */
export const DEFAULT_IDENTIFIER_CAPACITY = 1024;

export interface PaidResource {
  readonly app: Express;
  /** One entry per request that reached the protected route, in arrival order. */
  readonly observations: readonly RequestObservation[];
}

interface RequestState {
  readonly recorder: LifecycleRecorder;
  originResult?: OriginResult;
  /** The valid payment identifier this request presented, when it presented one. */
  paymentId?: string;
  /**
   * The pending operation entry this request itself created (a new identifier, or a corrected
   * attempt replacing a rejected one), when it created one. Only a request that owns a pending
   * entry ever concludes it; a request served from cache, refused, or waiting on someone else's
   * pending entry never sets this.
   */
  operation?: Extract<OperationState, { readonly kind: 'pending' }>;
}

/**
 * The EIP-3009 authorization a payload presents, normalized for comparison.
 *
 * Hex-shaped members are lower-cased so that case variants of the same bytes compare equal;
 * `value`/`validAfter`/`validBefore` are compared as the exact strings presented, since they are
 * decimal text rather than hex. Undefined when the payload does not carry a well-formed
 * authorization and signature — a payload this deformed is never allowed to bind or read an
 * identifier; it is left for the payment middleware to refuse on its own terms.
 */
interface PresentedAuthorization {
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
  readonly signature: string;
}

/** Reads and normalizes the authorization a payload presents, or undefined if it is malformed. */
function presentedAuthorization(payload: PaymentPayload): PresentedAuthorization | undefined {
  const container = (payload as { payload?: unknown }).payload;
  if (typeof container !== 'object' || container === null || Array.isArray(container)) {
    return undefined;
  }
  const record = container as Record<string, unknown>;
  const authorization = record['authorization'];
  if (typeof authorization !== 'object' || authorization === null || Array.isArray(authorization)) {
    return undefined;
  }
  const auth = authorization as Record<string, unknown>;
  const signature = record['signature'];
  const from = auth['from'];
  const to = auth['to'];
  const value = auth['value'];
  const validAfter = auth['validAfter'];
  const validBefore = auth['validBefore'];
  const nonce = auth['nonce'];
  if (
    typeof from !== 'string' ||
    typeof to !== 'string' ||
    typeof value !== 'string' ||
    typeof validAfter !== 'string' ||
    typeof validBefore !== 'string' ||
    typeof nonce !== 'string' ||
    typeof signature !== 'string' ||
    signature.length === 0
  ) {
    return undefined;
  }
  return {
    from: from.toLowerCase(),
    to: to.toLowerCase(),
    value,
    validAfter,
    validBefore,
    nonce: nonce.toLowerCase(),
    signature: signature.toLowerCase(),
  };
}

/** Whether two normalized authorizations name the same signed transfer. */
function sameAuthorization(a: PresentedAuthorization, b: PresentedAuthorization): boolean {
  return (
    a.from === b.from &&
    a.to === b.to &&
    a.value === b.value &&
    a.validAfter === b.validAfter &&
    a.validBefore === b.validBefore &&
    a.nonce === b.nonce &&
    a.signature === b.signature
  );
}

/**
 * Run-local state of one operation under a payment identifier.
 *
 * The lifetime of this store is the lifetime of the resource instance — one run of this example —
 * which is this reference's stand-in for the time-to-live window the extension's documentation
 * leaves to the application. Nothing here persists between runs: no durability, no recovery across
 * a restart, no coordination across multiple instances. Nothing here is, or replaces, a native
 * x402 artifact: the cached bytes are the origin's own produced result and the field value the
 * middleware itself emitted for the settlement that actually happened.
 *
 * An identifier passes through four states. `pending` while a request that claimed it is still
 * being processed — concurrent requests under the same identifier and authorization wait on it
 * rather than each starting their own verification and settlement. `completed` once settlement
 * actually succeeded, holding the result to serve back. `rejected` once an attempt under it ended
 * without settling for a reason that is safe to retry (nothing was submitted, or it was refused
 * outright), which releases the identifier for a corrected attempt. `uncertain` once an attempt
 * raised out of settlement rather than answering — a submission may or may not have reached the
 * network — and an `uncertain` identifier stays refused for the rest of the process's lifetime:
 * this store cannot tell a retry from a double-spend attempt, so it does neither, and reconciling
 * what actually happened is an out-of-band operation this reference does not perform.
 *
 * WHO MAY READ A CACHED RESULT. Retrieving the `completed` result requires the identifier, the same
 * normalized request fingerprint AND the same signed authorization the facilitator verified and
 * settled; the identifier alone is never enough. Within one process lifetime the captured
 * authorization is bearer-equivalent: presenting it proves possession of the artifact, not current
 * control of the wallet.
 */
type OperationState =
  | {
      readonly kind: 'pending';
      readonly fingerprint: string;
      readonly authorization: PresentedAuthorization;
      readonly done: Promise<void>;
      readonly conclude: () => void;
    }
  | {
      readonly kind: 'completed';
      readonly fingerprint: string;
      readonly authorization: PresentedAuthorization;
      readonly result: {
        readonly status: number;
        readonly contentType: string;
        readonly body: Uint8Array;
        /** The PAYMENT-RESPONSE field value emitted for the settlement that actually occurred. */
        readonly paymentResponse?: string;
      };
    }
  | { readonly kind: 'rejected'; readonly fingerprint: string }
  | { readonly kind: 'uncertain'; readonly fingerprint: string; readonly authorization: PresentedAuthorization };

/**
 * The authority this origin was actually serving on.
 *
 * Read from the socket the request arrived on, never from `Host` or an `X-Forwarded-*` value.
 * Under the direct-origin trust profile those are client-controlled, so repeating one would let a
 * caller decide what the evidence says the operation was. The socket's local address and port are
 * the origin's own, and on an ephemeral port they are the only place the real port exists.
 */
function observedAuthority(socket: Socket): string {
  const local = socket.localAddress ?? '';
  // A dual-stack socket reports an IPv4 peer in IPv4-mapped form. The listener holds the IPv4
  // address, so it is recorded as that rather than as an IPv6 literal describing the same host.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(local);
  const host = mapped?.[1] ?? local;
  const literal = isIP(host) === 6 ? `[${host}]` : host;
  return socket.localPort === undefined ? literal : `${literal}:${socket.localPort}`;
}

/**
 * Capture the request as components, or record that it could not be described.
 *
 * The scheme comes from whether the socket is a TLS socket, and the target is the origin-form
 * target exactly as received. Nothing is reassembled from an absolute URL, because a URL parser
 * normalises and the normalised operation is not the one that was requested.
 */
function captureComponents(req: Request): HttpRequestComponentsV1 | undefined {
  try {
    return captureRequestComponents({
      method: req.method,
      scheme: (req.socket as { encrypted?: boolean }).encrypted === true ? 'https' : 'http',
      authority: observedAuthority(req.socket),
      rawPathAndQuery: req.originalUrl,
      proxyTrustProfile: 'direct-origin',
    });
  } catch (error) {
    if (!(error instanceof ComponentError)) throw error;
    // A target this profile refuses is left undescribed rather than described approximately.
    return undefined;
  }
}

/** Reads a response header as a single string, which is how the x402 field values are set. */
function headerValue(res: Response, name: string): string | undefined {
  const value = res.getHeader(name);
  if (value === undefined || value === null) return undefined;
  return Array.isArray(value) ? value.join(', ') : String(value);
}

/**
 * Build the paid resource.
 *
 * The resource server is initialized here rather than lazily by the middleware, so the run order
 * is the same every time and an initialization failure surfaces at construction instead of inside
 * the first request.
 */
export async function createPaidResource(options: PaidResourceOptions): Promise<PaidResource> {
  const observations: RequestObservation[] = [];
  const perRequest = new AsyncLocalStorage<RequestState>();
  const state = (): RequestState | undefined => perRequest.getStore();

  const routeConfig: RouteConfig = {
    accepts: {
      scheme: 'exact',
      payTo: options.payTo,
      price: {
        asset: options.price.asset,
        amount: options.price.amount,
        ...(options.price.extra !== undefined ? { extra: options.price.extra } : {}),
      },
      network: options.network,
      maxTimeoutSeconds: options.maxTimeoutSeconds,
    },
    resource: options.resourceUrl,
    description: 'Reference paid resource for the payment-evidence example',
    mimeType: 'application/json',
    ...(options.declaredExtensions ? { extensions: options.declaredExtensions } : {}),
  };

  const resourceServer = new x402ResourceServer(options.facilitatorClient);
  options.registerSchemes(resourceServer);

  resourceServer
    .onAfterVerify(async (context) => {
      const recorder = state()?.recorder;
      recorder?.enter('payment_payload_received');
      if (context.result.isValid) {
        recorder?.enter('payment_verified');
        recorder?.note({ payer: context.result.payer });
      } else {
        // The facilitator's own words are never persisted. A supported machine code survives; a
        // response body, a URL or an exception message becomes the term this flow decided.
        recorder?.finish('verification_rejected', {
          failureReason: persistableFailureReason(
            context.result.invalidReason,
            'verification_rejected',
          ),
        });
      }
    })
    .onVerifyFailure(async (context) => {
      // An exception message is unbounded and remote in origin, so what is recorded is that
      // verification raised, and nothing it said.
      state()?.recorder.finish('verification_rejected', { failureReason: 'verification_exception' });
    })
    .onBeforeSettle(async () => {
      // Reaching settlement means the handler already ran and its output is buffered.
      state()?.recorder.enter('resource_executed');
    })
    .onAfterSettle(async (context) => {
      const recorder = state()?.recorder;
      if (context.result.success) {
        recorder?.enter('payment_settled');
        recorder?.note({ transaction: context.result.transaction, payer: context.result.payer });
      } else {
        recorder?.finish('settlement_failed', {
          failureReason: persistableFailureReason(context.result.errorReason, 'settlement_rejected'),
        });
      }
    })
    .onSettleFailure(async (context) => {
      state()?.recorder.finish('settlement_failed', { failureReason: 'settlement_exception' });
    })
    .onVerifiedPaymentCanceled(async (context) => {
      const recorder = state()?.recorder;
      recorder?.enter('resource_executed');
      // One state for both handler failures. Express normalizes a throw into an error response
      // before the middleware sees it, so the reason it reports does not separate them; the
      // reason it did report is recorded verbatim beside the status.
      recorder?.finish('handler_error_status', {
        cancellationReason: persistableFailureReason(context.reason, 'handler_failed'),
        ...(context.responseStatus !== undefined
          ? { responseStatus: context.responseStatus }
          : {}),
      });
    });

  const routePattern = `${options.method} ${options.path}`;
  const httpServer = new x402HTTPResourceServer(resourceServer, {
    [routePattern]: routeConfig,
  }).onProtectedRequest(async (context) => {
    const recorder = state()?.recorder;
    recorder?.enter('request_received');
    if (context.paymentHeader === undefined) recorder?.enter('payment_required');
    else recorder?.enter('payment_payload_received');
  });

  await httpServer.initialize();

  /**
   * Run-local idempotency for the payment-identifier extension, implementing the semantics its
   * documentation assigns to the resource server: the identifier binds to a normalized request
   * fingerprint on first use; overlapping requests under one identifier and one authorization
   * share a single operation, so only one of them actually verifies, executes and settles, and
   * the rest wait and then either receive its result or its refusal; a retry with the same
   * identifier, fingerprint AND authorization after a successful settlement is served the cached
   * result WITHOUT processing another payment; the same identifier with a DIFFERENT fingerprint,
   * a different authorization, or one still `uncertain` is refused with 409 and neither reuses a
   * cached result nor creates a payment; and, because the declaration here marks the identifier
   * required, a payment payload without a valid one is refused with 400 before any verification.
   *
   * The fingerprint covers what the extension's documentation names: method and route (the
   * origin-form target as received) plus the scheme, network, asset, amount and recipient this
   * resource advertises. The store's lifetime is this resource instance — one run — which stands
   * in for the documented time-to-live window; nothing persists between runs, nothing survives a
   * restart, and nothing here coordinates across multiple instances. Extraction and requirement
   * checks are the upstream extension APIs, not local reimplementations.
   *
   * See the {@link OperationState} doc comment for the four states an identifier moves through,
   * who is allowed to read back a cached result, and what "bearer-equivalent" means here.
   */
  const idempotency = new Map<string, OperationState>();
  const identifierRequired = isPaymentIdentifierRequired(
    options.declaredExtensions?.[PAYMENT_IDENTIFIER],
  );
  const identifierCapacity = options.identifierCapacity ?? DEFAULT_IDENTIFIER_CAPACITY;
  const requestFingerprint = (req: Request): string =>
    JSON.stringify([
      req.method,
      req.originalUrl,
      'exact',
      options.network,
      options.price.asset,
      options.price.amount,
      options.payTo,
    ]);

  const app = express();

  // The framework advertises itself on every response by default. It tells a caller nothing they
  // need and tells anyone watching which stack to look up, so it is turned off here rather than
  // left to a deployment to remember.
  app.disable('x-powered-by');

  // Runs before the payment middleware, so the request's recorder exists for every hook the
  // middleware fires and the finish listener is registered before anything is written. Async
  // because a request that arrives while its identifier is `pending` waits on the settlement in
  // flight; AsyncLocalStorage propagates the store across that await, and express 5 awaits a
  // rejected promise returned from a middleware rather than losing it.
  app.use(async (req: Request, res: Response, next) => {
    const requestState: RequestState = { recorder: new LifecycleRecorder() };
    await perRequest.run(requestState, async () => {
      const recorder = requestState.recorder;
      const queryIndex = req.originalUrl.indexOf('?');
      const query = queryIndex === -1 ? '?' : req.originalUrl.slice(queryIndex);
      const observedSignature = req.get('payment-signature');
      // Captured now, while the socket the request arrived on is still the one in hand.
      const components = captureComponents(req);

      // Idempotency decisions run BEFORE the finish listener is registered: a request this layer
      // answers never reaches the payment middleware, records no lifecycle, and therefore adds no
      // observation that would misdescribe how it was handled. A field value that does not decode
      // is passed through untouched — the payment middleware is the authority on refusing it, and
      // this layer must not preempt that refusal with a verdict of its own.
      if (observedSignature !== undefined) {
        let payload: PaymentPayload | undefined;
        try {
          const decoded = decodePaymentSignatureHeader(observedSignature);
          if (typeof decoded === 'object' && decoded !== null && !Array.isArray(decoded)) {
            payload = decoded as PaymentPayload;
          }
        } catch {
          // Not decodable as a payment payload; handled by the middleware's own path.
        }
        if (payload !== undefined) {
          const requirement = validatePaymentIdentifierRequirement(payload, identifierRequired);
          if (!requirement.valid) {
            // The declaration marks the identifier required, and this payload carries no valid
            // one: 400 per the extension's documented semantics, before any verification.
            res
              .status(400)
              .set('content-type', 'application/json')
              .end('{"error":"a valid payment identifier is required"}');
            return;
          }
          const paymentId = extractPaymentIdentifier(payload);
          if (paymentId !== null) {
            const fingerprint = requestFingerprint(req);
            const authorization = presentedAuthorization(payload);
            // No well-formed authorization: this layer must not bind an identifier on behalf of a
            // payload it cannot compare later. Fall through untouched; the payment middleware
            // refuses it on its own terms.
            if (authorization !== undefined) {
              for (;;) {
                const entry = idempotency.get(paymentId);
                if (entry === undefined) {
                  if (idempotency.size >= identifierCapacity) {
                    res
                      .status(503)
                      .set('content-type', 'application/json')
                      .end('{"error":"payment identifier store at capacity"}');
                    return;
                  }
                  let conclude: (() => void) | undefined;
                  const done = new Promise<void>((resolve) => {
                    conclude = resolve;
                  });
                  const pending: OperationState = {
                    kind: 'pending',
                    fingerprint,
                    authorization,
                    done,
                    conclude: conclude!,
                  };
                  idempotency.set(paymentId, pending);
                  requestState.paymentId = paymentId;
                  requestState.operation = pending;
                  break;
                }
                if (entry.fingerprint !== fingerprint) {
                  // The same identifier naming a different request must neither return an old
                  // result nor create another payment: a 409-style refusal, per the documentation.
                  res
                    .status(409)
                    .set('content-type', 'application/json')
                    .end('{"error":"this payment identifier is bound to a different request"}');
                  return;
                }
                if (entry.kind === 'pending') {
                  if (!sameAuthorization(entry.authorization, authorization)) {
                    res
                      .status(409)
                      .set('content-type', 'application/json')
                      .end(
                        '{"error":"this payment identifier is bound to a different payment authorization"}',
                      );
                    return;
                  }
                  // Same identifier, same request, same authorization as the operation already in
                  // flight: wait for it to conclude rather than starting a second verification and
                  // settlement, then re-read the map — the outcome decides what happens next.
                  await entry.done;
                  continue;
                }
                if (entry.kind === 'completed') {
                  if (sameAuthorization(entry.authorization, authorization)) {
                    // The cached result, with no payment processing. The PAYMENT-RESPONSE value
                    // repeated here is the one the middleware emitted for the settlement that
                    // actually happened.
                    if (entry.result.paymentResponse !== undefined) {
                      res.set('payment-response', entry.result.paymentResponse);
                    }
                    res
                      .status(entry.result.status)
                      .set('content-type', entry.result.contentType)
                      .end(Buffer.from(entry.result.body));
                    return;
                  }
                  res
                    .status(409)
                    .set('content-type', 'application/json')
                    .end(
                      '{"error":"this payment identifier is bound to a different payment authorization"}',
                    );
                  return;
                }
                if (entry.kind === 'rejected') {
                  // The earlier attempt ended without settling for a retry-safe reason: the
                  // identifier is released for a corrected attempt under the same fingerprint.
                  let conclude: (() => void) | undefined;
                  const done = new Promise<void>((resolve) => {
                    conclude = resolve;
                  });
                  const pending: OperationState = {
                    kind: 'pending',
                    fingerprint,
                    authorization,
                    done,
                    conclude: conclude!,
                  };
                  idempotency.set(paymentId, pending);
                  requestState.paymentId = paymentId;
                  requestState.operation = pending;
                  break;
                }
                // entry.kind === 'uncertain': an earlier attempt under this identifier raised out
                // of settlement rather than answering. Whether it reached the network is unknown,
                // so this store refuses every further attempt under it rather than guess.
                res
                  .status(409)
                  .set('content-type', 'application/json')
                  .end(
                    '{"error":"the outcome of an earlier attempt under this payment identifier is unknown; it cannot be retried in this process"}',
                  );
                return;
              }
            }
          }
        }
      }

      let concluded = false;
      /**
       * Resolves the operation this request claimed, exactly once, from whichever of `finish` or
       * `close` fires first. A request that never claimed a pending entry (served from cache,
       * refused, or one whose payload carried no identifier or authorization) has nothing to
       * conclude.
       */
      const concludeOperation = (): void => {
        if (concluded) return;
        concluded = true;
        const operation = requestState.operation;
        const paymentId = requestState.paymentId;
        if (operation === undefined || paymentId === undefined) return;
        const o = recorder.observation();
        let next: OperationState;
        if (o.states.includes('payment_settled')) {
          const produced = requestState.originResult;
          if (produced === undefined) {
            // Settlement was observed to succeed but the produced result is missing: a state this
            // flow cannot explain, so it is treated the way an unanswered settlement is.
            next = { kind: 'uncertain', fingerprint: operation.fingerprint, authorization: operation.authorization };
          } else {
            const paymentResponse = headerValue(res, 'payment-response');
            next = {
              kind: 'completed',
              fingerprint: operation.fingerprint,
              authorization: operation.authorization,
              result: {
                status: res.statusCode,
                contentType: produced.contentType,
                body: produced.body,
                ...(paymentResponse !== undefined ? { paymentResponse } : {}),
              },
            };
          }
        } else if (recorder.hasTerminalState()) {
          if (o.terminalState === 'settlement_failed' && o.failureReason === 'settlement_exception') {
            // Settlement raised rather than answering: whether it reached the network is unknown.
            next = { kind: 'uncertain', fingerprint: operation.fingerprint, authorization: operation.authorization };
          } else {
            // settlement_failed for any other reason is a refusal; verification_rejected,
            // payment_rejected_pre_verification and handler_error_status never reached settlement
            // at all; payment_required_only means no payment was presented. All are safe to retry.
            next = { kind: 'rejected', fingerprint: operation.fingerprint };
          }
        } else {
          // No observer ever reported a terminal state. A settlement may still have been
          // submitted if the handler had already run; otherwise nothing was ever at risk.
          next = o.states.includes('resource_executed')
            ? { kind: 'uncertain', fingerprint: operation.fingerprint, authorization: operation.authorization }
            : { kind: 'rejected', fingerprint: operation.fingerprint };
        }
        // Replace only if this request's own pending entry is still the one in the map: a
        // concurrent conclusion cannot happen for the same identifier (only one request ever
        // holds a given pending entry), but the check keeps this honest under any future change.
        if (idempotency.get(paymentId) === operation) {
          idempotency.set(paymentId, next);
        }
        operation.conclude();
      };

      res.on('finish', () => {
        const reached = recorder.observation();
        if (reached.states.includes('payment_settled')) {
          // Settlement succeeded and the response was written. The origin can say a write was
          // attempted; it cannot see whether the client received it.
          recorder.enter('response_prepared');
          recorder.enter('response_write_attempted');
          recorder.finish('response_write_attempted', { responseStatus: res.statusCode });
        } else if (
          !recorder.hasTerminalState() &&
          reached.states.includes('payment_payload_received') &&
          !reached.states.includes('payment_verified')
        ) {
          // MEASURED, and derived rather than reported because no hook covers it: a payment field
          // was presented, the run finished, and no verification hook ever fired, so the resource
          // server refused the payment while matching it against the advertised requirements and
          // the facilitator was never asked. Observed as a payment-required response.
          recorder.finish('payment_rejected_pre_verification', { responseStatus: res.statusCode });
        } else {
          recorder.note({ responseStatus: res.statusCode });
        }

        observations.push({
          method: req.method,
          path: req.path,
          query,
          lifecycle: recorder.observation(),
          observedHeaders: {
            ...(headerValue(res, 'payment-required') !== undefined
              ? { 'payment-required': headerValue(res, 'payment-required')! }
              : {}),
            ...(observedSignature !== undefined ? { 'payment-signature': observedSignature } : {}),
            ...(headerValue(res, 'payment-response') !== undefined
              ? { 'payment-response': headerValue(res, 'payment-response')! }
              : {}),
          },
          ...(requestState.originResult ? { originResult: requestState.originResult } : {}),
          ...(components !== undefined ? { components } : {}),
        });

        concludeOperation();
      });
      // `close` fires whenever the response ends, including after `finish`; the boolean above
      // keeps this a no-op then. It exists for the case `finish` never fires at all — the
      // connection drops mid-request — so a claimed operation is not left pending forever.
      res.on('close', () => {
        concludeOperation();
      });

      next();
    });
  });

  // `syncFacilitatorOnStart` is off because initialization already ran above; leaving it on would
  // make the first request's behaviour depend on whether initialization had completed.
  app.use(paymentMiddlewareFromHTTPServer(httpServer, undefined, undefined, false));

  app.get(options.path, (req: Request, res: Response) => {
    const queryIndex = req.originalUrl.indexOf('?');
    const result = options.handler({
      path: req.path,
      query: queryIndex === -1 ? '?' : req.originalUrl.slice(queryIndex),
    });
    const requestState = state();
    if (requestState) requestState.originResult = result;
    res.status(result.status).set('content-type', result.contentType).end(Buffer.from(result.body));
  });

  /**
   * The application's own error boundary.
   *
   * MEASURED, and it shapes what the lifecycle can distinguish: express catches a throw from a
   * route handler and turns it into an error response before the payment middleware ever sees it.
   * The middleware therefore reports a handler that threw and a handler that returned an error
   * status through the same cancellation reason, `handler_failed`, and the two are told apart by
   * the status alone. Both cancel the verified payment without settling, which is the property the
   * evidence depends on. Registering this handler keeps the failure quiet and the status
   * predictable instead of relying on the framework's default page.
   */
  app.use((_error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    res.status(500).set('content-type', 'application/json').end('{"error":"handler failed"}');
  });

  return { app, observations };
}
