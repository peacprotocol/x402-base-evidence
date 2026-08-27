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
}

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
}

/**
 * Run-local idempotency state for one payment identifier.
 *
 * The lifetime of this store is the lifetime of the resource instance — one run of this example —
 * which is this reference's stand-in for the time-to-live window the extension's documentation
 * leaves to the application. Nothing here persists between runs, and nothing here is, or replaces,
 * a native x402 artifact: the cached bytes are the origin's own produced result and the field
 * value the middleware itself emitted for the settlement that actually happened.
 */
interface IdempotencyEntry {
  /** The normalized request fingerprint the identifier was first bound to. */
  readonly fingerprint: string;
  /**
   * The result cached after a SUCCESSFUL settlement, and only then. A run that failed before
   * settlement caches nothing, so a replay of it goes through payment processing again and the
   * cache can never manufacture a settlement that did not happen.
   */
  settled?: {
    readonly status: number;
    readonly contentType: string;
    readonly body: Uint8Array;
    /** The PAYMENT-RESPONSE field value emitted for the settlement that actually occurred. */
    readonly paymentResponse?: string;
  };
}

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
   * fingerprint on first use; a retry with the same identifier and the same fingerprint after a
   * successful settlement is served the cached result WITHOUT processing another payment; the
   * same identifier with a DIFFERENT fingerprint is refused with 409 and neither reuses the
   * cached result nor creates a payment; and, because the declaration here marks the identifier
   * required, a payment payload without a valid one is refused with 400 before any verification.
   *
   * The fingerprint covers what the extension's documentation names: method and route (the
   * origin-form target as received) plus the scheme, network, asset, amount and recipient this
   * resource advertises. The store's lifetime is this resource instance — one run — which stands
   * in for the documented time-to-live window; nothing persists between runs. Extraction and
   * requirement checks are the upstream extension APIs, not local reimplementations.
   */
  const idempotency = new Map<string, IdempotencyEntry>();
  const identifierRequired = isPaymentIdentifierRequired(
    options.declaredExtensions?.[PAYMENT_IDENTIFIER],
  );
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
  // middleware fires and the finish listener is registered before anything is written.
  app.use((req: Request, res: Response, next) => {
    const requestState: RequestState = { recorder: new LifecycleRecorder() };
    perRequest.run(requestState, () => {
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
            const entry = idempotency.get(paymentId);
            if (entry === undefined) {
              // First use binds the identifier to this request's fingerprint.
              idempotency.set(paymentId, { fingerprint });
              requestState.paymentId = paymentId;
            } else if (entry.fingerprint !== fingerprint) {
              // The same identifier naming a different request must neither return the old
              // result nor create another payment: a 409-style refusal, per the documentation.
              res
                .status(409)
                .set('content-type', 'application/json')
                .end('{"error":"this payment identifier is bound to a different request"}');
              return;
            } else if (entry.settled !== undefined) {
              // Same identifier, same request, settlement already succeeded: the cached result,
              // with no payment processing. The PAYMENT-RESPONSE value repeated here is the one
              // the middleware emitted for the settlement that actually happened.
              if (entry.settled.paymentResponse !== undefined) {
                res.set('payment-response', entry.settled.paymentResponse);
              }
              res
                .status(entry.settled.status)
                .set('content-type', entry.settled.contentType)
                .end(Buffer.from(entry.settled.body));
              return;
            } else {
              // Same identifier, same request, no settled result cached: an earlier attempt did
              // not settle, so this attempt goes through payment processing normally. The cache
              // never manufactures a settlement it did not observe.
              requestState.paymentId = paymentId;
            }
          }
        }
      }

      res.on('finish', () => {
        const reached = recorder.observation();
        if (reached.states.includes('payment_settled')) {
          // Settlement succeeded and the response was written. The origin can say a write was
          // attempted; it cannot see whether the client received it.
          recorder.enter('response_prepared');
          recorder.enter('response_write_attempted');
          recorder.finish('response_write_attempted', { responseStatus: res.statusCode });
          // Cache the settled result for the payment identifier this request presented, so a
          // retry with the same identifier and the same request is served this result instead of
          // processing another payment. Only a settlement that actually succeeded reaches here.
          const paymentId = requestState.paymentId;
          const produced = requestState.originResult;
          if (paymentId !== undefined && produced !== undefined) {
            const entry = idempotency.get(paymentId);
            if (entry !== undefined && entry.settled === undefined) {
              const paymentResponse = headerValue(res, 'payment-response');
              entry.settled = {
                status: res.statusCode,
                contentType: produced.contentType,
                body: produced.body,
                ...(paymentResponse !== undefined ? { paymentResponse } : {}),
              };
            }
          }
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
