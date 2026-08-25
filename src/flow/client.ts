/**
 * The paying client: request, receive the challenge, build a payment, retry.
 *
 * Every protocol step goes through the upstream client. The challenge is decoded by
 * `getPaymentRequiredResponse`, the payment is built by the registered scheme through
 * `createPaymentPayload`, the field value is produced by `encodePaymentSignatureHeader`, and the
 * outcome is read by `parsePaymentResult`. Nothing about x402 is re-implemented here; this file
 * only performs the two HTTP requests and records the field values it observed.
 *
 * The client records what it saw at its own boundary. That is a different vantage point from the
 * origin's, and the two are never merged: a value the client observed is labelled as observed by
 * the client, because only the origin can attest to what the origin emitted.
 */
import { x402Client, x402HTTPClient, type HTTPResourceResponse } from '@x402/core/client';
import type { Network, PaymentPayload, PaymentRequired } from '@x402/core/types';

export interface PaymentClientOptions {
  /** Registers the scheme clients that can pay. Offline this is the fixture wallet. */
  readonly registerSchemes: (client: x402Client) => void;
  /** Base origin, for example `http://127.0.0.1:8080`. */
  readonly baseUrl: string;
  readonly network: Network;
  /**
   * Alters the payment after the upstream client built it and before it is encoded.
   *
   * Only the acceptance cases that present terms the origin never advertised use this. It sits
   * here rather than inside a second client so that the altered payment travels the same encode,
   * send and parse path as an honest one, which is the whole point of those cases: the refusal has
   * to be the origin's decision about the payment, not an artifact of a different client.
   */
  readonly alterPayment?: (payload: PaymentPayload) => PaymentPayload;
}

/** One completed attempt to fetch a paid resource. */
export interface PaidFetchResult {
  /** The challenge the origin returned to the unpaid request. */
  readonly paymentRequired: PaymentRequired;
  /** The payment the client built and sent. */
  readonly paymentPayload: PaymentPayload;
  /** Field values as the client observed them, never presented as the origin's own record. */
  readonly observedByClient: {
    readonly 'payment-required': string;
    readonly 'payment-signature': string;
    readonly 'payment-response'?: string;
  };
  readonly unpaidStatus: number;
  readonly paidStatus: number;
  /** Response body bytes of the paid attempt, exactly as received. */
  readonly body: Uint8Array;
  /** The upstream parse of the paid response, including its payment status. */
  readonly parsed: HTTPResourceResponse;
}

export class PaymentClientError extends Error {}

/** Header reader in the shape the upstream client expects. */
function readerFor(response: globalThis.Response): (name: string) => string | null {
  return (name: string) => response.headers.get(name);
}

/**
 * Fetch a paid resource, paying if challenged.
 *
 * Only two requests are ever made: the unpaid attempt that produces the challenge, and the paid
 * retry. There is no retry loop, because a second failure is a result to record rather than a
 * condition to work around.
 */
export async function fetchPaidResource(
  options: PaymentClientOptions,
  path: string,
): Promise<PaidFetchResult> {
  const client = new x402Client();
  options.registerSchemes(client);
  const httpClient = new x402HTTPClient(client);

  const url = new URL(path, options.baseUrl).toString();

  const unpaid = await fetch(url, { method: 'GET' });
  if (unpaid.status !== 402) {
    throw new PaymentClientError(`expected a 402 challenge, observed ${unpaid.status}`);
  }
  const observedRequired = unpaid.headers.get('payment-required');
  if (observedRequired === null) {
    throw new PaymentClientError('402 response carried no payment-required field');
  }
  const unpaidBody: unknown = await unpaid.json().catch(() => undefined);
  const paymentRequired = httpClient.getPaymentRequiredResponse(readerFor(unpaid), unpaidBody);

  const built = await httpClient.createPaymentPayload(paymentRequired);
  const paymentPayload = options.alterPayment ? options.alterPayment(built) : built;
  const paymentHeaders = httpClient.encodePaymentSignatureHeader(paymentPayload);
  const observedSignature = Object.values(paymentHeaders)[0];
  if (observedSignature === undefined) {
    throw new PaymentClientError('the client produced no payment-signature field');
  }

  const paid = await fetch(url, { method: 'GET', headers: paymentHeaders });
  const body = new Uint8Array(await paid.arrayBuffer());
  const parsed = httpClient.parsePaymentResult({
    status: paid.status,
    getHeader: readerFor(paid),
    body: undefined,
  });
  const observedResponse = paid.headers.get('payment-response');

  return {
    paymentRequired,
    paymentPayload,
    observedByClient: {
      'payment-required': observedRequired,
      'payment-signature': observedSignature,
      ...(observedResponse !== null ? { 'payment-response': observedResponse } : {}),
    },
    unpaidStatus: unpaid.status,
    paidStatus: paid.status,
    body,
    parsed,
  };
}
