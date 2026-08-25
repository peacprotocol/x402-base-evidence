/**
 * The client-side scheme implementation used by the offline path.
 *
 * On a live run the client registers the upstream EVM exact scheme, which builds a real EIP-3009
 * authorization and signs it with a real key. Offline there is no key and no chain to pay on, so
 * this stands in for the wallet: it returns the fixed synthetic authorization and signature the
 * deterministic fixtures already use, through the upstream `SchemeNetworkClient` interface, so the
 * payload still travels the real client, encoder, middleware and resource-server path.
 *
 * The substitution is confined to one interface with one method. Everything the reference flow
 * claims about the lifecycle is produced by upstream code on both paths; only the origin of the
 * authorization differs, and offline it is deterministic placeholder material that authorizes no
 * transfer on any network: the signature bytes are derived from a label, not from any key.
 */
import type {
  PaymentPayloadContext,
  PaymentPayloadResult,
  PaymentRequirements,
  SchemeNetworkClient,
} from '@x402/core/types';
import { appendPaymentIdentifierToExtensions } from '@x402/extensions/payment-identifier';
import * as F from '../../fixtures/deterministic.ts';

/**
 * A wallet stand-in for the exact scheme on EVM networks.
 *
 * The payment identifier is appended with the upstream extension API rather than written by hand,
 * so the declaration the server advertised decides whether it appears and the structure is
 * whatever x402 defines rather than whatever this example assumed.
 */
export class FixtureExactWallet implements SchemeNetworkClient {
  readonly scheme = 'exact';

  /** Fixed so a repeated offline run produces identical bytes. */
  private readonly paymentId: string;

  constructor(paymentId: string = F.PAYMENT_ID) {
    this.paymentId = paymentId;
  }

  async createPaymentPayload(
    x402Version: number,
    _paymentRequirements: PaymentRequirements,
    context?: PaymentPayloadContext,
  ): Promise<PaymentPayloadResult> {
    // The upstream helper appends only when the server declared the extension, and it writes into
    // the declaration object it is given. A copy is passed so the server's own declaration is not
    // mutated by a client running in the same process.
    const declared = structuredClone(context?.extensions ?? {}) as Record<string, unknown>;
    const extensions = appendPaymentIdentifierToExtensions(declared, this.paymentId);
    return {
      x402Version,
      payload: { authorization: F.EXACT_EVM_AUTHORIZATION, signature: F.EXACT_EVM_SIGNATURE },
      ...(Object.keys(extensions).length > 0 ? { extensions } : {}),
    };
  }
}
