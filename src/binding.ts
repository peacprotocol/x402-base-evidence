/**
 * Application-local binding documents for this example.
 *
 * NON-NORMATIVE. These structures are local to this example. They do not extend the
 * PEAC wire format, record registry, extension registry or conformance requirements, and they are
 * not a protocol surface.
 *
 * They exist because x402's offer-to-receipt matching compares resource URL, network, payer and
 * recency, and so binds payment artifacts to each other rather than to the operation requested or
 * the bytes the origin produced.
 *
 * Canonicalization and digests use the protocol helper. Digests use a single representation:
 * `sha256:<64 lowercase hex>`.
 */
import { computeJsonDocumentDigestJcs } from '@peac/protocol';
import type { JsonValue } from '@peac/kernel';
import { digestBytes, coerceDigest, type Sha256Digest } from './digest.ts';
import { assertCanonicalComponents, ComponentError, type HttpRequestComponentsV1 } from './components.ts';

/** Profile identifier, namespaced to this example so it cannot be mistaken for protocol scope. */
export const PROFILE_REQUEST_BINDING = 'org.peacprotocol.examples.payment-evidence/request-binding/1';
export const PROFILE_ORIGIN_RESULT_BINDING =
  'org.peacprotocol.examples.payment-evidence/origin-result-binding/1';

export class BindingError extends Error {}

export const LIMITS = {
  maxSelectedHeaders: 32,
  maxBodyBytes: 8 * 1024 * 1024,
} as const;

/** x402 fields whose values are security-sensitive and must never be combined or duplicated. */
const FIELD_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
/** Header field values and content metadata must not carry CR, LF or NUL. */
const NO_INJECTION = /^[^\r\n\x00]*$/;

const NEVER_COMBINE = new Set([
  'payment-required',
  'payment-signature',
  'payment-response',
  'payment-identifier',
]);

export interface PaymentEvidenceRequestBindingV1 {
  profile: typeof PROFILE_REQUEST_BINDING;
  components: HttpRequestComponentsV1;
  contentType?: string;
  contentEncoding?: string;
  bodyDigest: Sha256Digest;
  /** Ordered by field name, never by caller array order. */
  selectedHeaders: Array<{ name: string; observedValueDigest: Sha256Digest }>;
}

export interface PaymentEvidenceOriginResultBindingV1 {
  profile: typeof PROFILE_ORIGIN_RESULT_BINDING;
  status: number;
  contentType?: string;
  contentEncoding?: string;
  /**
   * Digest of the bytes the origin application supplied to its response API, before transfer
   * encoding or gateway transformation. The origin cannot observe what the client finally received;
   * a client-side digest is reported separately by that client and is not signed here.
   */
  bodyDigest: Sha256Digest;
  capturePoint: 'origin_pre_transfer_encoding';
}

/** Bodies are bytes. Accepting a string would make the digest depend on an implied encoding. */
function checkBody(body: Uint8Array): Buffer {
  if (!(body instanceof Uint8Array)) throw new BindingError('body must be a Uint8Array');
  if (body.byteLength > LIMITS.maxBodyBytes)
    throw new BindingError(`body exceeds ${LIMITS.maxBodyBytes} bytes`);
  return Buffer.from(body);
}

/**
 * Validate the component object at runtime.
 *
 * This delegates to `assertCanonicalComponents`, the single implementation of the component
 * invariants that `captureRequestComponents` also runs. This builder previously carried its own
 * weaker copy, which accepted authorities, request targets and percent-encodings that capture
 * rejected, so a caller could route around the stricter door by constructing components by hand.
 *
 * The binding layer keeps reporting `BindingError` so its own error contract is unchanged; only the
 * validation logic is shared, and the underlying diagnostic message is preserved.
 */
function assertComponents(c: HttpRequestComponentsV1): void {
  try {
    assertCanonicalComponents(c);
  } catch (e) {
    if (e instanceof ComponentError) throw new BindingError(e.message);
    throw e;
  }
}

function assertContentMeta(contentType?: string, contentEncoding?: string): void {
  for (const [label, v] of [['contentType', contentType], ['contentEncoding', contentEncoding]] as const) {
    if (v === undefined) continue;
    if (typeof v !== 'string' || !NO_INJECTION.test(v) || v.length > 256)
      throw new BindingError(`invalid ${label}`);
  }
}

export function buildRequestBinding(input: {
  components: HttpRequestComponentsV1;
  contentType?: string;
  contentEncoding?: string;
  body: Uint8Array;
  selectedHeaders: Array<{ name: string; observedValueDigest: Sha256Digest }>;
}): PaymentEvidenceRequestBindingV1 {
  assertComponents(input.components);
  assertContentMeta(input.contentType, input.contentEncoding);
  if (!Array.isArray(input.selectedHeaders)) throw new BindingError('selectedHeaders must be an array');
  for (const h of input.selectedHeaders) {
    if (!h || typeof h.name !== 'string' || !FIELD_NAME.test(h.name))
      throw new BindingError(`invalid selected header name: ${String(h?.name).slice(0, 40)}`);
    if (typeof h.observedValueDigest !== 'string' || !SHA256.test(h.observedValueDigest))
      throw new BindingError(`invalid digest for header ${h.name}`);
  }
  if (input.selectedHeaders.length > LIMITS.maxSelectedHeaders)
    throw new BindingError(`more than ${LIMITS.maxSelectedHeaders} selected headers`);

  const counts = new Map<string, number>();
  for (const h of input.selectedHeaders) counts.set(h.name, (counts.get(h.name) ?? 0) + 1);
  for (const [name, count] of counts) {
    if (count > 1) {
      throw new BindingError(
        NEVER_COMBINE.has(name)
          ? `duplicate security-sensitive field rejected: ${name}`
          : `duplicate selected field rejected: ${name}`,
      );
    }
  }

  const selectedHeaders = [...input.selectedHeaders]
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map((h) => ({ name: h.name, observedValueDigest: h.observedValueDigest }));

  return {
    profile: PROFILE_REQUEST_BINDING,
    components: input.components,
    ...(input.contentType ? { contentType: input.contentType } : {}),
    ...(input.contentEncoding ? { contentEncoding: input.contentEncoding } : {}),
    bodyDigest: digestBytes(checkBody(input.body)),
    selectedHeaders,
  };
}

export function buildOriginResultBinding(input: {
  status: number;
  contentType?: string;
  contentEncoding?: string;
  body: Uint8Array;
}): PaymentEvidenceOriginResultBindingV1 {
  assertContentMeta(input.contentType, input.contentEncoding);
  if (!Number.isInteger(input.status) || input.status < 100 || input.status > 599)
    throw new BindingError(`status out of range: ${input.status}`);
  return {
    profile: PROFILE_ORIGIN_RESULT_BINDING,
    status: input.status,
    ...(input.contentType ? { contentType: input.contentType } : {}),
    ...(input.contentEncoding ? { contentEncoding: input.contentEncoding } : {}),
    bodyDigest: digestBytes(checkBody(input.body)),
    capturePoint: 'origin_pre_transfer_encoding',
  };
}

export async function bindingDigest(
  doc: PaymentEvidenceRequestBindingV1 | PaymentEvidenceOriginResultBindingV1,
): Promise<Sha256Digest> {
  return coerceDigest(await computeJsonDocumentDigestJcs(doc as unknown as JsonValue));
}
