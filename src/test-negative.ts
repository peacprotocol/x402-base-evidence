/**
 * Rejection corpus.
 *
 * Covers request-component validation, canonicalization strictness including RFC 8785 number and
 * Unicode behaviour, strict field-value parsing, staged x402 validation and the declared bounds.
 * A binding layer that only ever sees well-formed input is untested.
 */
import { buildRequestBinding, buildOriginResultBinding, BindingError } from './binding.ts';
import { captureRequestComponents, componentsFromAbsoluteUri, ComponentError } from './components.ts';
import {
  captureObservedX402Artifact,
  requireValidX402Artifact,
  promoteToPaymentPayload,
  exceedsDecodedPayloadBound,
  HeaderParseError,
  X402ValidationError,
  X402PromotionError,
  DIAGNOSTIC_LIMITS,
  X402_LIMITS,
  type CapturedX402Artifact,
  type SchemaValidatedPaymentRequiredArtifact,
  type SchemaValidatedPaymentPayloadArtifact,
  type StructurallyCheckedSettleResponseArtifact,
} from './x402-header.ts';
import { scanForDuplicateMembers, DUPLICATE_SCAN_LIMITS } from './strict-json.ts';
import { canonicalizeIndependent, JcsError } from './jcs-independent.ts';
import { asSha256Digest } from './digest.ts';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import * as F from '../fixtures/deterministic.ts';

beginAcceptanceSuite('negative');

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};
const rejects = (name: string, fn: () => unknown, ErrType?: new (...a: any[]) => Error) => {
  try { fn(); check(name, false, 'did NOT throw'); }
  catch (e) { check(name, ErrType ? e instanceof ErrType : true, `threw ${(e as Error).constructor.name}`); }
};
const rejectsAsync = async (name: string, fn: () => Promise<unknown>, ErrType?: new (...a: any[]) => Error) => {
  try { await fn(); check(name, false, 'did NOT throw'); }
  catch (e) { check(name, ErrType ? e instanceof ErrType : true, `threw ${(e as Error).constructor.name}`); }
};
const accepts = (name: string, fn: () => unknown) => {
  try { fn(); check(name, true); } catch (e) { check(name, false, `threw ${(e as Error).message}`); }
};
const uri = (u: string) => () => componentsFromAbsoluteUri({ method: 'GET', absoluteUri: u });
const encode = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
const encodeText = (text: string) => Buffer.from(text, 'utf8').toString('base64');

const capture = (observedValue: string, name = 'payment-signature') =>
  captureObservedX402Artifact({
    name,
    observedValue,
    capturePoint: 'origin_request_after_http_parsing',
    httpVersion: '2.0',
  });

console.log('\nRejection corpus\n');
console.log('  -- authority validation --');
rejects('empty authority rejected', uri('https://:443/a'), ComponentError);
rejects('port above 65535 rejected', uri('https://example.com:99999/a'), ComponentError);
rejects('unterminated IPv6 literal rejected', uri('https://[::1/a'), ComponentError);
rejects('unbracketed IPv6 literal rejected', uri('https://::1/a'), ComponentError);
rejects('port zero rejected', uri('https://example.com:0/a'), ComponentError);
rejects('non-numeric port rejected', uri('https://example.com:80x/a'), ComponentError);
rejects('credentials rejected', uri('https://user:pass@example.com/a'), ComponentError);
rejects('non-HTTP scheme rejected', uri('ftp://example.com/a'), ComponentError);
rejects('fragment rejected', uri('https://example.com/a#f'), ComponentError);
rejects('invalid host syntax rejected', uri('https://exa mple.com/a'), ComponentError);
accepts('bracketed IPv6 accepted', uri('https://[::1]:8443/a'));
accepts('non-default port retained', uri('https://example.com:8443/a'));

console.log('\n  -- authority normalization (RFC 9421 2.2.3 -> RFC 9110 4.2.3, RFC 3986 3.2.3) --');
// The two host branches once disagreed about an explicitly EMPTY port: a reg-name authority ending
// in ':' was rejected as a dangling separator while a bracketed IPv6 literal ending in ':' had it
// silently dropped. Default-port detection also compared the port as raw TEXT, so "0443" survived as
// though it were a distinct non-default port. One rule now decides both, numerically.
const authorityOf = (scheme: string, authority: string) =>
  captureRequestComponents({
    method: 'GET', scheme, authority, rawPathAndQuery: '/a', proxyTrustProfile: 'direct-origin',
  })['@authority'];
const normalizes = (scheme: string, authority: string, expected: string) =>
  check(`${scheme} + ${authority} normalizes to ${expected}`,
    authorityOf(scheme, authority) === expected,
    (() => { try { return authorityOf(scheme, authority); } catch (e) { return `threw ${(e as Error).message}`; } })());

normalizes('https', 'EXAMPLE.test:', 'example.test');
normalizes('https', 'example.test:0443', 'example.test');
normalizes('https', 'example.test:08443', 'example.test:8443');
normalizes('https', '[::1]:', '[::1]');
normalizes('https', 'example.test:443', 'example.test');
normalizes('http', 'example.test:0080', 'example.test');
normalizes('https', 'example.test:8443', 'example.test:8443');
rejects('port zero is still rejected after numeric normalization',
  () => authorityOf('https', 'example.test:00'), ComponentError);

console.log('\n  -- plain-JavaScript callers get ComponentError, never a leaked TypeError --');
// TypeScript types do not survive into JavaScript callers. A non-string reaching `.toLowerCase()` or
// `.length` used to surface as a TypeError, which would then read as part of this module's contract.
const captureWith = (patch: Record<string, unknown>) => () =>
  captureRequestComponents({
    method: 'GET', scheme: 'https', authority: 'e.test', rawPathAndQuery: '/a',
    proxyTrustProfile: 'direct-origin', ...patch,
  } as unknown as Parameters<typeof captureRequestComponents>[0]);
rejects('a non-string scheme is a ComponentError', captureWith({ scheme: 1 }), ComponentError);
rejects('a non-string authority is a ComponentError', captureWith({ authority: {} }), ComponentError);
rejects('a non-string raw target is a ComponentError', captureWith({ rawPathAndQuery: 5 }), ComponentError);
rejects('a non-string method is a ComponentError', captureWith({ method: null }), ComponentError);

console.log('\n  -- request target --');
rejects('malformed percent-encoding in path rejected', uri('https://example.com/a%ZZ'), ComponentError);
rejects('malformed percent-encoding in query rejected', uri('https://example.com/a?x=%Z'), ComponentError);
rejects('non-origin-form target rejected',
  () => captureRequestComponents({ method: 'GET', scheme: 'https', authority: 'e.test', rawPathAndQuery: 'a/b', proxyTrustProfile: 'direct-origin' }),
  ComponentError);
rejects('control character in target rejected',
  () => captureRequestComponents({ method: 'GET', scheme: 'https', authority: 'e.test', rawPathAndQuery: '/a\nb', proxyTrustProfile: 'direct-origin' }),
  ComponentError);
rejects('oversized target rejected', uri('https://example.com/' + 'a'.repeat(9000)), ComponentError);
rejects('invalid method token rejected',
  () => componentsFromAbsoluteUri({ method: 'BAD METHOD', absoluteUri: 'https://e.test/a' }), ComponentError);

// Preservation guarantees: a normalising parser would silently alter the evidenced operation.
const q = componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://example.com/p?x=%20&y=~&b=2&a=1&k=1&k=2' });
check('percent-encoding preserved', q['@query'].includes('%20') && q['@query'].includes('~'));
check('query order preserved', q['@query'] === '?x=%20&y=~&b=2&a=1&k=1&k=2');
check('duplicate query keys preserved', (q['@query'].match(/k=/g) ?? []).length === 2);
check('lowercase method preserved verbatim',
  componentsFromAbsoluteUri({ method: 'get', absoluteUri: 'https://e.test/a' })['@method'] === 'get');
check('M-SEARCH case preserved verbatim',
  componentsFromAbsoluteUri({ method: 'M-SEARCH', absoluteUri: 'https://e.test/a' })['@method'] === 'M-SEARCH');

console.log('\n  -- constructed components reach the same invariants as capture --');
// Regression corpus for the shared component invariants. buildRequestBinding once carried its own
// weaker validation, so each of these was accepted through the builder while capture rejected it.
// They are asserted against buildRequestBinding DIRECTLY, not against capture, because the builder
// is the door that was weak.
const okComponents = captureRequestComponents({
  method: 'POST',
  scheme: 'https',
  authority: 'api.example.test',
  rawPathAndQuery: '/v1/forecast?city=zurich',
  proxyTrustProfile: 'direct-origin',
});
const bindWith = (patch: Partial<Record<string, unknown>>) => () =>
  buildRequestBinding({
    components: { ...okComponents, ...patch } as typeof okComponents,
    body: new Uint8Array(),
    selectedHeaders: [],
  });

accepts('a captured component object builds a request binding',
  bindWith({}));
rejects('an out-of-range authority port is rejected by the builder',
  bindWith({ '@authority': 'api.example.test:99999' }), BindingError);
rejects('a non-numeric authority port is rejected by the builder',
  bindWith({ '@authority': 'api.example.test:http' }), BindingError);
// The builder asserts; it never normalises. Rewriting a caller's authority behind their back would
// change the operation the evidence describes, so a noncanonical-but-normalizable authority is
// rejected here even though the CAPTURE path accepts the same text and canonicalizes it.
rejects('an empty explicit port is rejected by the builder as noncanonical',
  bindWith({ '@authority': 'api.example.test:' }), BindingError);
rejects('a leading-zero default port is rejected by the builder as noncanonical',
  bindWith({ '@authority': 'api.example.test:0443' }), BindingError);
rejects('a leading-zero non-default port is rejected by the builder as noncanonical',
  bindWith({ '@authority': 'api.example.test:08443' }), BindingError);
rejects('an explicit default port is rejected by the builder as noncanonical',
  bindWith({ '@authority': 'api.example.test:443' }), BindingError);
rejects('malformed percent-encoding in the path is rejected by the builder',
  bindWith({ '@path': '/v1/%zz' }), BindingError);
rejects('malformed percent-encoding in the query is rejected by the builder',
  bindWith({ '@query': '?city=%2' }), BindingError);
rejects('a control character in the target is rejected by the builder',
  bindWith({ '@path': '/v1/fore\u0001cast' }), BindingError);
rejects('a space in the target is rejected by the builder',
  bindWith({ '@path': '/v1/fore cast' }), BindingError);
rejects('a non-ASCII target is rejected by the builder',
  bindWith({ '@path': '/v1/z\u00fcrich' }), BindingError);
rejects('a fragment in the target is rejected by the builder',
  bindWith({ '@path': '/v1/forecast#frag' }), BindingError);
rejects('credentials in the authority are rejected by the builder',
  bindWith({ '@authority': 'user@api.example.test' }), BindingError);
rejects('an empty authority is rejected by the builder',
  bindWith({ '@authority': '' }), BindingError);
rejects('an unbracketed IPv6 authority is rejected by the builder',
  bindWith({ '@authority': '::1' }), BindingError);
rejects('a malformed IPv4 authority is rejected by the builder',
  bindWith({ '@authority': '999.1.1.1' }), BindingError);
// Not normalised behind the caller's back: a non-canonical authority is refused, never rewritten.
rejects('a non-lowercase authority is rejected rather than lowercased',
  bindWith({ '@authority': 'API.Example.Test' }), BindingError);
rejects('an explicit https default port is rejected rather than stripped',
  bindWith({ '@authority': 'api.example.test:443' }), BindingError);
rejects('a query without its leading "?" is rejected by the builder',
  bindWith({ '@query': 'city=zurich' }), BindingError);
rejects('a non-origin-form path is rejected by the builder',
  bindWith({ '@path': 'v1/forecast' }), BindingError);
rejects('an oversized request target is rejected by the builder',
  bindWith({ '@path': `/${'a'.repeat(9000)}` }), BindingError);
rejects('a foreign capturePoint is rejected by the builder',
  bindWith({ capturePoint: 'somewhere-else' }), BindingError);
rejects('a foreign proxyTrustProfile is rejected by the builder',
  bindWith({ proxyTrustProfile: 'trusted-proxy' }), BindingError);

console.log('\n  -- status and body --');
rejects('status below 100 rejected', () => buildOriginResultBinding({ status: 99, body: new Uint8Array() }), BindingError);
rejects('status above 599 rejected', () => buildOriginResultBinding({ status: 600, body: new Uint8Array() }), BindingError);
rejects('non-integer status rejected', () => buildOriginResultBinding({ status: 200.5, body: new Uint8Array() }), BindingError);
rejects('string body rejected (bytes only)',
  () => buildOriginResultBinding({ status: 200, body: 'text' as unknown as Uint8Array }), BindingError);

console.log('\n  -- field value capture --');
await rejectsAsync('a non-payment field name is rejected outright',
  () => capture('abc', 'x-random'), HeaderParseError);
await rejectsAsync('payment-identifier is an extension, not a payment field',
  () => capture('pay_0000000000000000', 'payment-identifier'), HeaderParseError);

recordExecution('X402-REJECT-008');
await rejectsAsync('a non-visible-ASCII field value is refused at capture',
  () => capture('aaé'), HeaderParseError);

recordExecution('X402-LIMIT-001');
await rejectsAsync('an encoded field value beyond the declared bound is refused',
  () => capture('A'.repeat(X402_LIMITS.maxEncodedValueBytes + 1)), HeaderParseError);

recordExecution('X402-LIMIT-002');
// Within the encoded bound this bound cannot be the first to trigger, so it is asserted directly
// rather than through a field value that cannot exist.
check('the decoded payload bound refuses anything above the declared size',
  exceedsDecodedPayloadBound(X402_LIMITS.maxDecodedPayloadBytes + 1) &&
    !exceedsDecodedPayloadBound(X402_LIMITS.maxDecodedPayloadBytes));

console.log('\n  -- staged x402 validation --');
recordExecution('X402-REJECT-001');
const anything = await capture(encode({ anything: 'at all' }));
check('an arbitrary JSON object decodes but is refused by the upstream schema',
  anything.stages.transport === 'accepted' && anything.stages.json === 'accepted' &&
    anything.stages['upstream-schema'] === 'rejected');

recordExecution('X402-STAGE-001');
check('the stage report names the exact failing stage',
  anything.diagnostics.length > 0 && anything.diagnostics.every((d) => d.stage === 'upstream-schema'),
  JSON.stringify(anything.diagnostics));
check('no stage after the failure is reported as evaluated',
  anything.stages['scheme-payload'] === 'not_evaluated' && anything.stages.extensions === 'not_evaluated');

const NETWORK = 'eip155:84532';
const requirements = {
  scheme: 'exact',
  network: NETWORK,
  asset: '0x0000000000000000000000000000000000dead',
  amount: '250000',
  payTo: F.PAY_TO,
  maxTimeoutSeconds: 60,
  extra: {},
};
const wellFormed = {
  x402Version: 2,
  resource: { url: 'https://api.example.test/v1/forecast' },
  accepted: requirements,
  payload: { authorization: F.EXACT_EVM_AUTHORIZATION, signature: F.EXACT_EVM_SIGNATURE },
};

const rejectedAtSchema = async (label: string, value: unknown) => {
  const a = await capture(encode(value));
  check(label, a.stages['upstream-schema'] === 'rejected', JSON.stringify(a.stages));
  return a;
};

recordExecution('X402-REJECT-002');
await rejectedAtSchema('a payload missing a required member is rejected',
  { x402Version: 2, resource: wellFormed.resource, payload: wellFormed.payload });

recordExecution('X402-REJECT-003');
await rejectedAtSchema('a payload with the wrong x402Version is rejected',
  { ...wellFormed, x402Version: 3 });

recordExecution('X402-REJECT-005');
await rejectedAtSchema('a payload with a malformed CAIP-2 network is rejected',
  { ...wellFormed, accepted: { ...requirements, network: 'not-caip2' } });

recordExecution('X402-REJECT-006');
await rejectedAtSchema('a well-formed v1-shaped object is rejected by the v2 schema',
  { x402Version: 1, scheme: 'exact', network: 'base-sepolia', payload: { authorization: F.EXACT_EVM_AUTHORIZATION } });

recordExecution('X402-REJECT-004');
// The upstream v2 schema types `scheme` as a free string, so an unsupported scheme passes schema
// validation and is refused by this profile's scheme-payload stage instead. Reporting it as a
// schema rejection would misattribute the verdict.
const unknownScheme = await capture(encode({
  ...wellFormed, accepted: { ...requirements, scheme: 'definitely-not-a-scheme' },
}));
check('an unsupported scheme is refused at the scheme-payload stage',
  unknownScheme.stages['upstream-schema'] === 'accepted' &&
    unknownScheme.stages['scheme-payload'] === 'rejected',
  JSON.stringify(unknownScheme.stages));
check('an unsupported scheme produces no canonical digest',
  unknownScheme.validatedObjectJcsDigest === undefined);

const wrongPayloadMember = await capture(encode({ ...wellFormed, payload: { notAnAuthorization: 1 } }));
check('a payload member that does not match the scheme is refused',
  wrongPayloadMember.stages['scheme-payload'] === 'rejected');

const malformedAuthorization = await capture(encode({
  ...wellFormed, payload: { authorization: { ...F.EXACT_EVM_AUTHORIZATION, to: 'not-a-hex-address' } },
}));
check('an authorization with a malformed address is refused at the scheme-payload stage',
  malformedAuthorization.stages['scheme-payload'] === 'rejected');

// x402 v2 section 5.2.2 marks `signature` Required for the exact scheme on EVM. The upstream v2
// schema types `payload` as an open record and the upstream `isEIP3009Payload` guard only looks for
// an `authorization` member, so a payload carrying an authorization nobody signed reaches this
// profile's scheme-payload stage still intact. It must die there.
recordExecution('X402-REJECT-009');
const missingSignature = await capture(encode({
  ...wellFormed, payload: { authorization: F.EXACT_EVM_AUTHORIZATION },
}));
check('a payload missing its required signature decodes at transport',
  missingSignature.stages.transport === 'accepted', JSON.stringify(missingSignature.stages));
check('a payload missing its required signature parses as JSON',
  missingSignature.stages.json === 'accepted', JSON.stringify(missingSignature.stages));
check('a payload missing its required signature is refused at the scheme-payload stage',
  missingSignature.stages['scheme-payload'] === 'rejected', JSON.stringify(missingSignature.stages));
check('the missing signature is diagnosed as expected_hex_signature at payload.signature',
  missingSignature.diagnostics.some((d) =>
    d.stage === 'scheme-payload' && d.code === 'expected_hex_signature' &&
    d.path.join('.') === 'payload.signature'),
  JSON.stringify(missingSignature.diagnostics));
check('a payload missing its required signature produces no canonical digest',
  missingSignature.validatedObjectJcsDigest === undefined);
rejects('a payload missing its required signature cannot be promoted',
  () => promoteToPaymentPayload(missingSignature), X402PromotionError);

recordExecution('X402-REJECT-010');
const malformedSignature = await capture(encode({
  ...wellFormed, payload: { authorization: F.EXACT_EVM_AUTHORIZATION, signature: '0xdeadbeef' },
}));
check('a payload with a malformed signature decodes at transport',
  malformedSignature.stages.transport === 'accepted', JSON.stringify(malformedSignature.stages));
check('a payload with a malformed signature parses as JSON',
  malformedSignature.stages.json === 'accepted', JSON.stringify(malformedSignature.stages));
check('a payload with a malformed signature is refused at the scheme-payload stage',
  malformedSignature.stages['scheme-payload'] === 'rejected', JSON.stringify(malformedSignature.stages));
check('the malformed signature is diagnosed as expected_hex_signature at payload.signature',
  malformedSignature.diagnostics.some((d) =>
    d.stage === 'scheme-payload' && d.code === 'expected_hex_signature' &&
    d.path.join('.') === 'payload.signature'),
  JSON.stringify(malformedSignature.diagnostics));
check('a payload with a malformed signature produces no canonical digest',
  malformedSignature.validatedObjectJcsDigest === undefined);
rejects('a payload with a malformed signature cannot be promoted',
  () => promoteToPaymentPayload(malformedSignature), X402PromotionError);

console.log('\n  -- asset transfer method: this reference implements the EIP-3009 profile only --');
recordExecution('X402-REJECT-011');
// x402 v2 exact/EVM selects the asset-transfer method through `extra.assetTransferMethod`, echoed by
// a payload at `accepted.extra.assetTransferMethod`. The pinned upstream package implements
// `eip3009` and `permit2` for this scheme; the specification also names `erc7710`. This reference
// implements EIP-3009 only.
//
// The ordering is the point. A permit2 requirement carries a `permit2Authorization` payload, but
// nothing stops a counterparty pairing a permit2 requirement with an EIP-3009-SHAPED payload. If the
// payload shape were checked first, that pair would satisfy every EIP-3009 field check and this
// profile would report an accepted scheme-payload stage for a transfer method it cannot evaluate.
const permit2Method = await capture(encode({
  ...wellFormed, accepted: { ...requirements, extra: { assetTransferMethod: 'permit2' } },
}));
check('a permit2 asset transfer method reaches an accepted upstream-schema stage',
  permit2Method.stages['upstream-schema'] === 'accepted', JSON.stringify(permit2Method.stages));
check('a permit2 asset transfer method is refused at the scheme-payload stage',
  permit2Method.stages['scheme-payload'] === 'rejected', JSON.stringify(permit2Method.stages));
check('the permit2 refusal is diagnosed as unsupported_asset_transfer_method at accepted.extra.assetTransferMethod',
  permit2Method.diagnostics.some((d) =>
    d.stage === 'scheme-payload' && d.code === 'unsupported_asset_transfer_method' &&
    d.path.join('.') === 'accepted.extra.assetTransferMethod'),
  JSON.stringify(permit2Method.diagnostics));
check('a permit2 asset transfer method produces no canonical digest',
  permit2Method.validatedObjectJcsDigest === undefined);
rejects('a permit2 asset transfer method cannot be promoted',
  () => promoteToPaymentPayload(permit2Method), X402PromotionError);

// The regression this ordering exists to prevent, stated as its own vector: the payload here is a
// COMPLETE, well-formed EIP-3009 payload. Only the declared transfer method disagrees with it.
check('a permit2 requirement paired with an EIP-3009-shaped payload does not pass scheme-payload',
  permit2Method.stages['scheme-payload'] === 'rejected' &&
    !permit2Method.diagnostics.some((d) => d.code === 'expected_eip3009_authorization'),
  JSON.stringify(permit2Method.diagnostics));

const erc7710Method = await capture(encode({
  ...wellFormed, accepted: { ...requirements, extra: { assetTransferMethod: 'erc7710' } },
}));
check('an erc7710 asset transfer method is refused at the scheme-payload stage',
  erc7710Method.stages['scheme-payload'] === 'rejected', JSON.stringify(erc7710Method.stages));
const nonStringMethod = await capture(encode({
  ...wellFormed, accepted: { ...requirements, extra: { assetTransferMethod: 3009 } },
}));
check('a non-string asset transfer method is refused at the scheme-payload stage',
  nonStringMethod.stages['scheme-payload'] === 'rejected', JSON.stringify(nonStringMethod.stages));

// The default path stays open: an absent field means EIP-3009, which this profile supports.
const absentMethod = await capture(encode({
  ...wellFormed, accepted: { ...requirements, extra: { name: 'USDC', version: '2' } },
}));
check('an absent asset transfer method is read as the eip3009 default, not as a rejection',
  absentMethod.stages['scheme-payload'] === 'accepted', JSON.stringify(absentMethod.stages));

console.log('\n  -- compile-time type-state --');
// This block exists to be TYPE-CHECKED, not to assert at runtime. `@ts-expect-error` fails `tsc` if
// the error it expects ever stops occurring, so if the brands stopped discriminating -- or if a
// promoted type were ever weakened back into something a raw capture structurally satisfies -- the
// directive would become unused and the typecheck would fail. A comment alone could not do that.
const consumesPromotedPayload = (a: SchemaValidatedPaymentPayloadArtifact) => a.decoded.accepted.scheme;
const consumesPromotedRequired = (a: SchemaValidatedPaymentRequiredArtifact) => a.decoded.x402Version;
const consumesPromotedSettle = (a: StructurallyCheckedSettleResponseArtifact) => a.decoded.success;
const rawCapture: CapturedX402Artifact = absentMethod;
const neverRuns = () => {
  // @ts-expect-error a raw CapturedX402Artifact must never satisfy the promoted payload type
  consumesPromotedPayload(rawCapture);
  // @ts-expect-error a raw CapturedX402Artifact must never satisfy the promoted required type
  consumesPromotedRequired(rawCapture);
  // @ts-expect-error a raw CapturedX402Artifact must never satisfy the promoted settle type
  consumesPromotedSettle(rawCapture);
};
check('a raw capture is not assignable where a promoted artifact is required (compile-time)',
  typeof neverRuns === 'function');
check('promotion is the only route to a promoted artifact',
  promoteToPaymentPayload(await capture(F.OBSERVED_REQUEST_HEADERS['payment-signature'])).decoded
    .accepted.scheme === F.SCHEME);

const settleWithoutTransaction = await captureObservedX402Artifact({
  name: 'payment-response',
  observedValue: encode({ success: true, network: NETWORK }),
  capturePoint: 'origin_response_before_gateway',
  httpVersion: '2.0',
});
check('a settle response missing a required member fails the local structural check',
  settleWithoutTransaction.localStructural?.localStructuralStatus === 'rejected' &&
    settleWithoutTransaction.stages['upstream-schema'] === 'not_evaluated');
check('a local structural failure is attributed to the local authority, not to x402',
  settleWithoutTransaction.diagnostics.every((d) => d.stage === 'local-structural'));

console.log('\n  -- duplicate members --');
recordExecution('X402-DUP-001');
const literalDuplicate = await capture(encodeText('{"x402Version":2,"x402Version":2}'));
check('a literal duplicate member is refused before canonicalization',
  literalDuplicate.stages['duplicate-members'] === 'rejected' &&
    literalDuplicate.stages['upstream-schema'] === 'not_evaluated' &&
    literalDuplicate.validatedObjectJcsDigest === undefined);
check('the duplicate diagnostic names the offending member',
  literalDuplicate.diagnostics[0]?.code === 'duplicate_member' &&
    literalDuplicate.diagnostics[0]?.path.at(-1) === 'x402Version');

recordExecution('X402-DUP-002');
const escapedDuplicate = await capture(encodeText('{"payer":1,"\\u0070ayer":2}'));
check('an escaped-key collision is refused before canonicalization',
  escapedDuplicate.stages['duplicate-members'] === 'rejected' &&
    escapedDuplicate.validatedObjectJcsDigest === undefined);
check('the escaped key is compared after decoding, not as source text',
  escapedDuplicate.diagnostics[0]?.path.at(-1) === 'payer');

recordExecution('X402-DUP-003');
const nestedDuplicate = await capture(encodeText('{"accepted":{"asset":"a","asset":"b"}}'));
check('a duplicate member in a nested object is refused',
  nestedDuplicate.stages['duplicate-members'] === 'rejected');
check('the nested diagnostic path reaches the offending member',
  JSON.stringify(nestedDuplicate.diagnostics[0]?.path) === JSON.stringify(['accepted', 'asset']));

check('a duplicate inside an array element is refused',
  scanForDuplicateMembers('{"a":[{"b":1,"b":2}]}').status === 'rejected');
check('an escaped surrogate pair key does not collide with an unrelated key',
  scanForDuplicateMembers('{"\\ud83d\\ude00":1,"a":2}').status === 'accepted');
check('nesting beyond the declared depth bound fails closed',
  scanForDuplicateMembers('['.repeat(DUPLICATE_SCAN_LIMITS.maxDepth + 2) + ']'.repeat(DUPLICATE_SCAN_LIMITS.maxDepth + 2)).status === 'rejected');
check('trailing content after a complete value fails closed',
  scanForDuplicateMembers('{"a":1} trailing').status === 'rejected');
check('an unterminated string fails closed', scanForDuplicateMembers('{"a":"x').status === 'rejected');
check('a well-formed nested document is accepted',
  scanForDuplicateMembers(JSON.stringify(wellFormed)).status === 'accepted');

console.log('\n  -- diagnostics bounds --');
recordExecution('X402-LIMIT-003');
const manyIssues: Record<string, unknown> = { x402Version: 2, accepted: {}, payload: {} };
for (let i = 0; i < 40; i++) manyIssues[`filler${i}`] = 'x'.repeat(200);
const bounded = await capture(encode(manyIssues));
check('diagnostics are capped at the declared issue count',
  bounded.diagnostics.length <= DIAGNOSTIC_LIMITS.maxIssues, `got ${bounded.diagnostics.length}`);
check('diagnostics stay within the declared serialized size',
  Buffer.byteLength(JSON.stringify(bounded.diagnostics), 'utf8') <= DIAGNOSTIC_LIMITS.maxSerializedBytes);
check('every diagnostic path stays within the declared depth',
  bounded.diagnostics.every((d) => d.path.length <= DIAGNOSTIC_LIMITS.maxPathDepth));
check('diagnostics retain no validator message text',
  bounded.diagnostics.every((d) => /^[a-z0-9_]{1,40}$/.test(d.code)));

const hostilePath: Record<string, unknown> = { x402Version: 2, accepted: {}, payload: {} };
hostilePath['"><script>'.padEnd(300, 'y')] = 1;
const sanitized = await capture(encode(hostilePath));
check('diagnostic path segments are sanitised and truncated',
  sanitized.diagnostics.every((d) =>
    d.path.every((p) => /^[A-Za-z0-9._-]*$/.test(p) && p.length <= DIAGNOSTIC_LIMITS.maxPathSegmentChars)));

console.log('\n  -- capture versus acceptance --');
const garbage = encodeText('{not json');
const capturedBad = await capture(garbage);
check('capture preserves an invalid artifact rather than throwing',
  capturedBad.stages.json === 'rejected' && !!capturedBad.observedValueDigest);
check('capture still records the observed bytes for invalid material',
  !!capturedBad.decodedPayloadDigest);
check('capture produces no canonical digest for invalid material',
  capturedBad.validatedObjectJcsDigest === undefined);
await rejectsAsync('acceptance refuses what capture preserved',
  () => requireValidX402Artifact({ name: 'payment-signature', observedValue: garbage, capturePoint: 'origin_request_after_http_parsing', httpVersion: '2.0' }),
  X402ValidationError);
await rejectsAsync('acceptance refuses a missing required extension',
  () => requireValidX402Artifact({ name: 'payment-response', observedValue: F.OBSERVED_RESPONSE_HEADERS['payment-response'], capturePoint: 'origin_response_before_gateway', httpVersion: '2.0', requiredExtensions: ['payment-identifier'] }),
  X402ValidationError);
rejects('promotion refuses an artifact whose stages did not complete',
  () => promoteToPaymentPayload(capturedBad as CapturedX402Artifact), X402PromotionError);
rejects('promotion refuses an artifact of the wrong type',
  () => promoteToPaymentPayload(settleWithoutTransaction as CapturedX402Artifact), X402PromotionError);

const notBase64 = await capture('not*standard*base64');
check('a value outside the standard base64 alphabet is refused at transport',
  notBase64.stages.transport === 'rejected' && notBase64.stages.json === 'not_evaluated');

recordExecution('X402-REJECT-007');
// A valid field value, tampered after encoding. Whatever the altered bytes decode to, the artifact
// must not reach acceptance, and the observed digest must differ from the untampered one.
const authentic = F.OBSERVED_REQUEST_HEADERS['payment-signature'];
const flip = (c: string) => (c === 'A' ? 'B' : 'A');
const midpoint = Math.floor(authentic.length / 2);
const tampered = authentic.slice(0, midpoint) + flip(authentic[midpoint]!) + authentic.slice(midpoint + 1);
check('the tampered value differs from the authentic one', tampered !== authentic);
const tamperedArtifact = await capture(tampered);
const authenticArtifact = await capture(authentic);
check('base64 tampered after encoding does not reach acceptance',
  tamperedArtifact.stages['upstream-schema'] !== 'accepted' ||
    tamperedArtifact.validatedObjectJcsDigest !== authenticArtifact.validatedObjectJcsDigest,
  JSON.stringify(tamperedArtifact.stages));
check('the observed digest of a tampered value differs from the authentic value',
  tamperedArtifact.observedValueDigest !== authenticArtifact.observedValueDigest);
await rejectsAsync('acceptance refuses a tampered field value',
  () => requireValidX402Artifact({ name: 'payment-signature', observedValue: tampered, capturePoint: 'origin_request_after_http_parsing', httpVersion: '2.0' }),
  X402ValidationError);

console.log('\n  -- RFC 8785 --');
rejects('lone high surrogate MUST throw', () => canonicalizeIndependent({ a: '\ud800' }), JcsError);
rejects('lone low surrogate MUST throw', () => canonicalizeIndependent({ a: '\udc00' }), JcsError);
accepts('valid surrogate pair accepted', () => canonicalizeIndependent({ a: '😀' }));
rejects('undefined member rejected, not silently dropped', () => canonicalizeIndependent({ a: 1, b: undefined }), JcsError);
rejects('bigint rejected', () => canonicalizeIndependent({ a: 1n }), JcsError);
rejects('function rejected', () => canonicalizeIndependent({ a: () => 1 }), JcsError);
rejects('symbol rejected', () => canonicalizeIndependent({ a: Symbol('s') }), JcsError);
rejects('non-plain object rejected', () => canonicalizeIndependent({ a: new Date(0) }), JcsError);
rejects('sparse array hole rejected', () => { const a = [1]; a[3] = 4; return canonicalizeIndependent(a); }, JcsError);
rejects('symbol-keyed own property rejected',
  () => canonicalizeIndependent({ a: 1, [Symbol('s')]: 2 } as never), JcsError);
rejects('cyclic structure rejected', () => { const o: any = { a: 1 }; o.self = o; return canonicalizeIndependent(o); }, JcsError);
rejects('NaN rejected', () => canonicalizeIndependent({ a: NaN }), JcsError);
rejects('Infinity rejected', () => canonicalizeIndependent({ a: Infinity }), JcsError);
// RFC 8785 serialises via ECMAScript Number::toString and does not reject large doubles.
// Precision loss happens at parse time, not canonicalization time.
check('large double serialises per ECMAScript rather than being rejected',
  canonicalizeIndependent(9007199254740993) === '9007199254740992');

// RFC 8785 number serialization samples.
for (const [input, expected] of [
  [0, '0'], [-0, '0'], [1, '1'], [-1, '-1'],
  [1e21, '1e+21'], [1e-7, '1e-7'], [1.5, '1.5'],
  [333333333.33333329, '333333333.3333333'],
  [0.000001, '0.000001'], [1e-6, '0.000001'],
] as Array<[number, string]>) {
  check(`number ${String(input)} serialises as ${expected}`,
    canonicalizeIndependent(input) === expected, `got ${canonicalizeIndependent(input)}`);
}
check('members sorted by UTF-16 code unit', canonicalizeIndependent({ b: 1, a: 2, A: 3 }) === '{"A":3,"a":2,"b":1}');
check('non-ASCII member ordering by code unit',
  canonicalizeIndependent({ 'é': 1, a: 2 }) === '{"a":2,"é":1}');
check('control characters escaped', canonicalizeIndependent({ a: '\x01' }) === '{"a":"\\u0001"}');
check('negative zero serialises as 0', canonicalizeIndependent({ a: -0 }) === '{"a":0}');

console.log('\n  -- digest representation --');
rejects('bare hex rejected', () => asSha256Digest('a'.repeat(64)));
rejects('uppercase hex rejected', () => asSha256Digest('sha256:' + 'A'.repeat(64)));
rejects('short digest rejected', () => asSha256Digest('sha256:abc'));
accepts('canonical digest accepted', () => asSha256Digest('sha256:' + 'a'.repeat(64)));

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
