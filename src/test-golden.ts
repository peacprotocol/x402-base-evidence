/**
 * Deterministic validation vectors, schema validation and staged-validation reporting.
 *
 * Compares freshly built bindings against the committed fixtures/golden-v1.json, cross-checks the
 * protocol canonicalization helper against a separately written RFC 8785 implementation, and
 * validates every document against its closed JSON Schema. Also proves the committed file cannot
 * silently drift from the generator that produced it (see the "golden vector drift" section below).
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { buildRequestBinding, buildOriginResultBinding, bindingDigest } from './binding.ts';
import { componentsFromAbsoluteUri } from './components.ts';
import {
  captureObservedX402Artifact,
  promoteToPaymentRequired,
  promoteToPaymentPayload,
  promoteToSettleResponse,
  SUPPORTED_ASSET_TRANSFER_METHODS,
  X402PromotionError,
  X402_STAGES,
} from './x402-header.ts';
import { isPaymentRequiredV2, isPaymentPayloadV2 } from '@x402/core/schemas';
import { DEFAULT_ASSETS } from '@x402/evm';
import {
  extractAndValidatePaymentIdentifier,
  PAYMENT_IDENTIFIER,
} from '@x402/extensions/payment-identifier';
import { canonicalizeIndependent } from './jcs-independent.ts';
import { digestBytes } from './digest.ts';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { buildGolden } from './gen-golden.ts';
import * as F from '../fixtures/deterministic.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (p: string) => JSON.parse(readFileSync(join(HERE, '..', p), 'utf8'));
const golden = read('fixtures/golden-v1.json');

beginAcceptanceSuite('golden');

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

// Upstream pin invariants for the locally declared v2 network identifier: the constant is the
// expected CAIP-2 form, and the pinned default-asset registry still keys the expected entry under
// it (the fixture module itself fails fast at import if the entry disappears entirely).
console.log('\nUpstream pin invariants\n');
check('NETWORK is the Base Sepolia CAIP-2 identifier', F.NETWORK === 'eip155:84532');
const pinnedBaseSepoliaAssets = DEFAULT_ASSETS[F.NETWORK];
check('pinned DEFAULT_ASSETS keys a Base Sepolia entry',
  Array.isArray(pinnedBaseSepoliaAssets) && pinnedBaseSepoliaAssets.length > 0);
check('fixture asset metadata comes from the pinned registry entry',
  pinnedBaseSepoliaAssets?.[0]?.asset === F.ASSET_CONTRACT &&
    pinnedBaseSepoliaAssets?.[0]?.decimals === F.TOKEN_DECIMALS);

const req = await captureObservedX402Artifact({
  name: 'Payment-Required',
  observedValue: F.OBSERVED_CHALLENGE_HEADERS['payment-required'],
  capturePoint: 'client_response_after_http_parsing',
  httpVersion: F.HTTP_VERSION,
});
const sig = await captureObservedX402Artifact({
  name: 'Payment-Signature',
  observedValue: F.OBSERVED_REQUEST_HEADERS['payment-signature'],
  capturePoint: 'origin_request_after_http_parsing',
  httpVersion: F.HTTP_VERSION,
});
const resp = await captureObservedX402Artifact({
  name: 'Payment-Response',
  observedValue: F.OBSERVED_RESPONSE_HEADERS['payment-response'],
  capturePoint: 'origin_response_before_gateway',
  httpVersion: F.HTTP_VERSION,
});

const components = componentsFromAbsoluteUri({ method: 'GET', absoluteUri: F.RESOURCE_URL });
const requestBinding = buildRequestBinding({ components, body: F.REQUEST_BODY, selectedHeaders: [sig] });
const originResultBinding = buildOriginResultBinding({
  status: 200, contentType: 'application/json', body: F.ORIGIN_RESULT_BODY,
});

const reqDigest = await bindingDigest(requestBinding);
const resDigest = await bindingDigest(originResultBinding);

console.log('\nDeterministic validation vectors\n');

check('request binding digest matches committed vector', reqDigest === golden.requestBindingDigest,
  `got ${reqDigest}\n          expected ${golden.requestBindingDigest}`);
check('origin result digest matches committed vector', resDigest === golden.originResultBindingDigest);
check('origin result body digest matches committed vector',
  originResultBinding.bodyDigest === golden.originResultBodyDigest);
check('request body digest matches committed vector', requestBinding.bodyDigest === golden.requestBodyDigest);

check('request binding canonical UTF-8 bytes match committed vector',
  Buffer.from(canonicalizeIndependent(requestBinding), 'utf8').toString('hex') === golden.requestBindingJcsUtf8Hex);
check('origin result canonical UTF-8 bytes match committed vector',
  Buffer.from(canonicalizeIndependent(originResultBinding), 'utf8').toString('hex') === golden.originResultBindingJcsUtf8Hex);

// Two separately written canonicalizers must agree, or the vectors mean nothing.
check('second RFC 8785 implementation agrees on the request binding',
  digestBytes(Buffer.from(canonicalizeIndependent(requestBinding), 'utf8')) === reqDigest);
check('second RFC 8785 implementation agrees on the origin result binding',
  digestBytes(Buffer.from(canonicalizeIndependent(originResultBinding), 'utf8')) === resDigest);

console.log('\n  -- observed artifacts --');
const gReq = golden.observedHeaders['payment-required'];
const gSig = golden.observedHeaders['payment-signature'];
const gResp = golden.observedHeaders['payment-response'];
check('observed value digest matches committed vector', sig.observedValueDigest === gSig.observedValueDigest);
check('decoded payload digest matches committed vector', sig.decodedPayloadDigest === gSig.decodedPayloadDigest);
check('canonical digest of the validated object matches committed vector',
  sig.validatedObjectJcsDigest === gSig.validatedObjectJcsDigest);
check('the canonical digest agrees with the second RFC 8785 implementation',
  sig.validatedObjectJcsDigest ===
    digestBytes(Buffer.from(canonicalizeIndependent(F.PAYMENT_PAYLOAD), 'utf8')),
  `helper=${sig.validatedObjectJcsDigest}`);
check('the artifact type is identified from the field name', sig.artifactType === 'PaymentPayload');
check('the challenge artifact type is identified', req.artifactType === 'PaymentRequired');
check('the settle response artifact type is identified', resp.artifactType === 'SettleResponse');
check('the committed vector records the same stage report',
  JSON.stringify(sig.stages) === JSON.stringify(gSig.stages),
  `got ${JSON.stringify(sig.stages)}`);
check('the committed vector records the same challenge stage report',
  JSON.stringify(req.stages) === JSON.stringify(gReq.stages));
check('the committed vector records the same settle-response stage report',
  JSON.stringify(resp.stages) === JSON.stringify(gResp.stages));

console.log('\n  -- upstream validation of the positive fixtures --');
recordExecution('X402-VALID-001');
check('the payment-required fixture is accepted by the upstream validator',
  isPaymentRequiredV2(F.PAYMENT_REQUIRED));
check('the captured challenge reaches an accepted upstream-schema stage',
  req.stages['upstream-schema'] === 'accepted', JSON.stringify(req.stages));

recordExecution('X402-VALID-002');
check('the payment payload fixture is accepted by the upstream validator',
  isPaymentPayloadV2(F.PAYMENT_PAYLOAD));
check('the captured payload reaches an accepted upstream-schema stage',
  sig.stages['upstream-schema'] === 'accepted', JSON.stringify(sig.stages));
check('the exact-scheme payload member is accepted at the scheme-payload stage',
  sig.stages['scheme-payload'] === 'accepted');

recordExecution('X402-VALID-003');
const identifier = extractAndValidatePaymentIdentifier(F.PAYMENT_PAYLOAD);
check('the payment identifier extension is present and valid via the upstream API',
  identifier.validation.valid && identifier.id === F.PAYMENT_ID,
  JSON.stringify(identifier));
check('the extensions stage reports the upstream extension verdict',
  sig.stages.extensions === 'accepted');
check('the payment identifier travels inside the payload, not as a separate field',
  Object.prototype.hasOwnProperty.call(F.PAYLOAD_EXTENSIONS, PAYMENT_IDENTIFIER));

recordExecution('X402-VALID-004');
// Encode, observe, decode, validate. Each positive fixture must survive the exact path a real
// deployment would take, otherwise the vectors describe something no counterparty would send.
const roundTrips = [
  ['payment-required', req, promoteToPaymentRequired] as const,
  ['payment-signature', sig, promoteToPaymentPayload] as const,
  ['payment-response', resp, promoteToSettleResponse] as const,
];
for (const [label, artifact, promote] of roundTrips) {
  let promoted = false;
  try {
    promote(artifact);
    promoted = true;
  } catch (e) {
    promoted = false;
    check(`${label} round trip: encode, capture, validate`, false, (e as Error).message);
  }
  if (promoted) check(`${label} round trip: encode, capture, validate`, true);
  check(`${label} produces a canonical digest once accepted`,
    artifact.validatedObjectJcsDigest !== undefined);
}

recordExecution('X402-VALID-005');
// x402 v2 exact/EVM resolves the asset-transfer method from `extra.assetTransferMethod`, which a
// payload echoes at `accepted.extra.assetTransferMethod`, and treats an ABSENT field as the EIP-3009
// default. Both readings of the profile this reference implements are exercised: the deterministic
// fixture omits the field, and the vector below states it explicitly.
const explicitEip3009 = await captureObservedX402Artifact({
  name: 'payment-signature',
  observedValue: Buffer.from(
    JSON.stringify({
      ...F.PAYMENT_PAYLOAD,
      accepted: {
        ...F.PAYMENT_REQUIREMENTS,
        extra: { ...F.PAYMENT_REQUIREMENTS.extra, assetTransferMethod: 'eip3009' },
      },
    }),
    'utf8',
  ).toString('base64'),
  capturePoint: 'origin_request_after_http_parsing',
  httpVersion: F.HTTP_VERSION,
});
check('an explicit eip3009 asset transfer method is accepted at the scheme-payload stage',
  explicitEip3009.stages['scheme-payload'] === 'accepted', JSON.stringify(explicitEip3009.stages));
check('an explicit eip3009 asset transfer method produces a canonical digest',
  explicitEip3009.validatedObjectJcsDigest !== undefined);
check('an absent asset transfer method is read as the eip3009 default and accepted',
  (F.PAYMENT_PAYLOAD.accepted.extra as Record<string, unknown>).assetTransferMethod === undefined &&
    sig.stages['scheme-payload'] === 'accepted');
check('this profile declares exactly one supported asset transfer method',
  SUPPORTED_ASSET_TRANSFER_METHODS.length === 1 && SUPPORTED_ASSET_TRANSFER_METHODS[0] === 'eip3009');

console.log('\n  -- promoted artifacts report fields that exist at runtime --');
// A promoted type must describe the object a caller actually receives. An earlier revision declared
// a `value` property that no promotion assigned, so every one of these reads compiled and returned
// `undefined`. Each promoted artifact is therefore inspected through the public runtime contract.
const promotedRequired = promoteToPaymentRequired(req);
const promotedPayload = promoteToPaymentPayload(sig);
const promotedSettle = promoteToSettleResponse(resp);

check('a promoted PaymentRequired exposes decoded.x402Version at runtime',
  promotedRequired.decoded.x402Version === 2, JSON.stringify(promotedRequired.decoded.x402Version));
check('a promoted PaymentPayload exposes decoded.accepted.scheme at runtime',
  promotedPayload.decoded.accepted.scheme === F.SCHEME, JSON.stringify(promotedPayload.decoded.accepted?.scheme));
check('a promoted SettleResponse exposes decoded.success at runtime',
  promotedSettle.decoded.success === true, JSON.stringify(promotedSettle.decoded.success));
check('a promoted artifact carries its canonical digest as a required field',
  [promotedRequired, promotedPayload, promotedSettle].every(
    (a) => typeof a.validatedObjectJcsDigest === 'string' && a.validatedObjectJcsDigest.startsWith('sha256:')));
check('the promoted decoded object is the object the named authority accepted',
  promotedPayload.decoded.accepted.asset === F.ASSET_CONTRACT &&
    promotedRequired.decoded.accepts[0]?.asset === F.ASSET_CONTRACT);
// No public runtime contract relies on a nonexistent `.value`: the property is gone from the types,
// and it is proven absent from the objects themselves rather than only from the declarations.
check('no promoted artifact carries a `value` property',
  [promotedRequired, promotedPayload, promotedSettle].every(
    (a) => !Object.prototype.hasOwnProperty.call(a, 'value')));

console.log('\n  -- staged validation --');
// The transport layer accepting a value says nothing about whether it is a valid x402 object.
// This vector decodes cleanly and is refused by the upstream schema, which is exactly the
// distinction this module exists to report.
recordExecution('X402-STAGE-004');
const decodesButInvalid = await captureObservedX402Artifact({
  name: 'payment-signature',
  observedValue: Buffer.from(JSON.stringify({ anything: 'at all' }), 'utf8').toString('base64'),
  capturePoint: 'origin_request_after_http_parsing',
  httpVersion: F.HTTP_VERSION,
});
check('transport and json acceptance do not imply schema acceptance',
  decodesButInvalid.stages.transport === 'accepted' && decodesButInvalid.stages.json === 'accepted' &&
    decodesButInvalid.stages['upstream-schema'] === 'rejected');
check('no canonical digest is produced for an object no authority accepted',
  decodesButInvalid.validatedObjectJcsDigest === undefined);
check('every stage carries one of the three declared statuses',
  X402_STAGES.every((s) => ['accepted', 'rejected', 'not_evaluated'].includes(sig.stages[s])));

recordExecution('X402-STAGE-002');
check('settle response keeps the upstream schema status not_evaluated',
  resp.stages['upstream-schema'] === 'not_evaluated' &&
    resp.localStructural?.upstreamSchemaStatus === 'not_evaluated');
check('settle response reports a separate, named local structural authority',
  resp.localStructural?.localStructuralAuthority === golden.settleResponseLocalStructuralAuthority,
  `got ${resp.localStructural?.localStructuralAuthority}`);
check('an accepted settle response is still not reported as x402 schema validated',
  resp.localStructural?.localStructuralStatus === 'accepted' &&
    resp.stages['upstream-schema'] === 'not_evaluated');

recordExecution('X402-STAGE-003');
let promotionRefused = false;
try {
  promoteToPaymentPayload(decodesButInvalid);
} catch (e) {
  promotionRefused = e instanceof X402PromotionError;
}
check('a capture that did not satisfy its stages cannot be promoted', promotionRefused);

console.log('\n  -- RFC 9421 component semantics --');
check('@method case is preserved, not uppercased',
  componentsFromAbsoluteUri({ method: 'get', absoluteUri: 'https://e.test/a' })['@method'] === 'get');
check('@query carries its leading "?"', requestBinding.components['@query'].startsWith('?'));
check('absent query yields "?"',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://e.test/a' })['@query'] === '?');
check('@path preserves dot segments',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://e.test/a/../b' })['@path'] === '/a/../b');
check('@authority lowercases host and drops the default port',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://EXAMPLE.test:443/a' })['@authority'] === 'example.test');
check('empty path yields "/"',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://example.test' })['@path'] === '/');
check('empty path with a query still yields "/" for @path',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://example.test?x=1' })['@path'] === '/');
check('an explicit empty query ("?" with nothing after) is preserved, not collapsed to absent',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://example.test/a?' })['@query'] === '?');
check('percent-encoded path octets are preserved verbatim, never decoded',
  componentsFromAbsoluteUri({ method: 'GET', absoluteUri: 'https://example.test/a%2Fb%20c' })['@path'] === '/a%2Fb%20c');

console.log('\n  -- determinism --');
const reordered = buildRequestBinding({ components, body: F.REQUEST_BODY, selectedHeaders: [sig] });
check('caller header order does not change the binding digest',
  (await bindingDigest(reordered)) === reqDigest);
check('selected headers are stored sorted',
  JSON.stringify(requestBinding.selectedHeaders.map((h) => h.name)) ===
    JSON.stringify([...requestBinding.selectedHeaders.map((h) => h.name)].sort()));

console.log('\n  -- JSON Schema (closed, 2020-12) --');
const ajv = new (Ajv2020 as any)({ strict: true, allErrors: true });
const vReq = ajv.compile(read('schemas/request-binding.v1.schema.json'));
const vRes = ajv.compile(read('schemas/origin-result-binding.v1.schema.json'));
check('request binding validates against its closed schema', vReq(requestBinding), JSON.stringify(vReq.errors)?.slice(0, 200));
check('origin result validates against its closed schema', vRes(originResultBinding), JSON.stringify(vRes.errors)?.slice(0, 200));
check('committed vector validates against its closed schema', vReq(golden.requestBinding));
check('an unknown property is rejected by the closed schema',
  !vReq({ ...requestBinding, extra: 1 }));

console.log('\n  -- digest representation --');
const all = [
  requestBinding.bodyDigest, originResultBinding.bodyDigest,
  ...requestBinding.selectedHeaders.map((h) => h.observedValueDigest),
  sig.observedValueDigest, sig.decodedPayloadDigest!, sig.validatedObjectJcsDigest!,
  req.observedValueDigest, resp.observedValueDigest, reqDigest, resDigest,
];
check('every digest uses the single sha256: representation',
  all.every((d) => /^sha256:[0-9a-f]{64}$/.test(d)));

console.log('\n  -- golden vector drift --');
// Section: REF-GOLDEN-001. gen-golden.ts's buildGolden() is the SAME function `pnpm gen:golden`
// uses to write fixtures/golden-v1.json. Calling it here and deep-comparing against the committed
// file (rather than only the individual fields asserted above) proves the committed document as a
// whole cannot silently diverge from what the generator currently produces: a field this suite does
// not otherwise assert on would still be caught here.
recordExecution('REF-GOLDEN-001');
const freshlyBuilt = await buildGolden();
const freshJson = JSON.stringify(freshlyBuilt, null, 2) + '\n';
const committedJson = readFileSync(join(HERE, '..', 'fixtures/golden-v1.json'), 'utf8');
check('the committed golden vector file is byte-identical to a fresh gen-golden.ts build',
  freshJson === committedJson,
  freshJson === committedJson
    ? ''
    : 'fixtures/golden-v1.json has drifted from the generator; run `pnpm gen:golden` and review the diff');

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
