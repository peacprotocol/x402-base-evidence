/**
 * Build (and, run directly, write) fixtures/golden-v1.json.
 *
 * `buildGolden()` is the single source of the vector shape. It is imported both by this file's own
 * write path (run only when the binding structures intentionally change, reviewed as a diff) and by
 * the drift check in `test-golden.ts`, which calls it and compares the result against the committed
 * file WITHOUT writing anything. One generator, two consumers, so the write path and the drift check
 * can never silently diverge from each other.
 *
 * Vectors that regenerate silently, or that only some of their fields are checked against, are not
 * deterministic validation vectors; the drift check compares the full committed document.
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { buildRequestBinding, buildOriginResultBinding, bindingDigest } from './binding.ts';
import { componentsFromAbsoluteUri } from './components.ts';
import { captureObservedX402Artifact, SETTLE_RESPONSE_LOCAL_AUTHORITY } from './x402-header.ts';
import { canonicalizeIndependent } from './jcs-independent.ts';
import { digestBytes } from './digest.ts';
import * as F from '../fixtures/deterministic.ts';

export async function buildGolden(): Promise<Record<string, unknown>> {
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
  const requestBinding = buildRequestBinding({
    components,
    body: F.REQUEST_BODY,
    selectedHeaders: [sig],
  });
  const originResultBinding = buildOriginResultBinding({
    status: 200,
    contentType: 'application/json',
    body: F.ORIGIN_RESULT_BODY,
  });

  return {
    _comment:
      'Deterministic validation vectors with hard-coded expected bytes and digests. Regenerate via pnpm gen:golden and review the diff.',
    profileRequestBinding: requestBinding.profile,
    profileOriginResultBinding: originResultBinding.profile,
    requestBinding,
    requestBindingJcsUtf8Hex: Buffer.from(canonicalizeIndependent(requestBinding), 'utf8').toString('hex'),
    requestBindingDigest: await bindingDigest(requestBinding),
    originResultBinding,
    originResultBindingJcsUtf8Hex: Buffer.from(canonicalizeIndependent(originResultBinding), 'utf8').toString('hex'),
    originResultBindingDigest: await bindingDigest(originResultBinding),
    originResultBodyDigest: digestBytes(F.ORIGIN_RESULT_BODY),
    requestBodyDigest: digestBytes(F.REQUEST_BODY),
    settleResponseLocalStructuralAuthority: SETTLE_RESPONSE_LOCAL_AUTHORITY,
    observedHeaders: {
      'payment-required': req,
      'payment-signature': sig,
      'payment-response': resp,
    },
  };
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const HERE = dirname(fileURLToPath(import.meta.url));
  const golden = await buildGolden();
  const out = join(HERE, '..', 'fixtures', 'golden-v1.json');
  writeFileSync(out, JSON.stringify(golden, null, 2) + '\n');
  console.log(`wrote ${out}`);
  console.log(`  requestBindingDigest      ${(golden as Record<string, unknown>).requestBindingDigest}`);
  console.log(`  originResultBindingDigest ${(golden as Record<string, unknown>).originResultBindingDigest}`);
}
