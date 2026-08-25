/**
 * Readable walkthrough of the binding layer using deterministic synthetic data.
 *
 * Assertions live in the deterministic-validation and rejection suites; this file exists to show
 * what the structures look like.
 */
import { buildRequestBinding, buildOriginResultBinding, bindingDigest } from './binding.ts';
import { componentsFromAbsoluteUri } from './components.ts';
import { captureObservedX402Artifact, X402_STAGES } from './x402-header.ts';
import * as F from '../fixtures/deterministic.ts';

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

console.log('\nPayment evidence example: deterministic synthetic run\n');
console.log('  profile             :', requestBinding.profile);
console.log('  @method             :', requestBinding.components['@method']);
console.log('  @scheme // @authority:', `${requestBinding.components['@scheme']} // ${requestBinding.components['@authority']}`);
console.log('  @path               :', requestBinding.components['@path']);
console.log('  @query              :', requestBinding.components['@query']);
console.log('  proxy trust profile :', requestBinding.components.proxyTrustProfile);
console.log('  request binding     :', await bindingDigest(requestBinding));
console.log('  origin result       :', await bindingDigest(originResultBinding));
console.log('  origin body digest  :', originResultBinding.bodyDigest);
console.log('');
for (const h of [sig, resp]) {
  console.log(`  ${h.name}`);
  console.log(`    observed digest   : ${h.observedValueDigest}`);
  console.log(`    artifact type     : ${h.artifactType}`);
  for (const stage of X402_STAGES) console.log(`    ${stage.padEnd(18)}: ${h.stages[stage]}`);
  if (h.localStructural) {
    console.log(`    local structural  : ${h.localStructural.localStructuralStatus}`);
    console.log(`    structural authority: ${h.localStructural.localStructuralAuthority}`);
  }
  for (const d of h.diagnostics) {
    console.log(`    diagnostic        : ${d.stage} ${d.code} [${d.path.join('.')}]`);
  }
}
console.log('\n  Selected headers are bound in sorted order, independent of caller order:');
for (const h of requestBinding.selectedHeaders) console.log(`    ${h.name}`);
console.log('\n  The origin binding covers bytes produced by the origin application before');
console.log('  transfer encoding or gateway transformation. A client-side digest, if any,');
console.log('  is reported by that client and is not signed here.\n');
