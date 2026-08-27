/**
 * Dependency import smoke test.
 *
 * Compiles and executes the exact x402 subpaths this profile depends on, and asserts the exact
 * symbols it uses. Checking only that a module loads would pass after an upstream rename removed
 * every symbol actually relied upon.
 */
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  X402_PINNED_VERSION,
  SETTLE_RESPONSE_LOCAL_AUTHORITY,
  SETTLE_RESPONSE_LOCAL_AUTHORITY_BASIS,
} from './x402-header.ts';

const APP_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

/**
 * Read an installed package's version from disk.
 *
 * NOT via require.resolve('<pkg>/package.json'): the x402 packages define an "exports" map that
 * deliberately does not expose ./package.json, so resolution throws. Reading node_modules directly
 * reports what is actually installed, which is the thing under test.
 */
function installedVersion(pkg: string): string {
  try {
    const pj = JSON.parse(readFileSync(join(APP_ROOT, 'node_modules', pkg, 'package.json'), 'utf8')) as {
      version?: string;
    };
    return pj.version ?? 'missing-version-field';
  } catch (e) {
    return `ERROR ${(e as Error).message.split('\n')[0]}`;
  }
}

/**
 * Required subpaths AND the exact symbols this profile depends on. Asserting only that "some export
 * exists" would pass even after an upstream rename removed everything actually used.
 *
 * This set is exactly what the runtime code imports. Requiring a subpath the code never calls would
 * make an unrelated upstream change fail this gate, and would advertise a dependency on a feature
 * that is not implemented here. The offer-receipt and builder-code subpaths were required here
 * without being used and have been removed; they remain in ALL_EXPORT_PATHS below, whose purpose is
 * discovery, not dependency.
 */
const REQUIRED_EXPORTS: Record<string, readonly string[]> = {
  '@x402/core': ['x402Version'],
  // The client-side seams the live flow relies on: extension enrichment and the
  // before-payment-creation hook. The instance-method shape is asserted separately below.
  '@x402/core/client': ['x402Client', 'x402HTTPClient'],
  '@x402/core/http': [
    'decodePaymentRequiredHeader',
    'decodePaymentSignatureHeader',
    'decodePaymentResponseHeader',
    'encodePaymentRequiredHeader',
    'encodePaymentSignatureHeader',
    'encodePaymentResponseHeader',
  ],
  // The runtime validators this profile treats as the upstream schema authority.
  '@x402/core/schemas': [
    'PaymentRequiredV2Schema',
    'PaymentPayloadV2Schema',
    'isPaymentRequiredV2',
    'isPaymentPayloadV2',
    'validatePaymentRequired',
    'validatePaymentPayload',
  ],
  '@x402/evm': ['DEFAULT_ASSETS', 'isEIP3009Payload'],
  '@x402/evm/exact/server': ['ExactEvmScheme', 'registerExactEvmScheme'],
  '@x402/evm/exact/client': ['ExactEvmScheme', 'registerExactEvmScheme'],
  '@x402/evm/exact/facilitator': ['ExactEvmScheme', 'registerExactEvmScheme'],
  '@x402/express': ['paymentMiddleware', 'x402ResourceServer'],
  '@x402/extensions/payment-identifier': [
    'PAYMENT_IDENTIFIER',
    'declarePaymentIdentifierExtension',
    'appendPaymentIdentifierToExtensions',
    'extractAndValidatePaymentIdentifier',
    'validatePaymentIdentifier',
    'generatePaymentId',
  ],
};
const REQUIRED_SUBPATHS = Object.keys(REQUIRED_EXPORTS);

const PINNED = ['@x402/core', '@x402/express', '@x402/evm', '@x402/extensions'] as const;
const EXPECTED_VERSION = X402_PINNED_VERSION;

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

// 1. installed versions must equal the exact pins
for (const p of PINNED) {
  const v = installedVersion(p);
  check(`${p} installed at ${EXPECTED_VERSION}`, v === EXPECTED_VERSION, `got ${v}`);
}

// 2. every required subpath must resolve, load, AND expose the exact symbols relied upon
for (const sub of REQUIRED_SUBPATHS) {
  let mod: Record<string, unknown>;
  try {
    mod = (await import(sub)) as Record<string, unknown>;
  } catch (e) {
    check(`import ${sub}`, false, (e as Error).message.split('\n')[0]);
    continue;
  }
  const missing = REQUIRED_EXPORTS[sub]!.filter((sym) => !(sym in mod));
  check(`${sub} exports ${REQUIRED_EXPORTS[sub]!.join(', ')}`, missing.length === 0,
    missing.length ? `missing: ${missing.join(', ')}` : '');
}

// 2b. the client seams the live flow injects through must keep their instance-method shape: the
//     payment identifier travels through `registerExtension` (enrichment) and the EIP-3009 scope
//     guard through `onBeforePaymentCreation`. An upstream rename or removal fails here by name,
//     not somewhere inside a live run.
{
  const { x402Client } = await import('@x402/core/client');
  const proto = x402Client.prototype as unknown as Record<string, unknown>;
  for (const method of ['registerExtension', 'onBeforePaymentCreation', 'setSpendControls', 'register']) {
    check(
      `x402Client.prototype.${method} is a function`,
      typeof proto[method] === 'function',
      `got ${typeof proto[method]}`,
    );
  }
}

// 3. the settle-response authority string must be first-party (never shaped like an @x402/core
//    identifier, so it cannot be mistaken for an upstream verdict), and its documented basis must
//    name the version actually installed, so a reported structural verdict is always attributable
//    to a known upstream shape.
check(
  'settle response structural authority is first-party, not upstream-shaped',
  SETTLE_RESPONSE_LOCAL_AUTHORITY === 'x402-base-evidence/local-settle-response-shape@1' &&
    !SETTLE_RESPONSE_LOCAL_AUTHORITY.startsWith('@x402/'),
  `got ${SETTLE_RESPONSE_LOCAL_AUTHORITY}`,
);
check(
  'the documented basis names the pinned upstream version',
  SETTLE_RESPONSE_LOCAL_AUTHORITY_BASIS === `@x402/core@${X402_PINNED_VERSION} SettleResponse TypeScript declaration`,
  `got ${SETTLE_RESPONSE_LOCAL_AUTHORITY_BASIS}`,
);

// 4. the reason this profile reports settle responses under a LOCAL structural authority is that
//    upstream ships no runtime validator for them. That is a measured claim, so it is measured:
//    every export path of the pinned packages is searched for one. If upstream ever adds one,
//    this fails and the local check must be replaced by the upstream authority.
// DISCOVERY SCOPE, NOT A FEATURE DEPENDENCY. Every published export path of the pinned packages is
// enumerated here so the "upstream ships no settle-response validator" claim is measured across the
// whole surface rather than across the subset this profile happens to import. A path appearing in
// this list says nothing about whether this profile uses it; REQUIRED_EXPORTS above is the only
// declaration of what this code actually depends on.
const ALL_EXPORT_PATHS = [
  '@x402/core', '@x402/core/client', '@x402/core/facilitator', '@x402/core/http',
  '@x402/core/server', '@x402/core/types', '@x402/core/types/v1', '@x402/core/utils',
  '@x402/core/schemas',
  '@x402/evm', '@x402/evm/v1', '@x402/evm/exact/client', '@x402/evm/exact/server',
  '@x402/evm/exact/facilitator', '@x402/evm/exact/v1/client', '@x402/evm/exact/v1/facilitator',
  '@x402/extensions', '@x402/extensions/bazaar', '@x402/extensions/sign-in-with-x',
  '@x402/extensions/offer-receipt', '@x402/extensions/payment-identifier',
  '@x402/extensions/builder-code',
  '@x402/express',
] as const;
// A validator would be named like the predicates and schemas that do exist for the other types.
const VALIDATOR_SHAPE = /^(is|validate|parse)Settle|^Settle.*Schema$/;
const settleValidators: string[] = [];
for (const sub of ALL_EXPORT_PATHS) {
  try {
    const mod = (await import(sub)) as Record<string, unknown>;
    for (const key of Object.keys(mod)) if (VALIDATOR_SHAPE.test(key)) settleValidators.push(`${sub}:${key}`);
  } catch {
    // Unresolvable subpaths are reported by the required-subpath checks above.
  }
}
check('upstream still ships no runtime settle-response validator', settleValidators.length === 0,
  settleValidators.join(', '));

// 5. report what the installed packages actually export, so an upstream rename is visible in the diff
console.log('\n  installed export surface:');
for (const sub of REQUIRED_SUBPATHS) {
  try {
    const mod = (await import(sub)) as Record<string, unknown>;
    const keys = Object.keys(mod).filter((k) => k !== 'default').sort();
    console.log(`    ${sub}`);
    console.log(`      ${keys.slice(0, 12).join(', ')}${keys.length > 12 ? ` ... (+${keys.length - 12})` : ''}`);
  } catch {
    console.log(`    ${sub}  <unresolvable>`);
  }
}

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
