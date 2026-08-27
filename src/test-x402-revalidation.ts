/**
 * The x402 native validation authority, kept distinct from artifact integrity and every other
 * authority a verification report names.
 *
 * A digest recomputing only proves the bytes are the ones the record bound; it says nothing about
 * whether those bytes are themselves a well-formed x402 object. Every case here proves the two
 * questions are actually answered separately: a genuinely re-signed record whose bound digest
 * matches a structurally invalid x402 artifact must fail `x402_native_validation` while
 * `artifact_integrity` still passes, and an artifact x402 v2 defines no runtime validator for must
 * report `not_evaluated` rather than borrowing a verdict from a check that never ran.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issue } from '@peac/protocol';
import * as F from '../fixtures/deterministic.ts';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { runOnce, buildEvidence } from './flow/fixture-e2e.ts';
import { resolveIssuerKey } from './flow/issuer-key.ts';
import { writeEvidence, type EvidenceLayout } from './flow/issue-record.ts';
import { verifyEvidence, type EvidenceVerificationReport } from './flow/verify-evidence.ts';
import { digestBytes } from './digest.ts';
import type { EvidenceArtifact } from './flow/presence.ts';

beginAcceptanceSuite('x402-revalidation');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

const issuerKey = await resolveIssuerKey('fixture');
const honestRun = await runOnce();
const honestLayout = await buildEvidence(honestRun);

const named = (report: EvidenceVerificationReport, name: string) =>
  report.checks.find((c) => c.name === name);

const temporaryDirectories: string[] = [];
function evidenceWith(overrides: ReadonlyMap<EvidenceArtifact, Uint8Array>): string {
  const directory = mkdtempSync(join(tmpdir(), 'peac-x402-revalidation-'));
  temporaryDirectories.push(directory);
  const files = new Map<EvidenceArtifact, Uint8Array>(honestLayout.files);
  for (const [artifact, bytes] of overrides) files.set(artifact, bytes);
  const jws = overrides.get('record.jws');
  const layout: EvidenceLayout = {
    jws: jws === undefined ? honestLayout.jws : new TextDecoder().decode(jws).trim(),
    files,
  };
  writeEvidence(directory, layout);
  return directory;
}

recordExecution('X402-REVALIDATION-001');
{
  const report = await verifyEvidence(evidenceWith(new Map()), issuerKey.publicKey);
  check('a valid native evidence set verifies overall', report.ok === true, JSON.stringify(report.checks));
  check(
    'x402_native_validation is valid for a genuinely well-formed evidence set',
    report.authorities.x402_native_validation === 'valid',
    JSON.stringify(report.authorities),
  );
  check(
    'the payment-required artifact independently re-validates',
    named(report, 'x402 native validation: payment-required')?.ok === true,
  );
  check(
    'the payment-signature artifact independently re-validates as an Exact/EVM PaymentPayload',
    named(report, 'x402 native validation: payment-signature')?.ok === true,
  );
  check(
    'the presented terms match an advertised accept entry',
    named(report, 'x402 native validation: term matching')?.ok === true,
  );
}

recordExecution('X402-REVALIDATION-002');
{
  // A hostile payment-required artifact: valid standard base64, decodes to valid JSON, but the
  // x402Version the upstream validator requires is wrong. Its digest is computed the same way the
  // production capture path computes it (UTF-8 bytes of the observed base64 text), and the record
  // is genuinely re-signed under the fixture key to bind THAT digest -- so artifact_integrity has
  // no reason to fail: the bytes present are exactly the bytes the record names.
  const hostilePaymentRequired = {
    ...F.PAYMENT_REQUIRED,
    x402Version: 999 as unknown as 2,
  };
  const hostileBase64 = Buffer.from(JSON.stringify(hostilePaymentRequired), 'utf8').toString('base64');
  const hostileDigest = digestBytes(new TextEncoder().encode(hostileBase64));

  const [, payload] = honestLayout.jws.split('.');
  if (payload === undefined) throw new Error('the honest record has no payload segment');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
    iss: string;
    kind: 'evidence' | 'challenge';
    type: string;
    jti: string;
    pillars: readonly string[];
    occurred_at: string;
    extensions: Record<string, Record<string, unknown>>;
  };
  const paymentEvidenceGroup = claims.extensions['com.example/payment_evidence'];
  if (paymentEvidenceGroup === undefined) {
    throw new Error('the honest record has no com.example/payment_evidence extension group');
  }
  paymentEvidenceGroup['payment_required_digest'] = hostileDigest;
  const resigned = await issue({
    iss: claims.iss,
    kind: claims.kind,
    type: claims.type,
    privateKey: issuerKey.privateKey,
    kid: issuerKey.kid,
    jti: claims.jti,
    // The decoded claims' pillar list is already a valid member of the enum `issue()` declares;
    // it just is not literally typed as one after a JSON round trip.
    pillars: claims.pillars as any,
    occurred_at: claims.occurred_at,
    extensions: claims.extensions,
  });

  const directory = evidenceWith(
    new Map<EvidenceArtifact, Uint8Array>([
      ['artifacts/payment-required.txt', new TextEncoder().encode(hostileBase64)],
      ['record.jws', new TextEncoder().encode(`${resigned.jws}\n`)],
    ]),
  );
  const report = await verifyEvidence(directory, issuerKey.publicKey);

  check(
    'the record signature itself still verifies (this is a genuine re-signature)',
    named(report, 'record signature and schema')?.ok === true,
  );
  check(
    'artifact_integrity still passes: the bound digest matches the bytes actually present',
    named(report, 'payment-required digest')?.ok === true,
    JSON.stringify(named(report, 'payment-required digest')),
  );
  check(
    'x402_native_validation fails: the artifact does not independently re-validate',
    named(report, 'x402 native validation: payment-required')?.ok === false,
    JSON.stringify(named(report, 'x402 native validation: payment-required')),
  );
  check(
    'the two authorities disagree, exactly as the evidence disagrees',
    report.authorities.artifact_integrity === 'valid' &&
      report.authorities.x402_native_validation === 'invalid',
    JSON.stringify(report.authorities),
  );
  check('the report as a whole is never trusted', report.ok === false);
}

recordExecution('X402-REVALIDATION-003');
{
  const report = await verifyEvidence(evidenceWith(new Map()), issuerKey.publicKey);
  const responseCheck = named(report, 'x402 native validation: payment-response');
  check(
    'payment-response reports not_evaluated rather than an invented x402 authority',
    responseCheck?.ok === true && responseCheck.detail.includes('not_evaluated'),
    JSON.stringify(responseCheck),
  );
  check(
    'not_evaluated for one artifact does not by itself invalidate the x402_native_validation authority',
    report.authorities.x402_native_validation === 'valid',
    JSON.stringify(report.authorities),
  );
}

for (const directory of temporaryDirectories) rmSync(directory, { recursive: true, force: true });

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
