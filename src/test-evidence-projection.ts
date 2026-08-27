/**
 * The evidence projection against real, cryptographically valid, hostile records.
 *
 * Every case here starts from one honestly issued record and re-signs a variant of it under the
 * SAME fixture issuer key, through the production `issue()` API — never a hand-assembled JWS — so
 * a passing signature check in these reports is never masking a forged or malformed record. What
 * changes is a single claim the evidence projection is supposed to independently establish, and
 * what is asserted is that the record's signature still verifies while the evidence projection
 * catches the disagreement anyway, so the report as a whole is never "Verified."
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issue } from '@peac/protocol';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { runOnce, buildEvidence } from './flow/fixture-e2e.ts';
import { resolveIssuerKey } from './flow/issuer-key.ts';
import { writeEvidence, type EvidenceLayout } from './flow/issue-record.ts';
import { verifyEvidence, type EvidenceVerificationReport } from './flow/verify-evidence.ts';
import type { EvidenceArtifact } from './flow/presence.ts';

beginAcceptanceSuite('evidence-projection');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

const issuerKey = await resolveIssuerKey('fixture');
const honestRun = await runOnce();
const honestLayout = await buildEvidence(honestRun);

interface DecodedClaims {
  iss: string;
  kind: 'evidence' | 'challenge';
  type: string;
  jti: string;
  pillars: string[];
  occurred_at?: string;
  extensions: {
    'org.peacprotocol/commerce': Record<string, unknown>;
    'com.example/payment_evidence': Record<string, unknown>;
  };
}

function decodeHonestClaims(): DecodedClaims {
  const [, payload] = honestLayout.jws.split('.');
  if (payload === undefined) throw new Error('the honest record has no payload segment');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as DecodedClaims;
}

/** Re-sign a mutated variant of the honest claims under the same fixture issuer key. */
async function resign(mutate: (claims: DecodedClaims) => void): Promise<string> {
  const claims = decodeHonestClaims();
  mutate(claims);
  const result = await issue({
    iss: claims.iss,
    kind: claims.kind,
    type: claims.type,
    privateKey: issuerKey.privateKey,
    kid: issuerKey.kid,
    jti: claims.jti,
    // A deliberately mutated hostile pillar list is intentionally not a member of the enum
    // `issue()` declares; the point of this case is that `issue()` still signs it.
    pillars: claims.pillars as any,
    ...(claims.occurred_at !== undefined ? { occurred_at: claims.occurred_at } : {}),
    extensions: claims.extensions,
  });
  return result.jws;
}

const temporaryDirectories: string[] = [];

/** Write the honest evidence to a fresh directory, with `record.jws` replaced by a hostile jws. */
function evidenceWithRecord(jws: string): string {
  const directory = mkdtempSync(join(tmpdir(), 'peac-projection-'));
  temporaryDirectories.push(directory);
  const files = new Map<EvidenceArtifact, Uint8Array>(honestLayout.files);
  files.set('record.jws', new TextEncoder().encode(`${jws}\n`));
  const layout: EvidenceLayout = { jws, files };
  writeEvidence(directory, layout);
  return directory;
}

async function verifyHostile(jws: string): Promise<EvidenceVerificationReport> {
  return verifyEvidence(evidenceWithRecord(jws), issuerKey.publicKey);
}

const named = (report: EvidenceVerificationReport, name: string) =>
  report.checks.find((c) => c.name === name);

/**
 * Every hostile case below must clear the same bar: the record's own signature and schema still
 * verify (proving the case is a real re-signature, not a broken one), the ONE evidence-projection
 * check for the mutated field is the check that fails, and the report as a whole is never "ok".
 */
function assertCaughtByProjection(
  name: string,
  report: EvidenceVerificationReport,
  projectionCheckName: string,
): void {
  const signature = named(report, 'record signature and schema');
  check(
    `${name}: the record signature itself still verifies`,
    signature?.ok === true,
    JSON.stringify(signature),
  );
  const projection = named(report, projectionCheckName);
  check(
    `${name}: ${projectionCheckName} is the check that fails`,
    projection?.ok === false,
    JSON.stringify(projection),
  );
  check(`${name}: the report is never trusted`, report.ok === false);
}

recordExecution('PEAC-PROJECTION-001');
{
  // 'challenge' is the only other value Wire 0.2 allows for `kind`, and it structurally forbids
  // `occurred_at`, so the hostile record here carries no `occurred_at` claim at all. That omission
  // does not affect anything the projection checks: none of them read `occurred_at`.
  const jws = await resign((claims) => {
    claims.kind = 'challenge';
    delete claims.occurred_at;
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong kind', report, 'evidence projection: kind');
}

recordExecution('PEAC-PROJECTION-002');
{
  const jws = await resign((claims) => {
    claims.pillars = ['safety'];
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong pillars', report, 'evidence projection: pillars');
}

recordExecution('PEAC-PROJECTION-003');
{
  const jws = await resign((claims) => {
    claims.extensions['org.peacprotocol/commerce']['payment_rail'] = 'not-x402';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong payment rail', report, 'evidence projection: payment_rail');
}

recordExecution('PEAC-PROJECTION-004');
{
  const jws = await resign((claims) => {
    claims.extensions['com.example/payment_evidence']['network'] = 'eip155:1';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong network', report, 'evidence projection: network');
}

recordExecution('PEAC-PROJECTION-005');
{
  const jws = await resign((claims) => {
    claims.extensions['org.peacprotocol/commerce']['asset'] = '0x0000000000000000000000000000000000dEaD';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong asset', report, 'evidence projection: asset');
}

recordExecution('PEAC-PROJECTION-006');
{
  const jws = await resign((claims) => {
    claims.extensions['org.peacprotocol/commerce']['amount_minor'] = '1';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong amount', report, 'evidence projection: amount_minor');
}

recordExecution('PEAC-PROJECTION-007');
{
  const jws = await resign((claims) => {
    claims.extensions['org.peacprotocol/commerce']['env'] = 'live';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong env for the observed Base Sepolia network', report, 'evidence projection: env');
}

recordExecution('PEAC-PROJECTION-008');
{
  // The honest run's chain observation did not reach a successful settlement outcome, so the
  // projection expects `event` to be ABSENT; asserting it here is exactly the overstatement this
  // check exists to catch. (When the honest run DID settle, as it does by default, this instead
  // exercises the "record claims settlement when a different observed outcome occurred" branch by
  // asserting an event string the observation's actual outcome does not justify.)
  const jws = await resign((claims) => {
    claims.extensions['org.peacprotocol/commerce']['event'] = 'refund';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('overstated settlement event', report, 'evidence projection: event');
}

recordExecution('PEAC-PROJECTION-009');
{
  const jws = await resign((claims) => {
    claims.extensions['com.example/payment_evidence']['lifecycle_states'] = ['request_received'];
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong lifecycle_states', report, 'evidence projection: lifecycle_states');
}

recordExecution('PEAC-PROJECTION-010');
{
  const honestReference = decodeHonestClaims().extensions['org.peacprotocol/commerce']['reference'];
  check(
    'the honest record carries a reference to disagree with',
    typeof honestReference === 'string' && honestReference.length > 0,
    String(honestReference),
  );
  const jws = await resign((claims) => {
    claims.extensions['org.peacprotocol/commerce']['reference'] = 'pay_forged_0000000000000000000000';
  });
  const report = await verifyHostile(jws);
  assertCaughtByProjection('wrong reference', report, 'evidence projection: reference');
}

recordExecution('PEAC-PROJECTION-011');
{
  const report = await verifyEvidence(evidenceWithRecord(honestLayout.jws), issuerKey.publicKey);
  check('a correctly issued record verifies', report.ok === true, JSON.stringify(report.checks));
  const derivedNames = [
    'evidence projection: kind',
    'evidence projection: pillars',
    'evidence projection: payment_rail',
    'evidence projection: network',
    'evidence projection: asset',
    'evidence projection: amount_minor',
    'evidence projection: env',
    'evidence projection: event',
    'evidence projection: lifecycle_states',
    'evidence projection: reference',
  ];
  check(
    'every independently derived projection field agrees on the honest record',
    derivedNames.every((n) => named(report, n)?.ok === true),
    derivedNames.filter((n) => named(report, n)?.ok !== true).join(', '),
  );
}

recordExecution('PEAC-PROJECTION-012');
{
  const report = await verifyEvidence(evidenceWithRecord(honestLayout.jws), issuerKey.publicKey);
  const currency = named(report, 'evidence projection: currency');
  check(
    'currency is classified as an issuer assertion, never independently verified',
    currency?.ok === true && currency.detail.includes('issuer assertion'),
    JSON.stringify(currency),
  );
}

recordExecution('PEAC-PROJECTION-013');
{
  const report = await verifyEvidence(evidenceWithRecord(honestLayout.jws), issuerKey.publicKey);
  const occurredAt = named(report, 'evidence projection: occurred_at');
  const jti = named(report, 'evidence projection: jti');
  check(
    'occurred_at is classified as an issuer assertion, never independently verified',
    occurredAt?.ok === true && occurredAt.detail.includes('issuer assertion'),
    JSON.stringify(occurredAt),
  );
  check(
    'jti is classified as an issuer assertion, never independently verified',
    jti?.ok === true && jti.detail.includes('issuer assertion'),
    JSON.stringify(jti),
  );
}

for (const directory of temporaryDirectories) rmSync(directory, { recursive: true, force: true });

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
