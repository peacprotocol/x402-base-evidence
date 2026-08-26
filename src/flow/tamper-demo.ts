/**
 * Show what tampering looks like from outside.
 *
 * The committed evidence is copied to a temporary directory, exactly one bound field is changed to
 * a more flattering value, and the same verifier that passes on the untouched directory is run
 * against the copy. The committed evidence is never modified.
 *
 * The interesting part is not that verification fails. It is that the failure names the document
 * that was edited, so a reader learns which claim is not supported rather than being told the
 * whole directory is suspect.
 *
 * Exits non-zero if verification fails to notice, because a tamper demonstration that quietly
 * passes is worse than none.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EXPECTED_EVIDENCE_DIR, EXPECTED_EVIDENCE_DISPLAY } from './issue-record.ts';
import { resolveIssuerKey } from './issuer-key.ts';
import { verifyEvidence } from './verify-evidence.ts';

/** The one field this demonstration changes, and the document that carries it. */
const TARGET_DOCUMENT = 'chain-observation.json';
const TARGET_FIELD = 'amount_base_units';
const TAMPERED_VALUE = '1';

export async function main(): Promise<void> {
  const issuerKey = await resolveIssuerKey('fixture');

  console.log('\nTamper demonstration\n');
  const baseline = await verifyEvidence(EXPECTED_EVIDENCE_DIR, issuerKey.publicKey);
  console.log(`  committed evidence  : ${EXPECTED_EVIDENCE_DISPLAY}`);
  console.log(`  baseline            : ${baseline.ok ? 'verified' : 'NOT VERIFIED'}`);
  if (!baseline.ok) {
    console.log('\n  The committed evidence does not verify, so there is nothing to tamper with.\n');
    process.exit(1);
  }

  const directory = mkdtempSync(join(tmpdir(), 'peac-tamper-'));
  try {
    cpSync(EXPECTED_EVIDENCE_DIR, directory, { recursive: true });

    const target = join(directory, TARGET_DOCUMENT);
    const document = JSON.parse(readFileSync(target, 'utf8')) as {
      payment_expectation: Record<string, unknown>;
    } & Record<string, unknown>;
    const original = document.payment_expectation[TARGET_FIELD];
    document.payment_expectation[TARGET_FIELD] = TAMPERED_VALUE;
    writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`);

    console.log(`  edited              : ${TARGET_DOCUMENT}`);
    console.log(`  field               : payment_expectation.${TARGET_FIELD}`);
    console.log(`  ${String(original)} changed to ${TAMPERED_VALUE}`);

    const report = await verifyEvidence(directory, issuerKey.publicKey);
    console.log('\n  verification of the edited copy\n');
    for (const check of report.checks) {
      console.log(`    ${check.ok ? 'ok  ' : 'FAIL'}  ${check.name}${check.detail ? `: ${check.detail}` : ''}`);
    }

    const failed = report.checks.filter((c) => !c.ok).map((c) => c.name);
    console.log('');
    if (report.ok) {
      console.log('  The edit was NOT detected. That is a defect in the verifier, not a demonstration.\n');
      process.exit(1);
    }
    console.log(`  Detected at: ${failed.join(', ')}`);
    console.log(
      '  The signature still verifies: the record was not touched. What failed is the digest the\n' +
        '  record binds for the edited document, and the one field the record and the observation\n' +
        '  both carry, so the failure names the claims that are no longer supported rather than\n' +
        '  condemning the directory as a whole.\n',
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
