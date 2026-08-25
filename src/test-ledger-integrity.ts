/**
 * Regression test: stale ledger state from a prior run must not be able to mask an omitted
 * acceptance case.
 *
 * This runs against ISOLATED temporary ledger directories, never the real `.acceptance/` directory
 * the other suites use, so it cannot interfere with or be interfered with by them.
 *
 * Two scenarios, both against the same simulated "prior run left a full ledger behind" state:
 *
 *   A. WITHOUT a directory-wide reset: only `beginAcceptanceSuite` truncation runs, exactly as if
 *      the reset step in `pnpm test` had been skipped. This demonstrates the vulnerability is real:
 *      a stale ledger from a suite that is NOT part of the current pass is still counted, and
 *      completeness incorrectly reports success even though a required case was never executed
 *      this run.
 *
 *   B. WITH `resetAcceptanceLedgers` run first, exactly as `src/acceptance-reset.ts` does at the
 *      start of the real `pnpm test`: the stale file is gone before the current pass's one suite
 *      records anything, so the SAME omission is correctly caught and completeness fails.
 *
 * Scenario A is not a passing production path; it exists only to prove the fix in scenario B fixes
 * something real, rather than asserting a property that was already true.
 */
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACCEPTANCE_CASES,
  beginAcceptanceSuite,
  recordExecution,
  checkCompleteness,
  resetAcceptanceLedgers,
  type AcceptanceId,
} from './acceptance-ids.ts';

beginAcceptanceSuite('ledger-integrity');

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

console.log('\nLedger integrity\n');

// All locally-scoped IDs. One is deliberately withheld from what "this run" records, simulating a
// suite that covers everything except that one case.
const localIds = Object.entries(ACCEPTANCE_CASES)
  .filter(([, spec]) => spec.scope === 'local')
  .map(([id]) => id as AcceptanceId);
const omitted = localIds.at(-1)!;
const recordedThisRun = localIds.filter((id) => id !== omitted);

function writeStaleFullLedger(dir: string): void {
  // A ledger file exactly as a complete prior run would have left it: every locally-scoped case,
  // including the one this run's single suite will NOT record.
  writeFileSync(join(dir, 'a-suite-not-run-this-time.ledger'), localIds.join('\n') + '\n');
}

// -- scenario A: no directory-wide reset --------------------------------------------------------
const dirA = mkdtempSync(join(tmpdir(), 'x402-base-evidence-ledger-a-'));
try {
  writeStaleFullLedger(dirA);
  // Exactly what beginAcceptanceSuite alone provides: truncation of only its own file.
  beginAcceptanceSuite('current-suite', dirA);
  for (const id of recordedThisRun) recordExecution(id);
  const reportA = checkCompleteness(dirA);
  check(
    'WITHOUT a directory-wide reset, a stale ledger from a skipped suite masks the omission ' +
      '(this is exactly why the reset step exists)',
    reportA.complete === true && !reportA.missing.includes(omitted),
    `complete=${reportA.complete} missing=${JSON.stringify(reportA.missing)}`,
  );
} finally {
  rmSync(dirA, { recursive: true, force: true });
}

// -- scenario B: resetAcceptanceLedgers runs first, as it does in the real pnpm test -------------
const dirB = mkdtempSync(join(tmpdir(), 'x402-base-evidence-ledger-b-'));
try {
  writeStaleFullLedger(dirB);
  resetAcceptanceLedgers(dirB);
  check('reset removes the stale ledger directory entirely', !existsSync(dirB));

  beginAcceptanceSuite('current-suite', dirB);
  for (const id of recordedThisRun) recordExecution(id);
  const reportB = checkCompleteness(dirB);
  check(
    'WITH a directory-wide reset, an omitted case is correctly reported as missing',
    reportB.complete === false && reportB.missing.includes(omitted) && reportB.missing.length === 1,
    `complete=${reportB.complete} missing=${JSON.stringify(reportB.missing)}`,
  );
} finally {
  rmSync(dirB, { recursive: true, force: true });
}

// Both scenarios above pointed the module-level ledger cursor at temporary, now-deleted
// directories. Re-begin against the real default ledger before recording this suite's own result.
beginAcceptanceSuite('ledger-integrity');
recordExecution('REF-LEDGER-001');

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
