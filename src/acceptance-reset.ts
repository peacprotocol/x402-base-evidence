/**
 * Clean-start step for the acceptance ledger. Runs first in `pnpm test`, before any suite begins.
 *
 * `beginAcceptanceSuite` truncates only the ONE ledger file for the suite calling it. That alone
 * does not protect against a suite that is skipped, renamed or removed from the composite run: its
 * ledger file from an earlier invocation would still sit in `.acceptance/` and `checkCompleteness`
 * would still count it, reporting a case as executed when it did not actually execute this run.
 * Removing the whole directory here, once, before anything else runs, closes that gap. See the
 * module comment in
 * `acceptance-ids.ts` and the regression test in `test-ledger-integrity.ts`.
 */
import { resetAcceptanceLedgers } from './acceptance-ids.ts';

resetAcceptanceLedgers();
console.log('acceptance ledger reset: starting from a clean directory');
