/**
 * Acceptance completeness gate.
 *
 * Run after the suites. It fails if any locally scoped acceptance case declared in the registry
 * did not execute, so a case cannot be quietly removed, renamed or skipped while the counts keep
 * looking healthy.
 */
import { ACCEPTANCE_CASES, checkCompleteness } from './acceptance-ids.ts';

const report = checkCompleteness();
const declared = Object.keys(ACCEPTANCE_CASES).length;

console.log('\nAcceptance matrix\n');
console.log(`  declared          : ${declared}`);
console.log(`  executed locally  : ${report.executed.length}`);
console.log(`  executed in CI    : ${report.declaredExternally.length}`);

for (const id of report.declaredExternally) {
  console.log(`  ci    ${id}  ${ACCEPTANCE_CASES[id as keyof typeof ACCEPTANCE_CASES].description}`);
}
for (const id of report.missing) {
  console.log(`  MISS  ${id}  ${ACCEPTANCE_CASES[id as keyof typeof ACCEPTANCE_CASES].description}`);
}

const unknown = report.executed.filter((id) => !(id in ACCEPTANCE_CASES));
for (const id of unknown) console.log(`  UNKNOWN  ${id} was recorded but is not declared`);

if (!report.complete || unknown.length > 0) {
  console.log(`\nFAILED: ${report.missing.length} declared case(s) did not execute\n`);
  process.exit(1);
}
console.log('\nPASSED: every declared case executed in its declared scope\n');
