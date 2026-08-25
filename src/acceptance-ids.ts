/**
 * Named acceptance registry.
 *
 * A count of passing checks says nothing about which properties were actually exercised: a suite
 * can grow while quietly losing the case that mattered. Every acceptance case therefore carries a
 * stable identifier, declared here once, and the suites record identifiers as they execute. A
 * completeness runner then fails if any declared identifier never executed, so coverage cannot
 * silently regress and no case can be skipped without the gate noticing.
 *
 * Two execution scopes exist:
 *   local         executed by the test suites in this process
 *   ci-external   executed by a continuous-integration job that this process cannot reproduce
 *                 (a repeated-run byte comparison, or a run with networking disabled). These are
 *                 still declared here so the matrix stays complete and visible.
 *
 * Reset the ledger directory before a composite run so stale suite state cannot satisfy
 * completeness. `beginAcceptanceSuite` truncates only the ONE ledger file for the suite calling it,
 * so a suite that is skipped, renamed or removed from `pnpm test` in a given run leaves its earlier
 * ledger file exactly where `readExecutedIds` will still find and count it. `resetAcceptanceLedgers`
 * removes the whole ledger directory and MUST run once, before the first suite of a composite run
 * begins (`src/acceptance-reset.ts`, wired as the first step of `pnpm test`). "CI starts from a
 * clean checkout" is not the correctness argument here: a developer running individual
 * `pnpm test:*` scripts out of order, or a `test` script that omits a suite, must still get a
 * truthful completeness report. `src/test-ledger-integrity.ts` is the regression test proving stale
 * state cannot survive a reset.
 */
import { appendFileSync, mkdirSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export type ExecutionScope = 'local' | 'ci-external';

export interface AcceptanceCase {
  readonly description: string;
  readonly scope: ExecutionScope;
}

/** The declared acceptance matrix for the implemented scope. */
export const ACCEPTANCE_CASES = {
  'X402-VALID-001': { description: 'PaymentRequired fixture accepted by the upstream validator', scope: 'local' },
  'X402-VALID-002': { description: 'PaymentPayload (EVM exact / EIP-3009 shape) accepted by the upstream validator', scope: 'local' },
  'X402-VALID-003': { description: 'payment identifier extension present and valid via upstream APIs', scope: 'local' },
  'X402-VALID-004': { description: 'round trip: encode, capture, upstream validation self-test', scope: 'local' },
  'X402-VALID-005': { description: 'explicit eip3009 asset transfer method is accepted', scope: 'local' },
  'X402-REJECT-001': { description: 'an arbitrary JSON object is rejected at the upstream-schema stage', scope: 'local' },
  'X402-REJECT-002': { description: 'a missing required member is rejected', scope: 'local' },
  'X402-REJECT-003': { description: 'a wrong x402Version is rejected', scope: 'local' },
  'X402-REJECT-004': { description: 'an unknown scheme is rejected at the scheme-payload stage', scope: 'local' },
  'X402-REJECT-005': { description: 'a malformed CAIP-2 network is rejected', scope: 'local' },
  'X402-REJECT-006': { description: 'a valid v1-shaped object is rejected by the v2 predicate', scope: 'local' },
  'X402-REJECT-007': { description: 'base64 tampered after encoding is rejected', scope: 'local' },
  'X402-REJECT-008': { description: 'a non-visible-ASCII field value is refused at capture', scope: 'local' },
  'X402-REJECT-009': { description: 'an exact-EVM payload missing its required signature is rejected at scheme-payload', scope: 'local' },
  'X402-REJECT-010': { description: 'an exact-EVM payload with a malformed signature is rejected at scheme-payload', scope: 'local' },
  'X402-REJECT-011': { description: 'permit2 asset transfer method is rejected by this EIP-3009-only reference', scope: 'local' },
  'X402-DUP-001': { description: 'a literal duplicate member is rejected before canonicalization', scope: 'local' },
  'X402-DUP-002': { description: 'an escaped-key collision is rejected before canonicalization', scope: 'local' },
  'X402-DUP-003': { description: 'a duplicate member in a nested object is rejected', scope: 'local' },
  'X402-STAGE-001': { description: 'the stage report names the exact failing stage', scope: 'local' },
  'X402-STAGE-002': { description: 'settle response keeps upstream-schema status not_evaluated', scope: 'local' },
  'X402-STAGE-003': { description: 'a capture-only artifact cannot be promoted', scope: 'local' },
  'X402-STAGE-004': { description: 'transport decoding never implies schema validity', scope: 'local' },
  'X402-LIMIT-001': { description: 'an oversized encoded field value is refused', scope: 'local' },
  'X402-LIMIT-002': { description: 'an oversized decoded payload is refused', scope: 'local' },
  'X402-LIMIT-003': { description: 'diagnostics are truncated at the declared caps', scope: 'local' },
  'REF-DET-001': { description: 'the fixture demonstration produces byte-identical output across runs', scope: 'ci-external' },
  'REF-NET-001': { description: 'the offline path passes in a job with networking disabled', scope: 'ci-external' },
  'REF-GOLDEN-001': { description: 'the committed golden vectors do not silently drift from the generator', scope: 'local' },
  'REF-LEDGER-001': { description: 'stale ledger state from a prior run cannot mask an omitted acceptance case once the ledger directory has been reset', scope: 'local' },
} as const satisfies Record<string, AcceptanceCase>;

export type AcceptanceId = keyof typeof ACCEPTANCE_CASES;

const HERE = dirname(fileURLToPath(import.meta.url));
/**
 * Default ledger directory for the real (non-test-isolated) acceptance run. `resetAcceptanceLedgers`
 * MUST be called against this directory before the FIRST suite of a run begins — see
 * `src/acceptance-reset.ts`, wired as the first step of `pnpm test`. Per-suite truncation in
 * `beginAcceptanceSuite` only protects a suite against its OWN stale file; it does nothing for a
 * suite that is skipped or renamed in this run but has a stale ledger file left over from an
 * earlier one. Only a directory-wide reset at the start of the composite run closes that gap. See
 * `src/test-ledger-integrity.ts` for the regression test that proves this.
 */
export const DEFAULT_LEDGER_DIR = join(HERE, '..', '.acceptance');

let ledgerPath: string | undefined;

/** Remove every ledger file (and the directory itself) so a run starts from provably clean state. */
export function resetAcceptanceLedgers(ledgerDir: string = DEFAULT_LEDGER_DIR): void {
  rmSync(ledgerDir, { recursive: true, force: true });
}

/**
 * Start recording for one suite. Each suite writes its own ledger so suites stay independent
 * processes while the completeness check still sees their union.
 *
 * This alone does NOT protect against a stale ledger from a suite that does not run in the current
 * pass: it truncates only the file for `suite`. Directory-wide freshness is `resetAcceptanceLedgers`'
 * job, run once before any suite begins.
 */
export function beginAcceptanceSuite(suite: string, ledgerDir: string = DEFAULT_LEDGER_DIR): void {
  if (!/^[a-z0-9-]+$/.test(suite)) throw new Error(`invalid suite name: ${suite}`);
  mkdirSync(ledgerDir, { recursive: true });
  ledgerPath = join(ledgerDir, `${suite}.ledger`);
  // Truncate by writing an empty file, so a removed case disappears from the union.
  appendFileSync(ledgerPath, '', { flag: 'w' });
}

/** Record that an acceptance case executed. Unknown identifiers are a programming error. */
export function recordExecution(id: AcceptanceId): void {
  if (!(id in ACCEPTANCE_CASES)) throw new Error(`unknown acceptance id: ${id}`);
  if (ledgerPath === undefined) throw new Error('beginAcceptanceSuite must be called before recordExecution');
  appendFileSync(ledgerPath, `${id}\n`);
}

/** Every identifier recorded by any suite in the current run. */
export function readExecutedIds(ledgerDir: string = DEFAULT_LEDGER_DIR): Set<string> {
  const executed = new Set<string>();
  let entries: string[];
  try {
    entries = readdirSync(ledgerDir);
  } catch {
    return executed;
  }
  for (const entry of entries) {
    if (!entry.endsWith('.ledger')) continue;
    for (const line of readFileSync(join(ledgerDir, entry), 'utf8').split('\n')) {
      const id = line.trim();
      if (id.length > 0) executed.add(id);
    }
  }
  return executed;
}

export interface CompletenessReport {
  readonly complete: boolean;
  readonly missing: readonly string[];
  readonly executed: readonly string[];
  readonly declaredExternally: readonly string[];
}

/**
 * Compare the declared matrix against what actually executed.
 *
 * Cases scoped to continuous integration are reported separately rather than treated as executed,
 * so a local run never reads as though it proved something it did not.
 */
export function checkCompleteness(ledgerDir: string = DEFAULT_LEDGER_DIR): CompletenessReport {
  const executed = readExecutedIds(ledgerDir);
  const missing: string[] = [];
  const declaredExternally: string[] = [];
  for (const [id, spec] of Object.entries(ACCEPTANCE_CASES)) {
    if (spec.scope === 'ci-external') {
      if (!executed.has(id)) declaredExternally.push(id);
      continue;
    }
    if (!executed.has(id)) missing.push(id);
  }
  return {
    complete: missing.length === 0,
    missing,
    executed: [...executed].sort(),
    declaredExternally,
  };
}
