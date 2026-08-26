/**
 * Base Sepolia preflight.
 *
 * Everything a live run needs, checked before anything is signed or sent, so a run either starts
 * from a known-good state or stops with the exact reason and what to do about it. A live run that
 * discovers a missing prerequisite halfway through produces a partial transcript, which is the one
 * outcome an evidence example must not produce.
 *
 * THIS FILE AND THE LIVE DEMONSTRATION ARE THE ONLY PLACES THAT USE THE NETWORK. Nothing else in
 * the reference flow opens a connection, and the offline path never calls the network-using checks
 * here; it exercises only the local ones, which is why they are separated below.
 *
 * The payer key is created once and reused; how it is stored and reloaded lives in `payer-key.ts`.
 *
 * WHAT THE PAYER NEEDS, AND WHAT IT DOES NOT. The payer needs Base Sepolia test USDC. It does not
 * need ETH, and this preflight does not require any: under the EIP-3009 asset-transfer method the
 * payer signs an authorization off-chain and the facilitator broadcasts the transaction that
 * consumes it, paying its gas as a structural consequence of being the broadcaster. Who broadcast
 * is recorded in the evidence as `transaction_sender`, an observed fact; no role beyond having
 * broadcast is inferred from it.
 *
 * REVIEWER MATERIAL COMES BEFORE FUNDS. The last local check proves the directory that will hold
 * the public half of the signing key is writable, before any payment is attempted, so there is no
 * state in which funds moved and the material a reviewer needs cannot be written.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isAddress } from 'viem';
import { DEFAULT_ASSETS } from '@x402/evm';
import type { FacilitatorClient } from '@x402/core/server';
import type { Network } from '@x402/core/types';
import { NETWORK } from '../../fixtures/deterministic.ts';
import { displayKeyPath } from './key-file.ts';
import { ENDPOINT_UNREACHABLE } from './observe-transaction.ts';
import { loadPayerAccount, PAYER_KEY_PATH, resolvePayerAccount } from './payer-key.ts';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

/** The one public HTTP JSON-RPC endpoint this example documents for Base Sepolia. */
export const BASE_SEPOLIA_RPC_URL = 'https://sepolia.base.org';

/** The chain identifier the RPC endpoint must report for `eip155:84532`. */
export const BASE_SEPOLIA_CHAIN_ID = 84532n;

/** Enough test USDC to pay the demonstration price several times over. */
export const MIN_USDC_BASE_UNITS = 1_000_000n;

export const FUNDING_INSTRUCTIONS = [
  'Test USDC: request Base Sepolia USDC for the payer address from a public testnet faucet.',
  'ETH is not required: the facilitator broadcasts the transaction under EIP-3009.',
].join('\n  ');

/**
 * `note` reports something worth seeing that decides nothing. It exists so an observation can be
 * shown without being turned into a requirement, which is how a check nobody needs ends up
 * blocking a run.
 */
export type CheckStatus = 'ok' | 'failed' | 'note' | 'not_evaluated';

export interface PreflightCheck {
  readonly name: string;
  readonly status: CheckStatus;
  /** Bounded, non-quoting explanation. Never contains key material. */
  readonly detail: string;
}

export interface PreflightReport {
  readonly ready: boolean;
  readonly checks: readonly PreflightCheck[];
  /** Public address of the payer. Safe to print, share and fund. */
  readonly payerAddress?: string;
}

const ok = (name: string, detail: string): PreflightCheck => ({ name, status: 'ok', detail });
const failed = (name: string, detail: string): PreflightCheck => ({ name, status: 'failed', detail });
const notEvaluated = (name: string, detail: string): PreflightCheck => ({
  name,
  status: 'not_evaluated',
  detail,
});

/**
 * The one Base Sepolia USDC entry the upstream default-asset registry declares.
 *
 * Read from the registry rather than restated, and failed closed when absent: if the pinned
 * upstream registry stops carrying a Base Sepolia default asset, the run stops here instead of
 * substituting or inventing a token.
 */
export function expectedUsdcAsset(): { asset: string; decimals: number } | undefined {
  const entry = DEFAULT_ASSETS[NETWORK]?.[0];
  if (entry === undefined) return undefined;
  return { asset: entry.asset, decimals: entry.decimals };
}

/**
 * Check that the recipient is an address this network can actually pay.
 *
 * Configuration reaches this example as an environment variable, so it is a string that has never
 * been checked by anything. Left unchecked, a typo is discovered by the chain, after a payment has
 * been built and signed, which is the worst place to find it. It is decided here instead, using the
 * same address rule the rest of the stack uses, before anything opens a connection.
 *
 * Whitespace is refused rather than trimmed. Trimming guesses at what was meant and quietly pays a
 * different address than the one that was configured.
 */
function recipientCheck(payTo: string | undefined): PreflightCheck {
  const name = 'recipient is an EVM address';
  if (payTo === undefined || payTo.length === 0) {
    return failed(name, 'no recipient address configured for the paid resource');
  }
  if (payTo.trim() !== payTo) {
    return failed(name, 'the configured recipient has leading or trailing whitespace');
  }
  if (!isAddress(payTo, { strict: false })) {
    return failed(name, 'the configured recipient is not an EVM address');
  }
  return ok(name, payTo);
}

/**
 * The payer and the recipient have to be two different accounts.
 *
 * A DEMONSTRATION INVARIANT OF THIS EXAMPLE, and nothing more. Neither x402 nor Base forbids
 * paying yourself, and a real integration may have perfectly good reasons to. This example exists
 * to show a payment moving between parties and being recorded as such, and a run where the payer
 * and the recipient are one account produces evidence in which the two roles cannot be told apart
 * by anyone reading it. So it is refused here, on local grounds, before anything reaches a network.
 */
export function distinctRolesCheck(payTo: string, payerAddress: string): PreflightCheck {
  const name = 'payer and recipient are distinct';
  if (payTo.toLowerCase() !== payerAddress.toLowerCase()) {
    return ok(name, 'the payment moves between two accounts');
  }
  return failed(
    name,
    'the configured recipient is the payer address; this example requires them to differ so both ' +
      'roles stay independently observable in the evidence. That is an invariant of this ' +
      'demonstration, not a rule of x402 or of Base',
  );
}

/**
 * Prove the directory that will hold reviewer material is writable, before anything is spent.
 *
 * A probe file is created exclusively, read back, and removed. Nothing else is touched: the real
 * key file for a run is written by the run itself, exclusively, so this check can never overwrite
 * or reserve anything a run will use.
 */
export function reviewerMaterialWritableCheck(outDirectory: string = join(APP_ROOT, 'out')): PreflightCheck {
  const name = 'reviewer key material is writable before any payment';
  const probe = join(outDirectory, `.write-probe-${randomBytes(6).toString('hex')}`);
  try {
    mkdirSync(outDirectory, { recursive: true });
    writeFileSync(probe, 'write probe\n', { flag: 'wx' });
    const readBack = readFileSync(probe, 'utf8');
    rmSync(probe);
    if (readBack !== 'write probe\n') {
      return failed(name, 'the probe file did not read back as written');
    }
    return ok(name, 'a probe file was written, read back and removed');
  } catch (e) {
    try {
      rmSync(probe, { force: true });
    } catch {
      // The probe could not be removed; the directory state is already the reported failure.
    }
    return failed(name, `the output directory could not be written (${(e as Error).message.split('\n')[0]})`);
  }
}

/**
 * Checks that need no network.
 *
 * Separated so they can be exercised offline, including their failure paths, without the suite
 * ever reaching for a connection.
 */
export function checkLocalConfiguration(input: {
  readonly network: Network;
  readonly payTo: string | undefined;
  readonly asset: string;
}): PreflightCheck[] {
  const checks: PreflightCheck[] = [];

  checks.push(
    input.network === NETWORK
      ? ok('network is Base Sepolia', input.network)
      : failed(
          'network is Base Sepolia',
          `configured ${input.network}, this example supports only ${NETWORK}`,
        ),
  );

  checks.push(recipientCheck(input.payTo));

  const usdc = expectedUsdcAsset();
  if (usdc === undefined) {
    checks.push(
      failed(
        'asset is the upstream Base Sepolia USDC entry',
        `the pinned upstream default-asset registry has no entry for ${NETWORK}; update the pin ` +
          'or this example deliberately rather than substituting an asset',
      ),
    );
  } else {
    checks.push(
      input.asset.toLowerCase() === usdc.asset.toLowerCase()
        ? ok('asset is the upstream Base Sepolia USDC entry', input.asset)
        : failed(
            'asset is the upstream Base Sepolia USDC entry',
            `configured ${input.asset}, the upstream registry names ${usdc.asset}`,
          ),
    );
  }

  return checks;
}

/**
 * How long any single request to the configured endpoint may take before it is treated as no
 * answer.
 *
 * An endpoint that never responds is not the same failure as one that refuses a connection: the
 * second returns an error and the first returns nothing at all, so a preparation command without a
 * deadline can sit there indefinitely with no output and no way to tell it apart from slow work.
 * The bound turns that into an ordinary failed check.
 */
export const PREFLIGHT_RPC_TIMEOUT_MS = 12_000;

/**
 * The two endpoint questions this preflight asks, and nothing else.
 *
 * Narrowed to an interface so a test can supply an endpoint that behaves however the case needs,
 * including one that never answers, without a socket and without reconstructing a client.
 */
export interface ChainStateRpc {
  /** The chain identifier, from `eth_chainId`. */
  chainId(): Promise<bigint>;
  /** An ERC-20 balance, from `eth_call` against the token contract. */
  erc20Balance(tokenContract: string, owner: string): Promise<bigint>;
}

/** The `balanceOf(address)` selector, the one call the balance check makes. */
const BALANCE_OF_SELECTOR = '0x70a08231';

/** A chain-state endpoint backed by raw JSON-RPC. Constructed only by a live preflight. */
export function jsonRpcChainState(rpcUrl: string, timeoutMs = PREFLIGHT_RPC_TIMEOUT_MS): ChainStateRpc {
  const call = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    const response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error(`rpc status ${response.status}`);
    const body = (await response.json()) as { result?: unknown; error?: unknown };
    if (body.error !== undefined) throw new Error('rpc error');
    return body.result;
  };
  const quantity = (value: unknown): bigint => {
    if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) {
      throw new Error('the endpoint reported a value this run could not read');
    }
    return BigInt(value);
  };
  return {
    async chainId(): Promise<bigint> {
      return quantity(await call('eth_chainId', []));
    },
    async erc20Balance(tokenContract: string, owner: string): Promise<bigint> {
      const data = `${BALANCE_OF_SELECTOR}${owner.slice(2).toLowerCase().padStart(64, '0')}`;
      return quantity(await call('eth_call', [{ to: tokenContract, data }, 'latest']));
    },
  };
}

/** Named once: the chain-id result decides whether the balance check is worth asking. */
const CHAIN_ID_CHECK = 'endpoint chain id matches Base Sepolia';

/**
 * Chain-identity and balance checks. Opens connections; never called by the offline path.
 *
 * Every request carries a deadline, and a request that does not answer within it becomes a named
 * failed check rather than a wait with no end. The reason recorded is fixed text: an endpoint's
 * own message is written to a terminal and pasted into run notes, and it can say anything at all.
 */
export async function checkChainState(
  payerAddress: string,
  asset: string,
  rpc: ChainStateRpc,
): Promise<PreflightCheck[]> {
  const checks: PreflightCheck[] = [];

  let chainId: bigint;
  try {
    chainId = await rpc.chainId();
  } catch {
    return [
      failed(CHAIN_ID_CHECK, ENDPOINT_UNREACHABLE),
      notEvaluated('payer holds test USDC', 'the endpoint did not answer'),
    ];
  }
  checks.push(
    chainId === BASE_SEPOLIA_CHAIN_ID
      ? ok(CHAIN_ID_CHECK, `eip155:${chainId}`)
      : failed(
          CHAIN_ID_CHECK,
          `endpoint reports eip155:${chainId}, expected eip155:${BASE_SEPOLIA_CHAIN_ID}`,
        ),
  );

  let balance: bigint;
  try {
    balance = await rpc.erc20Balance(asset, payerAddress);
  } catch {
    checks.push(failed('payer holds test USDC', ENDPOINT_UNREACHABLE));
    return checks;
  }
  checks.push(
    balance >= MIN_USDC_BASE_UNITS
      ? ok('payer holds test USDC', `${balance} base units`)
      : failed(
          'payer holds test USDC',
          `${balance} base units, at least ${MIN_USDC_BASE_UNITS} required`,
        ),
  );

  return checks;
}

/**
 * Asks the configured facilitator what it supports, through the upstream client.
 *
 * The wait is bounded by that client rather than here: its configuration applies a per-request
 * deadline to every `getSupported` attempt. So this call cannot hang, and adding a second deadline
 * around it would mean two different components deciding when the same request has failed.
 */
export async function checkFacilitatorSupport(
  facilitatorClient: FacilitatorClient,
  network: Network,
): Promise<PreflightCheck> {
  let supported: Awaited<ReturnType<FacilitatorClient['getSupported']>>;
  try {
    supported = await facilitatorClient.getSupported();
  } catch {
    // Deliberately says nothing the remote party supplied. An exception here carries a message
    // built elsewhere, and this diagnostic is written to a terminal and kept in run notes.
    return failed(
      'facilitator supports the network',
      'the configured facilitator could not be reached or did not answer',
    );
  }
  const match = supported.kinds.find((k) => k.network === network && k.scheme === 'exact');
  return match !== undefined
    ? ok('facilitator supports the network', `exact on ${network}`)
    : failed(
        'facilitator supports the network',
        `no exact scheme advertised for ${network} by the configured facilitator`,
      );
}

/**
 * How the preflight obtains the payer key.
 *
 * `create-if-absent` is what preparing a wallet means: no key yet is the ordinary first run.
 * `require-existing` is what a live run means: it must use the key that was funded, and creating a
 * fresh unfunded one would only move the failure later, into the middle of a payment.
 */
export type PayerKeyMode = 'create-if-absent' | 'require-existing';

export interface PreflightOptions {
  readonly network: Network;
  readonly payTo: string | undefined;
  readonly asset: string;
  readonly rpc: ChainStateRpc;
  readonly facilitatorClient: FacilitatorClient;
  /** Defaults to `create-if-absent`. */
  readonly payerKeyMode?: PayerKeyMode;
  /** Where the payer key file lives. Defaults to the test-network payer key. */
  readonly payerKeyPath?: string;
  /** Where reviewer material will be written. Defaults to the repository `out/` directory. */
  readonly outDirectory?: string;
}

/**
 * The full preflight. Fails closed: any failed check leaves the run not ready.
 *
 * Ordered so that everything decidable locally is decided first. A misconfigured recipient, a
 * missing key or an unwritable output directory is answered before a connection is opened, which
 * keeps the failure cheap and keeps the offline suites able to exercise these paths for real.
 */
export async function runPreflight(options: PreflightOptions): Promise<PreflightReport> {
  const checks = checkLocalConfiguration(options);
  if (checks.some((c) => c.status === 'failed')) {
    return { ready: false, checks };
  }

  const keyPath = options.payerKeyPath ?? PAYER_KEY_PATH;
  let payerAddress: string;
  if (options.payerKeyMode === 'require-existing') {
    const payer = loadPayerAccount(keyPath);
    if (payer === undefined) {
      checks.push(
        failed(
          'payer key present',
          `no payer key at ${displayKeyPath(keyPath)}; run the preparation command to create and fund one`,
        ),
      );
      return { ready: false, checks };
    }
    payerAddress = payer.address;
  } else {
    payerAddress = resolvePayerAccount(keyPath).address;
  }

  // The recipient is an address by now: the local checks above refuse anything else and return
  // before reaching here. These are the last things decidable without a connection, so they are
  // decided before one is opened.
  if (options.payTo === undefined) return { ready: false, checks, payerAddress };
  checks.push(distinctRolesCheck(options.payTo, payerAddress));
  checks.push(reviewerMaterialWritableCheck(options.outDirectory));
  if (checks.some((c) => c.status === 'failed')) return { ready: false, checks, payerAddress };

  checks.push(...(await checkChainState(payerAddress, options.asset, options.rpc)));
  checks.push(await checkFacilitatorSupport(options.facilitatorClient, options.network));
  return {
    ready: !checks.some((c) => c.status !== 'ok' && c.status !== 'note'),
    checks,
    payerAddress,
  };
}

/** Prints a report. The payer address is public and is the one value a person needs to fund. */
export function printReport(report: PreflightReport): void {
  console.log('\nBase Sepolia preflight\n');
  if (report.payerAddress !== undefined) console.log(`  payer address : ${report.payerAddress}\n`);
  for (const check of report.checks) {
    const mark =
      check.status === 'ok'
        ? 'ok  '
        : check.status === 'failed'
          ? 'FAIL'
          : check.status === 'note'
            ? 'note'
            : 'skip';
    console.log(`  ${mark}  ${check.name}: ${check.detail}`);
  }
  if (!report.ready) {
    console.log(`\nNot ready. Resolve the failures above.\n  ${FUNDING_INSTRUCTIONS}\n`);
    return;
  }
  console.log('\nReady. The live demonstration can run.\n');
}

/** Entry point for `demo:live:prepare`. */
export async function main(): Promise<void> {
  const { HTTPFacilitatorClient } = await import('@x402/core/server');
  const usdc = expectedUsdcAsset();
  const rpcUrl = process.env['PEAC_EXAMPLE_RPC_URL'] ?? BASE_SEPOLIA_RPC_URL;
  const report = await runPreflight({
    network: NETWORK,
    payTo: process.env['PEAC_EXAMPLE_PAY_TO'],
    asset: usdc?.asset ?? '',
    rpc: jsonRpcChainState(rpcUrl),
    facilitatorClient: new HTTPFacilitatorClient(),
  });
  printReport(report);
  if (!report.ready) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
