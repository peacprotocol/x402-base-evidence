/**
 * Base Sepolia preflight.
 *
 * Everything a live run needs, checked before anything is signed or sent, so a run either starts
 * from a known-good state or stops with the exact reason and what to do about it. A live run that
 * discovers a missing prerequisite halfway through produces a partial transcript, which is the one
 * outcome an evidence example must not produce.
 *
 * THIS FILE AND THE LIVE DEMONSTRATION ARE THE ONLY PLACES THAT PERFORM EXTERNAL NETWORK I/O.
 * The fixture suites do open loopback sockets — a local origin serving a local client inside one
 * process — but nothing else in the reference flow resolves a name or dials a remote host, and
 * the offline path never calls the network-using checks here; it exercises only the local ones,
 * which is why they are separated below.
 *
 * The payer key is created once and reused; how it is stored and reloaded lives in `payer-key.ts`.
 *
 * WHAT THE PAYER NEEDS, AND WHAT IT DOES NOT. In this x402 facilitator flow, the facilitator
 * submits the authorized transaction and pays gas. The payer therefore needs only Base Sepolia
 * test USDC, and this preflight requires no ETH: the payer signs an EIP-3009 authorization
 * off-chain and never broadcasts anything itself. Who broadcast is recorded in the evidence as
 * `transaction_sender`, an observed fact; no role beyond having broadcast is inferred from it.
 *
 * EVIDENCE OUTPUT COMES BEFORE FUNDS. The last local check proves the `out/` directory a run
 * writes its evidence and verification material into is writable, before any payment is
 * attempted, so there is no state in which funds moved and the material a reviewer needs cannot
 * be written.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isAddress } from 'viem';
import { DEFAULT_ASSETS } from '@x402/evm';
import type { FacilitatorClient } from '@x402/core/server';
import type { Network } from '@x402/core/types';
import { AMOUNT_BASE_UNITS, NETWORK } from '../../fixtures/deterministic.ts';
import {
  JSON_RPC_FAILURE_TEXT,
  JsonRpcFailure,
  admitAbiUint256Word,
  admitRpcQuantity,
  jsonRpcRequest,
} from './evm-json-rpc.ts';
import {
  assertUsableIssuer,
  ISSUER_KEY_PATH,
  IssuerConfigurationError,
  LIVE_ISSUER_ENV,
  storedIssuerBinding,
} from './issuer-key.ts';
import { boundedFsErrorName, displayKeyPath, InvalidKeyFileError } from './key-file.ts';
import { ENDPOINT_UNREACHABLE, publicEndpointReference } from './observe-transaction.ts';
import { loadPayerAccount, PAYER_KEY_PATH, resolvePayerAccount } from './payer-key.ts';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

/** The one public HTTP JSON-RPC endpoint this example documents for Base Sepolia. */
export const BASE_SEPOLIA_RPC_URL = 'https://sepolia.base.org';

/** The chain identifier the RPC endpoint must report for `eip155:84532`. */
export const BASE_SEPOLIA_CHAIN_ID = 84532n;

/**
 * The balance the preflight requires: EXACTLY the intended spend, in base units, derived from the
 * same fixture constant the payment itself uses so the two cannot drift.
 *
 * Least privilege, with no buffer: neither the x402 exact scheme nor the facilitator imposes any
 * balance requirement beyond the authorization's own value (the EIP-3009 `transferWithAuthorization`
 * moves exactly `value`, and the facilitator pays the gas), so requiring more than the run will
 * spend would only instruct operators to park test funds on a demonstration key for no measured
 * technical reason. The client additionally caps what it will sign for at this same amount
 * through its spend controls, so the balance decides whether settlement can succeed while the cap
 * decides what the client is willing to authorize.
 */
export const MIN_USDC_BASE_UNITS = BigInt(AMOUNT_BASE_UNITS);

export const FUNDING_INSTRUCTIONS = [
  'Test USDC: request Base Sepolia USDC for the payer address from a public testnet faucet.',
  'ETH is not required: in this x402 facilitator flow, the facilitator submits the authorized',
  'transaction and pays gas, so the payer needs only Base Sepolia test USDC.',
  'Recipient: set PEAC_EXAMPLE_PAY_TO to a Base Sepolia address the operator controls.',
  'Issuer: set PEAC_EXAMPLE_ISSUER to the absolute http or https URL of the issuing party.',
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
 * Whether a live run's issuer identity is ready, decided without touching key material.
 *
 * TWO CHECKS, BOTH FAIL-CLOSED AND BOTH SIDE-EFFECT-FREE. First, the issuer must be explicitly
 * configured and usable: live mode has no default issuer, so an absent or unusable value is a
 * failed check, no issuer key is created, and no payment is attemptable past it. Second, when an
 * issuer key file already exists, the issuer it records must be the configured one: a mismatch is
 * reported with the stored and configured identities — values the operator supplied, not key
 * material — and the key file is left exactly as it was. Nothing here generates a key; only a run
 * that has passed the whole preflight creates one, at run start.
 */
export function checkIssuerReadiness(
  configuredIssuer: string | undefined,
  keyPath: string = ISSUER_KEY_PATH,
): PreflightCheck[] {
  const configuredName = 'issuer is explicitly configured for live mode';
  const bindingName = 'existing issuer key records the configured issuer';

  if (configuredIssuer === undefined || configuredIssuer.length === 0) {
    return [
      failed(
        configuredName,
        `${LIVE_ISSUER_ENV} is not set; live mode has no default issuer, so no issuer key is ` +
          'created and no payment can be attempted',
      ),
      notEvaluated(bindingName, 'no issuer is configured to compare against'),
    ];
  }
  let issuer: string;
  try {
    issuer = assertUsableIssuer(configuredIssuer);
  } catch (e) {
    const reason =
      e instanceof IssuerConfigurationError
        ? e.message.split('\n')[0] ?? 'the configured issuer cannot be used'
        : 'the configured issuer cannot be used';
    return [
      failed(configuredName, reason),
      notEvaluated(bindingName, 'no usable issuer is configured to compare against'),
    ];
  }

  let stored: string | undefined;
  try {
    stored = storedIssuerBinding(keyPath);
  } catch (e) {
    // The key file exists and is not usable. Its diagnostic already carries the repository-relative
    // path and a bounded reason; the file itself was not modified.
    const reason = e instanceof InvalidKeyFileError ? e.reason : 'the issuer key file could not be read';
    return [ok(configuredName, issuer), failed(bindingName, `the issuer key file was refused: ${reason}`)];
  }
  if (stored === undefined) {
    return [
      ok(configuredName, issuer),
      ok(bindingName, 'no issuer key exists yet; a run will create one bound to the configured issuer'),
    ];
  }
  if (stored === issuer) {
    return [ok(configuredName, issuer), ok(bindingName, 'the stored issuer matches the configured issuer')];
  }
  return [
    ok(configuredName, issuer),
    failed(
      bindingName,
      `the key at ${displayKeyPath(keyPath)} records issuer ${stored}, but this run is configured ` +
        `for ${issuer}. The key file was not modified. Either configure the issuer the key already ` +
        'claims, or move the key file aside so a new key is created for the new issuer',
    ),
  ];
}

/**
 * Prove the evidence output directory (`out/`) is writable, before anything is spent.
 *
 * That directory is where a live run writes its evidence and the public half of its signing key,
 * so this is the "no run may spend funds it cannot document" gate. A probe file is created
 * exclusively, read back, and removed. Nothing else is touched: the real files for a run are
 * written by the run itself, exclusively, so this check can never overwrite or reserve anything a
 * run will use.
 */
export function reviewerMaterialWritableCheck(outDirectory: string = join(APP_ROOT, 'out')): PreflightCheck {
  const name = 'evidence output directory is writable before any payment';
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
    // The caught message embeds the absolute path it failed on, and this detail is printed to a
    // terminal; the allowlisted errno name is the bounded fact worth reporting.
    return failed(name, `the output directory could not be written (${boundedFsErrorName(e)})`);
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

/**
 * A chain-state endpoint backed by raw JSON-RPC. Constructed only by a live preflight.
 *
 * Each value is admitted by its actual RPC type. `eth_chainId` returns an EIP-1474 Quantity. The
 * `eth_call` result of `balanceOf(address)` is NOT a Quantity: it is the ABI-encoded return value
 * of a `uint256`, exactly one 32-byte Data word with its leading zero bytes intact, and it is
 * admitted as that. Reading it with a Quantity rule would refuse well-formed balances (every word
 * with a leading zero byte) while admitting values the Data type forbids.
 */
export function jsonRpcChainState(rpcUrl: string, timeoutMs = PREFLIGHT_RPC_TIMEOUT_MS): ChainStateRpc {
  return {
    async chainId(): Promise<bigint> {
      const chainId = admitRpcQuantity(await jsonRpcRequest(rpcUrl, 'eth_chainId', [], timeoutMs));
      if (chainId === undefined) throw new JsonRpcFailure('unusable');
      return chainId;
    },
    async erc20Balance(tokenContract: string, owner: string): Promise<bigint> {
      const data = `${BALANCE_OF_SELECTOR}${owner.slice(2).toLowerCase().padStart(64, '0')}`;
      const word = admitAbiUint256Word(
        await jsonRpcRequest(rpcUrl, 'eth_call', [{ to: tokenContract, data }, 'latest'], timeoutMs),
      );
      if (word === undefined) throw new JsonRpcFailure('unusable');
      return word;
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

  // A caught endpoint failure is reported through the bounded JSON-RPC failure vocabulary:
  // unreachable or timed out, answered with an RPC error, or structurally unusable. Nothing the
  // endpoint said is repeated.
  const endpointFailureText = (e: unknown): string =>
    e instanceof JsonRpcFailure ? JSON_RPC_FAILURE_TEXT[e.kind] : ENDPOINT_UNREACHABLE;

  let chainId: bigint;
  try {
    chainId = await rpc.chainId();
  } catch (e) {
    return [
      failed(CHAIN_ID_CHECK, endpointFailureText(e)),
      notEvaluated('payer holds test USDC', 'the endpoint did not usefully answer'),
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
  } catch (e) {
    checks.push(failed('payer holds test USDC', endpointFailureText(e)));
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
  /**
   * Issuer readiness for a live run: the configured issuer value, exactly as it arrived, and
   * where the issuer key file lives. When present, the issuer checks run as part of the local
   * phase; the offline suites that exercise other checks omit it.
   */
  readonly issuer?: { readonly configured: string | undefined; readonly keyPath?: string };
}

/**
 * The full preflight. Fails closed: any failed check leaves the run not ready.
 *
 * EVERY EVALUABLE CHECK IS EVALUATED, because the expected stopping point of preparation is this
 * report: an operator who still has to fund the payer, configure the recipient, or configure the
 * issuer needs the payer address, the balance state and every other finding in one pass, not one
 * failure per invocation. The one early return is a required-but-missing payer key, which leaves
 * nothing payer-dependent evaluable and no address to fund. Locally decidable checks still run
 * before any connection is opened.
 */
export async function runPreflight(options: PreflightOptions): Promise<PreflightReport> {
  const checks = checkLocalConfiguration(options);
  if (options.issuer !== undefined) {
    checks.push(...checkIssuerReadiness(options.issuer.configured, options.issuer.keyPath));
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

  const recipientUsable =
    options.payTo !== undefined && checks.every((c) => c.name !== 'recipient is an EVM address' || c.status === 'ok');
  if (recipientUsable && options.payTo !== undefined) {
    checks.push(distinctRolesCheck(options.payTo, payerAddress));
  } else {
    checks.push(
      notEvaluated('payer and recipient are distinct', 'no usable recipient is configured to compare against'),
    );
  }
  checks.push(reviewerMaterialWritableCheck(options.outDirectory));

  // The network checks still run when a local check failed: the report is the stopping point for
  // an operator mid-preparation, and the balance and facilitator findings are exactly what they
  // came for. Nothing past this report is reachable while any check is failed.
  checks.push(...(await checkChainState(payerAddress, options.asset, options.rpc)));
  checks.push(await checkFacilitatorSupport(options.facilitatorClient, options.network));
  return {
    ready: !checks.some((c) => c.status !== 'ok' && c.status !== 'note'),
    checks,
    payerAddress,
  };
}

/**
 * Prints a report. The payer address is public and is the one value a person needs to fund. The
 * caller prints the heading and the safe configuration summary; this prints the findings.
 */
export function printReport(report: PreflightReport): void {
  if (report.payerAddress !== undefined) console.log(`\n  payer address : ${report.payerAddress}\n`);
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

/**
 * The facilitator this example documents for Base Sepolia testing, which is also the pinned
 * upstream client's own default. Overridable through `PEAC_EXAMPLE_FACILITATOR_URL`, and always
 * constructed EXPLICITLY with the resolved URL, so what the run talks to is what the report
 * printed rather than whatever a library default resolves to at call time.
 */
export const DEFAULT_FACILITATOR_URL = 'https://x402.org/facilitator';

export const FACILITATOR_URL_ENV = 'PEAC_EXAMPLE_FACILITATOR_URL';
export const RPC_URL_ENV = 'PEAC_EXAMPLE_RPC_URL';
export const PAY_TO_ENV = 'PEAC_EXAMPLE_PAY_TO';

/**
 * A configured endpoint that cannot be admitted. The message names the environment variable and
 * the rule that refused it, and NEVER echoes the configured value: a refused endpoint string can
 * carry a credential, and this message is printed to terminals and pasted into run notes.
 */
export class EndpointConfigurationError extends Error {}

/** Hosts this example treats as loopback, where plain http is acceptable for local fixtures. */
const LOOPBACK_HOST = /^(localhost|127(?:\.\d{1,3}){3}|::1)$/;

/**
 * Admit a configured endpoint URL, or refuse it with a bounded reason.
 *
 * Example-local admission for the two endpoint variables this example reads, not a general
 * request-safety layer: the value must parse as an absolute URL, must use `https:` for any
 * non-loopback host (`http:` is admitted for loopback only, which is what the fixture and local
 * development paths use), must carry no embedded credentials, and no other scheme is admitted.
 * The value itself is never echoed on refusal; only the variable name and the violated rule are.
 */
export function admitEndpointUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new EndpointConfigurationError(`${name} is not an absolute URL`);
  }
  if (url.username !== '' || url.password !== '') {
    throw new EndpointConfigurationError(`${name} must not carry embedded credentials`);
  }
  if (url.protocol === 'https:') return value;
  if (url.protocol === 'http:') {
    if (LOOPBACK_HOST.test(url.hostname)) return value;
    throw new EndpointConfigurationError(`${name} must use https for a non-loopback host`);
  }
  throw new EndpointConfigurationError(`${name} must be an http or https URL`);
}

/** The RPC endpoint a live command uses: the documented public endpoint, or the admitted override. */
export function resolvedRpcUrl(): string {
  return admitEndpointUrl(RPC_URL_ENV, process.env[RPC_URL_ENV] ?? BASE_SEPOLIA_RPC_URL);
}

/** The facilitator a live command uses: the documented testing default, or the admitted override. */
export function resolvedFacilitatorUrl(): string {
  return admitEndpointUrl(
    FACILITATOR_URL_ENV,
    process.env[FACILITATOR_URL_ENV] ?? DEFAULT_FACILITATOR_URL,
  );
}

/**
 * Resolve both live endpoints, or stop with the bounded refusal and no stack trace.
 *
 * Entry points use this instead of calling the resolvers directly so a refused configuration
 * prints one line naming the variable and the rule — never the configured value, and never a
 * stack trace carrying absolute local paths.
 */
export function resolveEndpointsOrExit(): { rpcUrl: string; facilitatorUrl: string } {
  try {
    return { rpcUrl: resolvedRpcUrl(), facilitatorUrl: resolvedFacilitatorUrl() };
  } catch (e) {
    if (e instanceof EndpointConfigurationError) {
      console.error(`\nFAIL  ${e.message}\n`);
      process.exit(1);
    }
    throw e;
  }
}

/**
 * The safe configuration summary a live command prints: public addresses, identities the operator
 * configured, and endpoint ORIGINS only. Never a private key, never a full endpoint URL (a path
 * or query can carry a credential), and never an absolute local path.
 */
export function printSafeConfiguration(input: {
  readonly rpcUrl: string;
  readonly facilitatorUrl: string;
  readonly asset: string | undefined;
  readonly assetDecimals: number | undefined;
  readonly amountBaseUnits: string;
}): void {
  console.log('  configuration (safe values only)');
  console.log(`    network             : ${NETWORK} (Base Sepolia)`);
  console.log(`    token contract      : ${input.asset ?? '(no upstream default asset entry)'}`);
  console.log(
    `    required amount     : ${input.amountBaseUnits} base units` +
      (input.assetDecimals !== undefined ? ` (10^-${input.assetDecimals} USDC units)` : ''),
  );
  console.log(`    recipient           : ${process.env[PAY_TO_ENV] !== undefined ? process.env[PAY_TO_ENV] : `(unset; set ${PAY_TO_ENV})`}`);
  console.log(`    issuer              : ${process.env[LIVE_ISSUER_ENV] !== undefined ? process.env[LIVE_ISSUER_ENV] : `(unset; set ${LIVE_ISSUER_ENV})`}`);
  console.log(`    rpc endpoint origin : ${publicEndpointReference(input.rpcUrl) ?? '(not a usable http or https URL)'}`);
  console.log(`    facilitator origin  : ${publicEndpointReference(input.facilitatorUrl) ?? '(not a usable http or https URL)'}`);
}

/** Entry point for `demo:live:prepare`. */
export async function main(): Promise<void> {
  const { HTTPFacilitatorClient } = await import('@x402/core/server');
  const usdc = expectedUsdcAsset();
  const { rpcUrl, facilitatorUrl } = resolveEndpointsOrExit();
  const report = await runPreflight({
    network: NETWORK,
    payTo: process.env[PAY_TO_ENV],
    asset: usdc?.asset ?? '',
    rpc: jsonRpcChainState(rpcUrl),
    facilitatorClient: new HTTPFacilitatorClient({ url: facilitatorUrl }),
    issuer: { configured: process.env[LIVE_ISSUER_ENV] },
  });
  console.log('\nBase Sepolia preflight\n');
  printSafeConfiguration({
    rpcUrl,
    facilitatorUrl,
    asset: usdc?.asset,
    assetDecimals: usdc?.decimals,
    amountBaseUnits: AMOUNT_BASE_UNITS,
  });
  printReport(report);
  if (!report.ready) process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
