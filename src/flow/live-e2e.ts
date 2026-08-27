/**
 * The Base Sepolia live acceptance run: the smallest real flow, end to end.
 *
 * One paid request. A local origin behind the real x402 middleware advertises the exact scheme on
 * Base Sepolia USDC; the real upstream EVM exact client signs a real EIP-3009 authorization with
 * the local payer key; the configured facilitator verifies and settles it; the origin result is
 * written; and the evidence layer records what every party said: the native x402 artifacts, the
 * origin-observed request and result bindings, the facilitator's settlement report, and a
 * SEPARATELY ATTRIBUTED Base Sepolia RPC observation of the settlement transaction. A signed PEAC
 * record covers the digests, the directory is verified offline before it is finalized, and a
 * tamper demonstration proves the verification actually fails when one bound byte changes.
 *
 * WHAT THE OBSERVATION CLAIMS, AT MOST. The strongest claim a passing run makes is exactly this:
 * the named Base RPC source reported the transaction in a sealed L2 block, and the admitted
 * receipt contained the expected token transfer. Nothing here uses the `pending` tag, treats a
 * preconfirmation as acceptance, checks L1 batch inclusion or finality, or counts confirmations.
 *
 * THE FUNDING BOUNDARY. `demo:live:prepare` (preflight.ts) is the expected first stop: it prints
 * the payer address to fund and every configuration requirement, and it spends nothing. This
 * runner re-runs the same preflight and REFUSES to proceed unless every check passes, so a
 * payment is attemptable only from a fully prepared state. Running this command is what
 * authorizes the one live payment; nothing here retries a payment or pays more than once per run.
 *
 * BOUNDED OBSERVATION, NOT A PROTOCOL GUARANTEE. After the facilitator reports settlement, the
 * runner polls the configured Base Sepolia RPC on a fixed cadence within a fixed total deadline.
 * The cadence tracks the documented ~2s sealed-L2 block interval and the deadline is an
 * implementation decision of this example; neither is a claim about how fast the network seals.
 * Only transient states are retried (not found; endpoint temporarily unavailable; a receipt whose
 * sealed-block agreement has not yet been established). Definitive admitted results stop the loop
 * immediately: a reverted execution fails the acceptance, an admitted sealed receipt whose
 * expected transfer is definitively absent or different fails it, and a fully agreeing sealed-L2
 * inclusion with the expected transfer passes it. In every failing case the material is preserved
 * and written, because a failed live run is evidence too.
 */
import { cpSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { HTTPFacilitatorClient } from '@x402/core/server';
import type {
  PaymentPayloadContext,
  PaymentPayloadResult,
  PaymentRequirements,
  SchemeNetworkClient,
} from '@x402/core/types';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { registerExactEvmScheme } from '@x402/evm/exact/server';
import type { ClientEvmSigner } from '@x402/evm';
import {
  PAYMENT_IDENTIFIER,
  appendPaymentIdentifierToExtensions,
  declarePaymentIdentifierExtension,
  generatePaymentId,
} from '@x402/extensions/payment-identifier';
import type { PrivateKeyAccount } from 'viem/accounts';
import {
  AMOUNT_BASE_UNITS,
  ASSET_EIP712_VERSION,
  ASSET_NAME,
  MAX_TIMEOUT_SECONDS,
  NETWORK,
  ORIGIN_RESULT_BODY,
} from '../../fixtures/deterministic.ts';
import { HASH32 } from './evm-json-rpc.ts';
import { buildEvidence, RESOURCE_PATH, RESOURCE_QUERY, type RunResult } from './fixture-e2e.ts';
import {
  prepareRunOutputs,
  runEvidenceDir,
  runEvidenceDisplay,
  runPublicKeyDisplay,
  runPublicKeyPath,
  writeEvidenceTransactionally,
} from './issue-record.ts';
import { LIVE_ISSUER_ENV, resolveIssuerKey } from './issuer-key.ts';
import {
  baseSealedRpcSource,
  observeSealedTransaction,
  publicEndpointReference,
  transferMatchesExpected,
  type ExpectedTransfer,
  type SealedRpcObservationV1,
} from './observe-transaction.ts';
import { loadPayerAccount, PAYER_KEY_PATH } from './payer-key.ts';
import {
  expectedUsdcAsset,
  FUNDING_INSTRUCTIONS,
  jsonRpcChainState,
  PAY_TO_ENV,
  printReport,
  printSafeConfiguration,
  resolvedFacilitatorUrl,
  resolvedRpcUrl,
  runPreflight,
} from './preflight.ts';
import { createPaidResource, type RequestObservation } from './server.ts';
import { fetchPaidResource } from './client.ts';
import { formatReport, verifyEvidence } from './verify-evidence.ts';

/**
 * The loopback port the live origin listens on. Fixed rather than ephemeral so the resource URL
 * the 402 challenge advertises is the URL the origin is actually serving; a port already in use
 * fails the run before anything is signed or sent.
 */
export const LIVE_ORIGIN_PORT = 4021;

/**
 * The observation cadence and total deadline. The cadence tracks the documented ~2s sealed-L2
 * block interval on Base; the deadline bounds the whole loop. Both are implementation decisions
 * of this example, stated here once, and neither is a protocol guarantee.
 */
export const LIVE_OBSERVATION_POLL_MS = 2_000;
export const LIVE_OBSERVATION_DEADLINE_MS = 45_000;

/**
 * The client-side wallet for the live run: the genuine upstream EVM exact scheme, signing with
 * the local payer key, plus the payment identifier appended through the upstream extension API.
 * The same one-interface seam the fixture wallet occupies, occupied by the real thing.
 */
class LivePayerWallet implements SchemeNetworkClient {
  readonly scheme = 'exact';
  private readonly upstream: ExactEvmScheme;
  private readonly paymentId: string;

  constructor(signer: ClientEvmSigner, paymentId: string) {
    this.upstream = new ExactEvmScheme(signer);
    this.paymentId = paymentId;
  }

  async createPaymentPayload(
    x402Version: number,
    paymentRequirements: PaymentRequirements,
    context?: PaymentPayloadContext,
  ): Promise<PaymentPayloadResult> {
    const result = await this.upstream.createPaymentPayload(x402Version, paymentRequirements, context);
    // The upstream helper appends only when the server declared the extension, and it writes into
    // the declaration object it is given; a copy is passed so the server's own declaration is not
    // mutated by a client running in the same process.
    const declared = structuredClone(context?.extensions ?? {}) as Record<string, unknown>;
    const appended = appendPaymentIdentifierToExtensions(declared, this.paymentId);
    const extensions = { ...(result.extensions ?? {}), ...appended };
    return {
      ...result,
      ...(Object.keys(extensions).length > 0 ? { extensions } : {}),
    };
  }
}

/** How the bounded observation loop ended. Every branch preserves the last observation made. */
export interface LiveObservationResult {
  readonly outcome: 'matched' | 'reverted' | 'wrong_transfer' | 'not_established';
  readonly observation?: SealedRpcObservationV1;
}

/**
 * Poll the sealed source for one transaction until a definitive admitted result or the deadline.
 *
 * The clock and sleep are injectable so the suites can exercise every branch without waiting on
 * real time; the live entry point below supplies the real ones.
 */
export async function observeUntilSealed(input: {
  readonly observe: (observedAtUnixSeconds: number) => Promise<SealedRpcObservationV1>;
  readonly nowMs?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly expectedTransfer: ExpectedTransfer;
  readonly pollMs?: number;
  readonly deadlineMs?: number;
}): Promise<LiveObservationResult> {
  const nowMs = input.nowMs ?? Date.now;
  const sleep = input.sleep ?? (async (ms: number): Promise<void> => void (await delay(ms)));
  const pollMs = input.pollMs ?? LIVE_OBSERVATION_POLL_MS;
  const deadlineMs = input.deadlineMs ?? LIVE_OBSERVATION_DEADLINE_MS;
  const startedAt = nowMs();

  let observation: SealedRpcObservationV1 | undefined;
  for (;;) {
    observation = await input.observe(Math.floor(nowMs() / 1000));

    if (observation.observation_state === 'found' && observation.receipt_status === 'reverted') {
      // A definitive admitted execution result: the transaction ran and reverted. No amount of
      // further polling changes it, and it fails the acceptance with its material preserved.
      return { outcome: 'reverted', observation };
    }
    if (
      observation.observation_state === 'found' &&
      observation.observation_level === 'l2_block_inclusion'
    ) {
      // Sealed inclusion established from a complete admitted receipt. The transfer verdict is
      // now definitive either way: the receipt's full log set was admitted, so the expected
      // transfer is either present or definitively not.
      const matched =
        observation.token_transfer !== undefined &&
        transferMatchesExpected(observation.token_transfer, input.expectedTransfer);
      return { outcome: matched ? 'matched' : 'wrong_transfer', observation };
    }

    // Everything else is transient for the purposes of this loop: not yet found, endpoint
    // temporarily unavailable or answering unusably, or a receipt whose sealed-block agreement
    // has not yet been established. Retry within the deadline; on expiry, report honestly that
    // sealed inclusion was not established, with the last observation preserved.
    if (nowMs() - startedAt + pollMs > deadlineMs) {
      return { outcome: 'not_established', observation };
    }
    await sleep(pollMs);
  }
}

/** One live paid exchange against the local origin, using the real facilitator and wallet. */
async function runLiveOnce(input: {
  readonly payTo: string;
  readonly asset: string;
  readonly facilitatorUrl: string;
  readonly payer: PrivateKeyAccount;
  readonly paymentId: string;
}): Promise<RunResult> {
  const resourceUrl = `http://127.0.0.1:${LIVE_ORIGIN_PORT}${RESOURCE_PATH}${RESOURCE_QUERY}`;
  const resource = await createPaidResource({
    facilitatorClient: new HTTPFacilitatorClient({ url: input.facilitatorUrl }),
    registerSchemes: (server) => {
      registerExactEvmScheme(server, { networks: [NETWORK] });
    },
    network: NETWORK,
    payTo: input.payTo,
    price: {
      asset: input.asset,
      amount: AMOUNT_BASE_UNITS,
      extra: { name: ASSET_NAME, version: ASSET_EIP712_VERSION },
    },
    method: 'GET',
    path: RESOURCE_PATH,
    resourceUrl,
    maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
    declaredExtensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    // The paid result is the same synthetic JSON body the fixture serves: deliberately free of
    // anything sensitive, so the whole evidence directory can be shared for review.
    handler: () => ({ status: 200, contentType: 'application/json', body: ORIGIN_RESULT_BODY }),
  });

  const server = resource.app.listen(LIVE_ORIGIN_PORT, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve());
    server.once('error', reject);
  });
  const { address, port } = server.address() as AddressInfo;

  try {
    const client = await fetchPaidResource(
      {
        baseUrl: `http://127.0.0.1:${port}`,
        network: NETWORK,
        registerSchemes: (c) => {
          c.setSpendControls({ allowedAssets: [{ network: NETWORK, asset: input.asset }] });
          c.register(NETWORK, new LivePayerWallet(input.payer, input.paymentId));
        },
      },
      `${RESOURCE_PATH}${RESOURCE_QUERY}`,
    );
    if (resource.observations.length !== 2) {
      throw new Error(`expected two origin observations, recorded ${resource.observations.length}`);
    }
    const [challenge, origin] = resource.observations as readonly [RequestObservation, RequestObservation];
    return {
      client,
      challenge,
      origin,
      terminalState: origin.lifecycle.terminalState,
      listenerAuthority: `${address}:${port}`,
    };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const LIVE_RUN_NOTE = 'live-run-note.txt';

function liveRunNote(input: {
  readonly runId: string;
  readonly rpcReference: string;
  readonly observationStatement: string | undefined;
  readonly accepted: boolean;
}): string {
  return [
    'Live run on Base Sepolia',
    '',
    `Run identifier: ${input.runId}`,
    `Network: ${NETWORK} (Base Sepolia, a test network)`,
    '',
    'This directory describes ONE live run: a real EIP-3009 authorization signed by the local',
    'payer key, presented to the configured facilitator, with the settlement transaction',
    'observed through a separately attributed Base Sepolia RPC source. The request binding',
    'carries the components the origin actually observed, port included, so these bytes are not',
    'reproducible by rerunning; they describe the run that happened.',
    '',
    input.accepted
      ? 'Live acceptance PASSED. The strongest claim this run makes is exactly this: the named ' +
        'Base RPC source reported the transaction in a sealed L2 block, and the admitted receipt ' +
        'contained the expected token transfer.'
      : 'Live acceptance DID NOT PASS. The evidence records what was observed; see the chain ' +
        'observation document for the recorded state.',
    '',
    `RPC source: ${input.rpcReference}`,
    ...(input.observationStatement !== undefined ? ['', `Observation: ${input.observationStatement}`] : []),
    '',
    'No claim is made about L1 batch inclusion, L1 finality, or preconfirmation state, and no',
    'confirmation counts were used. Verification of this directory establishes integrity and',
    'internal consistency under the supplied key, never external truth.',
    '',
  ].join('\n');
}

/** Entry point for `demo:live`. Runs preflight first and refuses to pay from an unready state. */
export async function main(): Promise<void> {
  const usdc = expectedUsdcAsset();
  const rpcUrl = resolvedRpcUrl();
  const facilitatorUrl = resolvedFacilitatorUrl();
  const payTo = process.env[PAY_TO_ENV];

  console.log('\nBase Sepolia live acceptance run\n');
  printSafeConfiguration({
    rpcUrl,
    facilitatorUrl,
    asset: usdc?.asset,
    assetDecimals: usdc?.decimals,
    amountBaseUnits: AMOUNT_BASE_UNITS,
  });

  // The same preflight `demo:live:prepare` runs, with the payer key REQUIRED to exist: a live run
  // must use the key that was funded, and creating a fresh unfunded one here would only move the
  // failure into the middle of a payment.
  const report = await runPreflight({
    network: NETWORK,
    payTo,
    asset: usdc?.asset ?? '',
    rpc: jsonRpcChainState(rpcUrl),
    facilitatorClient: new HTTPFacilitatorClient({ url: facilitatorUrl }),
    payerKeyMode: 'require-existing',
    issuer: { configured: process.env[LIVE_ISSUER_ENV] },
  });
  printReport(report);
  if (!report.ready) {
    console.log(`Stopping BEFORE any payment: the preflight is not ready.\n  ${FUNDING_INSTRUCTIONS}\n`);
    process.exit(1);
  }
  if (usdc === undefined || payTo === undefined) {
    // Unreachable past a ready preflight; stated for the type system and for honesty.
    throw new Error('preflight reported ready without a resolved asset and recipient');
  }

  // Everything a reviewer needs is claimed and written BEFORE anything is spent.
  const issuerKey = await resolveIssuerKey('live');
  const payer = loadPayerAccount(PAYER_KEY_PATH);
  if (payer === undefined) throw new Error('preflight reported ready without a payer key');
  const runId = `live-${new Date().toISOString().replace(/[-:.]/g, '').slice(0, 15)}z`;
  const evidenceDirectory = runEvidenceDir(runId);
  const publicKeyFile = runPublicKeyPath(runId);
  prepareRunOutputs({ evidenceDirectory, publicKeyFile, issuerKey });
  console.log(`  run id        : ${runId}`);
  console.log(`  evidence goes : ${runEvidenceDisplay(runId)}`);
  console.log(`  public key    : ${runPublicKeyDisplay(runId)}\n`);

  // THE ONE LIVE PAYMENT.
  const paymentId = generatePaymentId();
  const run = await runLiveOnce({
    payTo,
    asset: usdc.asset,
    facilitatorUrl,
    payer,
    paymentId,
  });
  console.log(`  unpaid status  : ${run.client.unpaidStatus}`);
  console.log(`  paid status    : ${run.client.paidStatus}`);
  console.log(`  lifecycle      : ${run.origin.lifecycle.states.join(' -> ')}`);
  console.log(`  terminal state : ${run.terminalState}`);

  const settled = run.terminalState === 'response_write_attempted';
  const transactionHash = run.origin.lifecycle.transaction;

  // The separately attributed RPC observation, only for a settlement the facilitator reported,
  // and only through a transaction reference admitted as a 32-byte hash first.
  const rpcSource = baseSealedRpcSource(rpcUrl);
  const expectedTransfer: ExpectedTransfer = {
    token_contract: usdc.asset,
    transfer_from: payer.address,
    transfer_to: payTo,
    transfer_amount: AMOUNT_BASE_UNITS,
  };
  let observed: LiveObservationResult = { outcome: 'not_established' };
  if (settled && transactionHash !== undefined && HASH32.test(transactionHash)) {
    console.log(`\n  observing ${transactionHash} through ${rpcSource.reference} ...`);
    observed = await observeUntilSealed({
      observe: (observedAtUnixSeconds) =>
        observeSealedTransaction({
          source: rpcSource,
          transactionHash,
          expectedTransfer,
          observedAtUnixSeconds,
        }),
      expectedTransfer,
    });
    console.log(`  observation outcome: ${observed.outcome}`);
    if (observed.observation !== undefined) console.log(`  ${observed.observation.statement}`);
  } else if (settled) {
    console.log('\n  the settlement response carried no 32-byte transaction reference; no RPC observation was made');
  }

  // Evidence is written whatever the outcome: a failed live run is evidence too. The record binds
  // the components the origin observed for the request that actually happened.
  const components = run.origin.components;
  if (components === undefined) throw new Error('the origin recorded no request components for the paid request');
  const layout = await buildEvidence(run, {
    mode: 'live',
    requestIdentity: { kind: 'observed', components },
    requestBody: new Uint8Array(0),
    observedAtUnixSeconds: Math.floor(Date.now() / 1000),
    observationSource: {
      kind: 'facilitator',
      reference: publicEndpointReference(facilitatorUrl) ?? 'the configured facilitator',
    },
    ...(observed.observation !== undefined ? { rpcObservation: observed.observation } : {}),
    assetDecimals: usdc.decimals,
    paymentReference: paymentId,
    currency: 'USDC',
    // The registered commerce `env` field: Base Sepolia is a test network, so the record says so.
    environment: 'test',
  });

  const accepted = settled && observed.outcome === 'matched';
  await writeEvidenceTransactionally({
    finalDirectory: evidenceDirectory,
    layout,
    finalize: async (staged) => {
      const verification = await verifyEvidence(staged, issuerKey.publicKey);
      writeFileSync(
        join(staged, 'verification-report.txt'),
        formatReport(runEvidenceDisplay(runId), verification).trimStart(),
      );
      writeFileSync(
        join(staged, LIVE_RUN_NOTE),
        liveRunNote({
          runId,
          rpcReference: rpcSource.reference,
          observationStatement: observed.observation?.statement,
          accepted,
        }),
      );
      if (!verification.ok) {
        throw new Error('the freshly issued evidence did not verify; the staged directory is preserved');
      }
    },
  });
  console.log(`\n  evidence written and verified offline: ${runEvidenceDisplay(runId)}`);
  console.log(
    `  verify again: pnpm verify -- --evidence ${runEvidenceDisplay(runId)} --public-key ${runPublicKeyDisplay(runId)}`,
  );

  // The tamper demonstration: one bound byte changes in a COPY, and verification must fail. The
  // copy is a scratch artifact and is removed after the property is proven.
  const tamperDirectory = join(evidenceDirectory, '..', `${runId}-tamper-check`);
  cpSync(evidenceDirectory, tamperDirectory, { recursive: true });
  const tamperTarget = join(tamperDirectory, 'origin-result-body.bin');
  const bytes = readFileSync(tamperTarget);
  if (bytes.length === 0) throw new Error('the origin result body is empty; nothing to tamper');
  bytes[0] = (bytes[0] ?? 0) ^ 0xff;
  writeFileSync(tamperTarget, bytes);
  const tampered = await verifyEvidence(tamperDirectory, issuerKey.publicKey);
  rmSync(tamperDirectory, { recursive: true, force: true });
  if (tampered.ok) {
    console.error('\n  TAMPER CHECK FAILED: an altered origin result still verified.');
    process.exit(1);
  }
  console.log('  tamper check: one altered byte in a copy failed verification, as it must\n');

  if (!accepted) {
    console.error(
      'Live acceptance DID NOT PASS: ' +
        (settled
          ? `the RPC observation outcome was ${observed.outcome}`
          : `the run ended in ${run.terminalState}`) +
        '. The evidence and observation material are preserved above.\n',
    );
    process.exit(1);
  }
  console.log(
    'Live acceptance PASSED. The named Base RPC source reported the transaction in a sealed L2\n' +
      'block, and the admitted receipt contained the expected token transfer.\n',
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
