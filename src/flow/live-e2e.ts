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
 * tamper demonstration shows the verification failing when one bound byte changes.
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
 * Retryable and terminal states are classified explicitly, fail-closed: retried are exactly a
 * transaction not yet found, a transport-level failure, an explicitly admitted temporary HTTP
 * status, and a receipt whose sealed-block agreement has not yet been established. An RPC error,
 * a structurally unusable response and every unclassified condition are terminal. Definitive
 * admitted results stop the loop immediately: a reverted execution fails the acceptance, an
 * admitted sealed receipt whose expected transfer is definitively absent or different fails it,
 * and a fully agreeing sealed-L2 inclusion with the expected transfer passes it. Every terminal
 * and exception path preserves the run material that safely exists at that point (see
 * `executeLiveRun` below), and the failure-injection vectors in the EVM matrix are what make
 * that sentence checkable rather than aspirational.
 */
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { HTTPFacilitatorClient } from '@x402/core/server';
import type { BeforePaymentCreationHook, ClientExtension } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { registerExactEvmScheme } from '@x402/evm/exact/server';
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
import { SUPPORTED_ASSET_TRANSFER_METHODS } from '../x402-header.ts';
import { buildEvidence, RESOURCE_PATH, RESOURCE_QUERY, type RunResult } from './fixture-e2e.ts';
import type { EvidenceLayout } from './issue-record.ts';
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
  RETRYABLE_UNAVAILABLE_REASONS,
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
  resolveEndpointsOrExit,
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
 * The payment-identifier extension, injected through the upstream client-extension API.
 *
 * `x402Client.registerExtension` is the pinned upstream's own seam for enriching a payment
 * payload's extension data after the scheme builds it, so no wrapper around the scheme client is
 * needed for this. The upstream append helper reads the server's declaration out of the payload's
 * merged extensions and appends the identifier only when the server declared support; when the
 * server did not, the payload is returned unchanged, which is exactly the no-op behaviour the
 * upstream contract asks of a declaration-gated client extension.
 */
export function paymentIdentifierClientExtension(paymentId: string): ClientExtension {
  return {
    key: PAYMENT_IDENTIFIER,
    enrichPaymentPayload: async (paymentPayload) => {
      // A copy is enriched so no object shared with the decoded challenge is mutated in place.
      const extensions = structuredClone(paymentPayload.extensions ?? {}) as Record<string, unknown>;
      appendPaymentIdentifierToExtensions(extensions, paymentId);
      return { ...paymentPayload, extensions };
    },
  };
}

/**
 * Refuse to sign for any asset-transfer method outside this reference's EIP-3009 scope, at the
 * moment the selection is known and BEFORE the payer signs anything.
 *
 * The check runs in the upstream `onBeforePaymentCreation` hook, which fires with the selected
 * payment requirement before the scheme client builds or signs a payload. An explicit `eip3009`
 * is accepted; an ABSENT method is accepted because the pinned upstream scheme routes an absent
 * method to EIP-3009 (`paymentRequirements.extra?.assetTransferMethod ?? "eip3009"`, measured in
 * the installed package); `permit2` and every unknown value are refused. Without this guard the
 * upstream router would fall through to EIP-3009 signing for an unknown method value, signing a
 * payload under a method the requirement never selected. Native x402 remains the authority on
 * payment validity; this is local admission to the reference's declared scope.
 */
export function eip3009SelectionGuard(): BeforePaymentCreationHook {
  return async (context) => {
    const method = (
      context.selectedRequirements.extra as { assetTransferMethod?: unknown } | undefined
    )?.assetTransferMethod;
    if (method === undefined) return undefined;
    if (
      typeof method === 'string' &&
      (SUPPORTED_ASSET_TRANSFER_METHODS as readonly string[]).includes(method)
    ) {
      return undefined;
    }
    return {
      abort: true,
      reason: 'the selected requirement names an asset-transfer method outside the eip3009 scope of this reference',
    };
  };
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

    if (observation.observation_state === 'unavailable') {
      // Explicit terminal-versus-retryable classification, fail-closed. Retryable is exactly the
      // transport failure and the explicitly admitted temporary HTTP statuses; an RPC error, a
      // structurally unusable response, a malformed transaction reference, a local failure, and
      // any reason this code does not recognize are terminal, reported honestly as
      // not-established with the observation preserved. Asking again cannot make a malformed
      // answer well-formed, and an unclassified condition is not retried into being transient.
      const reason = observation.unavailable_reason;
      if (reason === undefined || !RETRYABLE_UNAVAILABLE_REASONS.has(reason)) {
        return { outcome: 'not_established', observation };
      }
    }

    // What remains is transient for the purposes of this loop: not yet found, a retryable
    // endpoint condition, or a receipt whose sealed-block agreement has not yet been established.
    // Retry within the deadline; on expiry, report honestly that sealed inclusion was not
    // established, with the last observation preserved.
    if (nowMs() - startedAt + pollMs > deadlineMs) {
      return { outcome: 'not_established', observation };
    }
    await sleep(pollMs);
  }
}

// ---------------------------------------------------------------------------------------------
// Run-attempt durability across the irreversible payment boundary.
//
// THE INVARIANT: once creation and transmission of a live payment authorization can begin, every
// subsequent terminal and exception path preserves the run material that safely exists at that
// point, and no path ever attempts a second payment. The mechanism is example-local and small: a
// run-attempt directory created BEFORE the payment with non-secret attempt metadata, and one
// orchestrator that runs the phases in order and, on any throw, writes the bounded material it
// holds into that directory before failing. Nothing here is a transaction system, an outbox or a
// workflow engine; it is a directory, a JSON file, and a try/catch in the right place.
// ---------------------------------------------------------------------------------------------

/** Where a live run failed, from the orchestrator's own vantage point. */
export type LiveRunStage =
  | 'payment_exchange'
  | 'rpc_observation'
  | 'evidence_assembly'
  | 'evidence_finalization';

/**
 * A live run that failed after the payment boundary was reachable.
 *
 * Carries the stage and NOTHING of the underlying error: an exception message can embed an
 * absolute path, an OS error, or remote text, and this error's message is printed by the entry
 * point and may be pasted into run notes. The preserved attempt directory is where the bounded
 * material lives.
 */
export class LiveRunFailure extends Error {
  readonly stage: LiveRunStage;
  constructor(stage: LiveRunStage) {
    super(
      `the live run failed during ${stage}; the material that safely existed was preserved in ` +
        'the run-attempt directory, and no second payment was attempted',
    );
    this.name = 'LiveRunFailure';
    this.stage = stage;
  }
}

/** The phases of one live run, injectable so failure at every boundary can be exercised. */
export interface LiveRunPhases {
  /** The one paid exchange. Called AT MOST ONCE; a failure is preserved, never retried. */
  readonly payment: () => Promise<RunResult>;
  readonly observe: (run: RunResult) => Promise<LiveObservationResult>;
  readonly assemble: (run: RunResult, observed: LiveObservationResult) => Promise<EvidenceLayout>;
  readonly finalize: (
    layout: EvidenceLayout,
    run: RunResult,
    observed: LiveObservationResult,
  ) => Promise<void>;
}

export interface LiveRunOutcome {
  readonly run: RunResult;
  readonly observed: LiveObservationResult;
}

const ATTEMPT_FILE = 'attempt.json';
const RUN_MATERIAL_FILE = 'run-material.json';

/** Visible-ASCII bound for preserved field values, matching the capture boundary's admission. */
const PRESERVABLE_FIELD_VALUE = /^[\x21-\x7e]{1,16384}$/;

const boundedFieldValue = (value: string | undefined): string | null =>
  value !== undefined && PRESERVABLE_FIELD_VALUE.test(value) ? value : null;

/**
 * Create the run-attempt directory and record that a payment is about to become attemptable.
 *
 * Written BEFORE the payment phase, and holding ONLY non-secret metadata: identifiers, public
 * addresses, endpoint origins and a timestamp. Never key material, never a full endpoint URL,
 * never an absolute local path.
 */
export function beginLiveAttempt(input: {
  readonly attemptDirectory: string;
  readonly runId: string;
  readonly metadata: Readonly<Record<string, string>>;
}): void {
  mkdirSync(input.attemptDirectory, { recursive: true });
  writeFileSync(
    join(input.attemptDirectory, ATTEMPT_FILE),
    `${JSON.stringify(
      {
        note: 'Non-secret attempt record, written before any payment is attemptable.',
        run_id: input.runId,
        state: 'payment_attempt_begun',
        started_at: new Date().toISOString(),
        ...input.metadata,
      },
      null,
      2,
    )}\n`,
  );
}

function writeAttemptState(
  attemptDirectory: string,
  runId: string,
  state: 'completed' | 'failed',
  failedStage?: LiveRunStage,
): void {
  writeFileSync(
    join(attemptDirectory, ATTEMPT_FILE),
    `${JSON.stringify(
      {
        note:
          state === 'completed'
            ? 'The run completed and its evidence directory was finalized.'
            : 'The run failed; the material that safely existed is preserved beside this file.',
        run_id: runId,
        state,
        ...(failedStage !== undefined ? { failed_stage: failedStage } : {}),
        recorded_at: new Date().toISOString(),
      },
      null,
      2,
    )}\n`,
  );
}

/**
 * Preserve what safely exists at the moment a live run fails.
 *
 * WHAT IS PRESERVED: bounded run facts (statuses, lifecycle states, the terminal state), the
 * observed x402 field values from the origin's vantage point (wire artifacts, admitted under the
 * same visible-ASCII size bound the capture boundary applies), the transaction reference only
 * when it is a well-formed 32-byte hash, and the RPC observation exactly as made — never one
 * fabricated for a phase that did not run. WHAT IS NEVER PRESERVED HERE: key material, raw
 * exception text, remote response bodies, absolute paths.
 */
function preserveRunMaterial(
  attemptDirectory: string,
  stage: LiveRunStage,
  run: RunResult | undefined,
  observed: LiveObservationResult | undefined,
): void {
  const transaction = run?.origin.lifecycle.transaction;
  const material = {
    note: 'Material preserved from a live run that failed before its evidence was finalized.',
    failed_stage: stage,
    payment_exchange:
      run === undefined
        ? null
        : {
            unpaid_status: run.client.unpaidStatus,
            paid_status: run.client.paidStatus,
            lifecycle_states: [...run.origin.lifecycle.states],
            terminal_state: run.terminalState,
            transaction_reference:
              transaction !== undefined && HASH32.test(transaction) ? transaction : null,
            observed_fields: {
              'payment-required': boundedFieldValue(
                run.challenge.observedHeaders['payment-required'],
              ),
              'payment-signature': boundedFieldValue(
                run.origin.observedHeaders['payment-signature'],
              ),
              'payment-response': boundedFieldValue(
                run.origin.observedHeaders['payment-response'],
              ),
            },
          },
    rpc_observation: observed?.observation ?? null,
    rpc_observation_outcome: observed?.outcome ?? null,
  };
  mkdirSync(attemptDirectory, { recursive: true });
  writeFileSync(
    join(attemptDirectory, RUN_MATERIAL_FILE),
    `${JSON.stringify(material, null, 2)}\n`,
  );
}

/**
 * Run the live phases in order; on any throw, preserve and fail without a second payment.
 *
 * The payment phase is invoked exactly once by construction: it appears once, outside any loop
 * and any catch, so no exception path can reach it a second time. Whatever phase throws, the
 * material held at that point is written to the attempt directory, the attempt file records the
 * failed stage, and a `LiveRunFailure` naming only the stage is thrown.
 */
export async function executeLiveRun(input: {
  readonly phases: LiveRunPhases;
  readonly attemptDirectory: string;
  readonly runId: string;
}): Promise<LiveRunOutcome> {
  let stage: LiveRunStage = 'payment_exchange';
  let run: RunResult | undefined;
  let observed: LiveObservationResult | undefined;
  try {
    run = await input.phases.payment();
    stage = 'rpc_observation';
    observed = await input.phases.observe(run);
    stage = 'evidence_assembly';
    const layout = await input.phases.assemble(run, observed);
    stage = 'evidence_finalization';
    await input.phases.finalize(layout, run, observed);
    writeAttemptState(input.attemptDirectory, input.runId, 'completed');
    return { run, observed };
  } catch {
    preserveRunMaterial(input.attemptDirectory, stage, run, observed);
    writeAttemptState(input.attemptDirectory, input.runId, 'failed', stage);
    throw new LiveRunFailure(stage);
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
          // The per-asset atomic cap makes the client refuse any requirement above the intended
          // spend REGARDLESS of the payer's balance: the balance decides whether a payment can
          // settle, the cap decides what this client is willing to sign for.
          c.setSpendControls({
            allowedAssets: [
              { network: NETWORK, asset: input.asset, maxAmountPerPayment: AMOUNT_BASE_UNITS },
            ],
          });
          // The genuine upstream EVM exact scheme signs with the local payer key; the payment
          // identifier arrives through the upstream client-extension seam, and the selection
          // guard refuses any asset-transfer method outside this reference's scope before
          // anything is signed.
          c.register(NETWORK, new ExactEvmScheme(input.payer));
          c.registerExtension(paymentIdentifierClientExtension(input.paymentId));
          c.onBeforePaymentCreation(eip3009SelectionGuard());
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
  const { rpcUrl, facilitatorUrl } = resolveEndpointsOrExit();
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

  // Live payment boundary: everything from here on can spend real test funds, so the run-attempt
  // record is written FIRST, and every phase past it runs under the preserving orchestrator.
  const paymentId = generatePaymentId();
  const rpcSource = baseSealedRpcSource(rpcUrl);
  const expectedTransfer: ExpectedTransfer = {
    token_contract: usdc.asset,
    transfer_from: payer.address,
    transfer_to: payTo,
    transfer_amount: AMOUNT_BASE_UNITS,
  };
  const attemptDirectory = `${evidenceDirectory}-attempt`;
  const attemptDisplay = `out/${runId}-attempt`;
  beginLiveAttempt({
    attemptDirectory,
    runId,
    metadata: {
      network: NETWORK,
      payer_address: payer.address,
      recipient: payTo,
      asset: usdc.asset,
      amount_base_units: AMOUNT_BASE_UNITS,
      facilitator_origin: publicEndpointReference(facilitatorUrl) ?? 'the configured facilitator',
      rpc_origin: rpcSource.reference,
    },
  });

  const isAccepted = (run: RunResult, observed: LiveObservationResult): boolean =>
    run.terminalState === 'response_write_attempted' && observed.outcome === 'matched';

  const phases: LiveRunPhases = {
    payment: () => runLiveOnce({ payTo, asset: usdc.asset, facilitatorUrl, payer, paymentId }),

    observe: async (run) => {
      console.log(`  unpaid status  : ${run.client.unpaidStatus}`);
      console.log(`  paid status    : ${run.client.paidStatus}`);
      console.log(`  lifecycle      : ${run.origin.lifecycle.states.join(' -> ')}`);
      console.log(`  terminal state : ${run.terminalState}`);

      // The separately attributed RPC observation, only for a settlement the facilitator
      // reported, and only through a transaction reference admitted as a 32-byte hash first.
      const settled = run.terminalState === 'response_write_attempted';
      const transactionHash = run.origin.lifecycle.transaction;
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
      return observed;
    },

    // Evidence is assembled whatever the outcome: a failed live run is evidence too. The record
    // binds the components the origin observed for the request that actually happened.
    assemble: async (run, observed) => {
      const components = run.origin.components;
      if (components === undefined) {
        throw new Error('the origin recorded no request components for the paid request');
      }
      return buildEvidence(run, {
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
    },

    finalize: async (layout, run, observed) => {
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
              accepted: isAccepted(run, observed),
            }),
          );
          if (!verification.ok) {
            throw new Error('the freshly issued evidence did not verify; the staged directory is preserved');
          }
        },
      });
    },
  };

  let liveOutcome: LiveRunOutcome;
  try {
    liveOutcome = await executeLiveRun({ phases, attemptDirectory, runId });
  } catch (e) {
    if (e instanceof LiveRunFailure) {
      console.error(`\n${e.message}\n  attempt record : ${attemptDisplay}\n`);
      process.exit(1);
    }
    throw e;
  }
  const { run, observed } = liveOutcome;
  const settled = run.terminalState === 'response_write_attempted';
  const accepted = isAccepted(run, observed);
  console.log(`\n  evidence written and verified offline: ${runEvidenceDisplay(runId)}`);
  console.log(
    `  verify again: pnpm verify -- --evidence ${runEvidenceDisplay(runId)} --public-key ${runPublicKeyDisplay(runId)}`,
  );

  // The tamper demonstration: one bound byte changes in a COPY, and verification must fail. The
  // copy is a scratch artifact and is removed after the property is demonstrated.
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
