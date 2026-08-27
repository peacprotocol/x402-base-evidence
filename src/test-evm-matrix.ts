/**
 * Security, replay, binding and tamper cases for the Base exact-scheme reference flow.
 *
 * Five families, and they answer different questions.
 *
 * SECURITY asks whether this integration lets a payment through that the advertised terms do not
 * describe, and whether the EIP-3009 semantics this profile depends on are actually enforced by
 * the installed upstream code rather than assumed. The altered-terms cases run black box: a real
 * origin is started, a real client builds a real payment, one field of that payment is altered,
 * and the payment is presented over HTTP. The payer, signature and time-window cases go through
 * the exported upstream facilitator class, because those semantics are upstream's to enforce and
 * this repository must not rebuild them as a local validity oracle; the chain answers handed to
 * that class are deterministic synthetic values, named as such below, and the validation logic
 * that runs over them is entirely the installed upstream implementation.
 *
 * REPLAY asks what repetition does. The offline stand-in refuses a second settlement of a consumed
 * authorization so the branch is reachable without a chain; the case records the observed outcome
 * and deliberately does not name the mechanism a real facilitator or the network enforces.
 *
 * EVIDENCE asks what a receipt is not: a successful execution status without the expected transfer
 * event is recorded as a mismatch, never as matching payment evidence.
 *
 * BINDING is the point of the whole example. A payment artifact that is entirely valid on its own
 * terms is presented for a different operation, or beside a different result, and the binding is
 * what refuses it. Every case here keeps the native artifact valid, so the failure can only be
 * attributed to the binding.
 *
 * TAMPER asks what an edited evidence directory looks like from outside. Each case alters exactly
 * one thing and asserts the specific check that catches it, because "verification failed" is not a
 * useful answer: which stage failed is what a reader acts on.
 */
import type { AddressInfo } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { registerExactEvmScheme } from '@x402/evm/exact/server';
import { ExactEvmScheme as UpstreamExactEvmFacilitator } from '@x402/evm/exact/facilitator';
import { authorizationTypes, type FacilitatorEvmSigner } from '@x402/evm';
import { privateKeyToAccount } from 'viem/accounts';
import { x402Client, x402HTTPClient } from '@x402/core/client';
import {
  PAYMENT_IDENTIFIER,
  declarePaymentIdentifierExtension,
} from '@x402/extensions/payment-identifier';
import type { PaymentPayload, PaymentRequired } from '@x402/core/types';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { buildRequestBinding, type PaymentEvidenceRequestBindingV1 } from './binding.ts';
import { componentsFromAbsoluteUri } from './components.ts';
import { captureObservedX402Artifact, requireValidX402Artifact } from './x402-header.ts';
import * as F from '../fixtures/deterministic.ts';
import {
  createFixtureFacilitator,
  DUPLICATE_SETTLEMENT_REASON,
  type FixtureFacilitatorBehavior,
  type FixtureFacilitatorCalls,
} from './flow/fixture-facilitator.ts';
import { FixtureExactWallet } from './flow/fixture-wallet.ts';
import { createPaidResource, type OriginResult, type RequestObservation } from './flow/server.ts';
import {
  buildEvidence,
  FIXTURE_EVIDENCE_OPTIONS,
  RESOURCE_PATH,
  RESOURCE_QUERY,
  runOnce,
} from './flow/fixture-e2e.ts';
import { writeEvidence, type EvidenceLayout } from './flow/issue-record.ts';
import { resolveIssuerKey } from './flow/issuer-key.ts';
import { compareExpectationToObservation } from './flow/observe-settlement.ts';
import {
  observeSealedTransaction,
  TRANSFER_EVENT_TOPIC,
  transfersOnContract,
  CHAIN_IDENTITY_UNESTABLISHED,
  type ObservedLog,
  type SealedTransactionSource,
} from './flow/observe-transaction.ts';
import { checkLocalConfiguration, distinctRolesCheck, expectedUsdcAsset } from './flow/preflight.ts';
import {
  verifyEvidence,
  type EvidenceVerificationReport,
} from './flow/verify-evidence.ts';
import type { EvidenceArtifact } from './flow/presence.ts';

beginAcceptanceSuite('evm-matrix');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

const decoder = new TextDecoder();
const encoder = new TextEncoder();

/** Same serialization the evidence writer uses, so a substituted document is shaped identically. */
const documentBytes = (value: unknown): Uint8Array =>
  encoder.encode(`${JSON.stringify(value, null, 2)}\n`);

// ---------------------------------------------------------------------------------------------
// Harness: a real origin, a real client, and one altered field.
// ---------------------------------------------------------------------------------------------

interface Origin {
  readonly baseUrl: string;
  readonly observations: readonly RequestObservation[];
  readonly calls: FixtureFacilitatorCalls;
  close(): Promise<void>;
}

const paidResult = (): OriginResult => ({
  status: 200,
  contentType: 'application/json',
  body: F.ORIGIN_RESULT_BODY,
});

/** Start a paid resource on the loopback interface with the in-process facilitator behind it. */
async function startOrigin(behavior: FixtureFacilitatorBehavior = {}): Promise<Origin> {
  const facilitator = createFixtureFacilitator(F.NETWORK, behavior);
  const resource = await createPaidResource({
    facilitatorClient: facilitator.client,
    registerSchemes: (server) => {
      registerExactEvmScheme(server, { networks: [F.NETWORK] });
    },
    network: F.NETWORK,
    payTo: F.PAY_TO,
    price: {
      asset: F.ASSET_CONTRACT,
      amount: F.AMOUNT_BASE_UNITS,
      extra: { name: F.ASSET_NAME, version: F.ASSET_EIP712_VERSION },
    },
    method: 'GET',
    path: RESOURCE_PATH,
    resourceUrl: F.RESOURCE_URL,
    maxTimeoutSeconds: F.MAX_TIMEOUT_SECONDS,
    declaredExtensions: { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
    handler: () => paidResult(),
  });

  const server = resource.app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => resolve());
    server.once('error', reject);
  });
  const { port } = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    observations: resource.observations,
    calls: facilitator.calls,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** The upstream client, paying through the offline wallet stand-in. */
function upstreamClient(paymentId: string = F.PAYMENT_ID): x402HTTPClient {
  const client = new x402Client();
  // The upstream spend-control allowlist recognizes each scheme's own network-default assets by
  // default. This suite always pays the fixed fixture asset, so it is named explicitly rather
  // than left to fall through the default-asset recognition path.
  client.setSpendControls({ allowedAssets: [{ network: F.NETWORK, asset: F.ASSET_CONTRACT }] });
  client.register(F.NETWORK, new FixtureExactWallet(paymentId));
  return new x402HTTPClient(client);
}

/** Fetch the challenge and decode it with the upstream client, exactly as a payer would. */
async function challenge(
  origin: Origin,
  http: x402HTTPClient,
): Promise<{ status: number; paymentRequired: PaymentRequired }> {
  const response = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`);
  const body: unknown = await response.json().catch(() => undefined);
  return {
    status: response.status,
    paymentRequired: http.getPaymentRequiredResponse((n) => response.headers.get(n), body),
  };
}

/** Present a payment over HTTP, encoded by the upstream client. */
async function present(
  origin: Origin,
  http: x402HTTPClient,
  payload: PaymentPayload,
): Promise<{ status: number; observation: RequestObservation }> {
  const response = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
    method: 'GET',
    headers: http.encodePaymentSignatureHeader(payload),
  });
  await response.arrayBuffer();
  const observation = origin.observations.at(-1);
  if (observation === undefined) throw new Error('the origin recorded no observation');
  return { status: response.status, observation };
}

/**
 * Present a payment whose advertised terms were altered after the client built it.
 *
 * Returns what the origin did, and what the facilitator was asked, so a refusal can be located:
 * a refusal with no verify call happened in the resource server's own requirements matching,
 * before anyone was asked whether the payment was good.
 */
async function presentAlteredTerms(
  alter: (accepted: PaymentPayload['accepted']) => PaymentPayload['accepted'],
): Promise<{ status: number; observation: RequestObservation; calls: FixtureFacilitatorCalls }> {
  const origin = await startOrigin();
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const honest = await http.createPaymentPayload(paymentRequired);
    const altered: PaymentPayload = { ...honest, accepted: alter(honest.accepted) };
    const { status, observation } = await present(origin, http, altered);
    return { status, observation, calls: { ...origin.calls } };
  } finally {
    await origin.close();
  }
}

/** A payment the origin refused before executing anything, and before asking the facilitator. */
function refusedBeforeExecution(
  label: string,
  outcome: { status: number; observation: RequestObservation; calls: FixtureFacilitatorCalls },
): void {
  const { status, observation, calls } = outcome;
  const states = observation.lifecycle.states;
  check(
    `${label} is refused with a payment-required response`,
    status === 402,
    `status ${status}`,
  );
  check(
    `${label} never reaches verification, settlement or the handler`,
    !states.includes('payment_verified') &&
      !states.includes('payment_settled') &&
      observation.originResult === undefined,
    states.join(' -> '),
  );
  check(
    `${label} is refused by the resource server before the facilitator is asked`,
    calls.verify === 0 && calls.settle === 0,
    `verify ${calls.verify}, settle ${calls.settle}`,
  );
  check(
    `${label} is recorded as refused before verification`,
    observation.lifecycle.terminalState === 'payment_rejected_pre_verification',
    observation.lifecycle.terminalState,
  );
}

// ---------------------------------------------------------------------------------------------
// Security: altered terms must not buy a resource.
// ---------------------------------------------------------------------------------------------

console.log('\nBase exact-scheme security, replay, evidence, binding and tamper matrix\n');
console.log('  -- security: altered payment terms --');

// A syntactically valid EVM address that is not any advertised party: sha-derived like every
// other synthetic constant, holding no known key.
const OTHER_RECIPIENT = '0x00000000000000000000000000000000000a7a01';
const OTHER_ASSET = '0x00000000000000000000000000000000000a5e70';

recordExecution('EVM-SEC-002');
refusedBeforeExecution(
  'a payment naming a different recipient',
  await presentAlteredTerms((accepted) => ({ ...accepted, payTo: OTHER_RECIPIENT })),
);

recordExecution('EVM-SEC-003');
refusedBeforeExecution(
  'a payment naming a smaller amount',
  await presentAlteredTerms((accepted) => ({ ...accepted, amount: '1' })),
);

recordExecution('EVM-SEC-004');
refusedBeforeExecution(
  'a payment naming a different asset',
  await presentAlteredTerms((accepted) => ({ ...accepted, asset: OTHER_ASSET })),
);

recordExecution('EVM-SEC-005');
refusedBeforeExecution(
  'a payment naming a different network',
  await presentAlteredTerms((accepted) => ({ ...accepted, network: 'eip155:8453' })),
);

// ---------------------------------------------------------------------------------------------
// Security: EIP-3009 payer, signature and time-window semantics, delegated to upstream.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- security: upstream EIP-3009 semantics --');

/**
 * The installed upstream facilitator, over deterministic synthetic chain answers.
 *
 * WHAT IS UPSTREAM AND WHAT IS NOT. Signature recovery, payer correspondence, recipient, amount
 * and time-window enforcement below are the installed `@x402/evm` facilitator's own code, reached
 * through its exported class: nothing in this repository reimplements them, and a case failing
 * here is a fact about the pinned upstream behaviour. The `FacilitatorEvmSigner` handed to that
 * class is this suite's deterministic stand-in for chain reads: the payer address answers with no
 * deployed code, so signatures take the ECDSA recovery path; the asset contract answers with
 * nonempty bytecode, so the deployed-contract check passes; and the transfer simulation resolves,
 * so verification reaches its local checks and its verdict. Those answers are synthetic and are
 * not evidence about any network.
 */
const syntheticChainReads: FacilitatorEvmSigner = {
  getAddresses: () => [],
  async getCode({ address }) {
    return address.toLowerCase() === F.ASSET_CONTRACT.toLowerCase() ? '0x60' : '0x';
  },
  async readContract() {
    return undefined;
  },
  async verifyTypedData() {
    throw new Error('not part of the verification path this suite exercises');
  },
  async writeContract() {
    throw new Error('settlement is never reached by this suite');
  },
  async sendTransaction() {
    throw new Error('settlement is never reached by this suite');
  },
  async waitForTransactionReceipt() {
    throw new Error('settlement is never reached by this suite');
  },
};

const upstreamFacilitator = new UpstreamExactEvmFacilitator(syntheticChainReads);

/**
 * TEST-ONLY signing keys. Deterministic, clearly labelled, holding nothing on any network, and
 * used solely so the upstream recovery path has real signatures to recover.
 */
const PAYER_TEST_KEY = `0x${'11'.repeat(32)}` as const;
const OTHER_TEST_KEY = `0x${'22'.repeat(32)}` as const;
const payerAccount = privateKeyToAccount(PAYER_TEST_KEY);
const otherAccount = privateKeyToAccount(OTHER_TEST_KEY);

interface Eip3009Authorization {
  readonly from: string;
  readonly to: string;
  readonly value: string;
  readonly validAfter: string;
  readonly validBefore: string;
  readonly nonce: string;
}

const eip712Domain = {
  name: F.ASSET_NAME,
  version: F.ASSET_EIP712_VERSION,
  chainId: 84532,
  verifyingContract: F.ASSET_CONTRACT as `0x${string}`,
} as const;

async function signAuthorization(
  authorization: Eip3009Authorization,
  signer: typeof payerAccount,
): Promise<`0x${string}`> {
  return signer.signTypedData({
    domain: eip712Domain,
    types: authorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: authorization.from as `0x${string}`,
      to: authorization.to as `0x${string}`,
      value: BigInt(authorization.value),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
      nonce: authorization.nonce as `0x${string}`,
    },
  });
}

const freshNonce = (): string => `0x${randomBytes(32).toString('hex')}`;

function probeAuthorization(overrides: Partial<Eip3009Authorization> = {}): Eip3009Authorization {
  const now = Math.floor(Date.now() / 1000);
  return {
    from: payerAccount.address,
    to: F.PAY_TO,
    value: F.AMOUNT_BASE_UNITS,
    validAfter: '0',
    validBefore: String(now + 600),
    nonce: freshNonce(),
    ...overrides,
  };
}

async function upstreamVerify(
  authorization: Eip3009Authorization,
  signer: typeof payerAccount,
): Promise<{ isValid: boolean; invalidReason?: string; payer?: string }> {
  const signature = await signAuthorization(authorization, signer);
  const payload: PaymentPayload = {
    x402Version: 2,
    resource: F.RESOURCE_INFO,
    accepted: F.PAYMENT_REQUIREMENTS,
    payload: { authorization, signature },
  };
  return (await upstreamFacilitator.verify(payload, F.PAYMENT_REQUIREMENTS)) as {
    isValid: boolean;
    invalidReason?: string;
    payer?: string;
  };
}

recordExecution('EVM-SEC-001');
{
  const honest = await upstreamVerify(probeAuthorization(), payerAccount);
  check(
    'an authorization signed by the authorized payer verifies, and the payer is the from address',
    honest.isValid && honest.payer?.toLowerCase() === payerAccount.address.toLowerCase(),
    `isValid ${honest.isValid}, payer ${String(honest.payer)}`,
  );

  const forged = await upstreamVerify(probeAuthorization(), otherAccount);
  check(
    'the same authorization signed by a different key is refused: the recovered signer must correspond to the authorized payer',
    !forged.isValid && forged.invalidReason === 'invalid_exact_evm_signature',
    `isValid ${forged.isValid}, reason ${String(forged.invalidReason)}`,
  );
}

recordExecution('EVM-SEC-006');
{
  const now = Math.floor(Date.now() / 1000);
  const expired = await upstreamVerify(
    probeAuthorization({ validBefore: String(now - 100) }),
    payerAccount,
  );
  check(
    'an authorization past its validBefore window is refused',
    !expired.isValid &&
      expired.invalidReason === 'invalid_exact_evm_payload_authorization_valid_before',
    `isValid ${expired.isValid}, reason ${String(expired.invalidReason)}`,
  );

  const notYet = await upstreamVerify(
    probeAuthorization({ validAfter: String(now + 600), validBefore: String(now + 1200) }),
    payerAccount,
  );
  check(
    'an authorization before its validAfter window is refused',
    !notYet.isValid &&
      notYet.invalidReason === 'invalid_exact_evm_payload_authorization_valid_after',
    `isValid ${notYet.isValid}, reason ${String(notYet.invalidReason)}`,
  );
}

// ---------------------------------------------------------------------------------------------
// Shared evidence: one honest run, reused by the binding and tamper cases.
// ---------------------------------------------------------------------------------------------

const honestRun = await runOnce();
const honestLayout = await buildEvidence(honestRun);
const issuerKey = await resolveIssuerKey('fixture');
const temporaryDirectories: string[] = [];

/** Write the honest evidence to a fresh directory, with named files replaced or removed. */
function evidenceWith(
  overrides: ReadonlyMap<EvidenceArtifact, Uint8Array | null>,
): string {
  const directory = mkdtempSync(join(tmpdir(), 'peac-evidence-'));
  temporaryDirectories.push(directory);
  const files = new Map<EvidenceArtifact, Uint8Array>();
  for (const [artifact, bytes] of honestLayout.files) {
    const override = overrides.get(artifact);
    if (override === null) continue;
    files.set(artifact, override ?? bytes);
  }
  const layout: EvidenceLayout = { jws: honestLayout.jws, files };
  writeEvidence(directory, layout);
  return directory;
}

const verifyWith = async (
  overrides: ReadonlyMap<EvidenceArtifact, Uint8Array | null>,
): Promise<EvidenceVerificationReport> =>
  verifyEvidence(evidenceWith(overrides), issuerKey.publicKey);

const failedChecks = (report: EvidenceVerificationReport): string[] =>
  report.checks.filter((c) => !c.ok).map((c) => c.name);

const failedExactly = (report: EvidenceVerificationReport, names: readonly string[]): boolean => {
  const failed = failedChecks(report);
  return (
    !report.ok &&
    failed.length === names.length &&
    names.every((name) => failed.includes(name))
  );
};

const passed = (report: EvidenceVerificationReport, name: string): boolean =>
  report.checks.some((c) => c.name === name && c.ok);

// Completes EVM-SEC-001: the broadcaster is separately observed and never treated as payment
// authority. The observation records who broadcast as a fact from the RPC account; the comparison
// verdicts are computed from the transfer event, so a different broadcaster changes no verdict.
{
  const broadcaster = '0x00000000000000000000000000000000000fac11';
  const matchingLog: ObservedLog = {
    address: F.ASSET_CONTRACT,
    topics: [
      TRANSFER_EVENT_TOPIC,
      `0x${F.PAYER.slice(2).padStart(64, '0')}`,
      `0x${F.PAY_TO.slice(2).padStart(64, '0')}`,
    ],
    data: `0x${BigInt(F.AMOUNT_BASE_UNITS).toString(16).padStart(64, '0')}`,
  };
  const source: SealedTransactionSource = {
    reference: 'synthetic sealed source',
    chainId: async () => 84532n,
    sealedHeadBlockNumber: async () => 1000n,
    transactionReceipt: async () => ({
      status: 'success',
      blockNumber: 900n,
      blockHash: '0x'.padEnd(66, 'a'),
      logs: [matchingLog],
    }),
    transactionByHash: async () => ({
      from: broadcaster,
      blockNumber: 900n,
      blockHash: '0x'.padEnd(66, 'a'),
    }),
    sealedBlockByNumber: async (n) => ({
      number: n,
      hash: '0x'.padEnd(66, 'a'),
      transactionHashes: [F.SETTLEMENT_TX_HASH],
    }),
  };
  const observation = await observeSealedTransaction({
    source,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer: {
      token_contract: F.ASSET_CONTRACT,
      transfer_from: F.PAYER,
      transfer_to: F.PAY_TO,
      transfer_amount: F.AMOUNT_BASE_UNITS,
    },
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'the broadcaster is recorded as an observed fact, distinct from the authorized payer',
    observation.transaction_sender === broadcaster &&
      observation.transaction_sender.toLowerCase() !== F.PAYER.toLowerCase(),
    `transaction_sender ${String(observation.transaction_sender)}`,
  );
  const expectationSide = {
    payment_expectation: {
      source: 'native_x402_artifact' as const,
      network: F.NETWORK,
      asset: F.ASSET_CONTRACT,
      amount_base_units: F.AMOUNT_BASE_UNITS,
      asset_decimals: F.TOKEN_DECIMALS,
      recipient: F.PAY_TO,
      payer: F.PAYER,
    },
    chain_observation: {
      source: { kind: 'facilitator' as const, reference: 'synthetic' },
      settlement_outcome: 'succeeded' as const,
      transaction_hash: F.SETTLEMENT_TX_HASH,
      network_reported: F.NETWORK,
      observed_at_unix_seconds: F.FIXED_NOW_UNIX_SECONDS,
    },
  };
  const withBroadcaster = compareExpectationToObservation({
    ...expectationSide,
    rpc_observation: observation,
  });
  const withOtherSender = compareExpectationToObservation({
    ...expectationSide,
    rpc_observation: { ...observation, transaction_sender: F.PAYER },
  });
  check(
    'comparison verdicts are computed from the transfer event, never from who broadcast',
    withBroadcaster.transfer_event === 'match' &&
      JSON.stringify(withBroadcaster) === JSON.stringify(withOtherSender),
    JSON.stringify(withBroadcaster),
  );
  check(
    'sealed inclusion was established from sealed block agreement, and execution status is separate',
    observation.observation_level === 'l2_block_inclusion' && observation.receipt_status === 'success',
    `level ${String(observation.observation_level)}, status ${String(observation.receipt_status)}`,
  );
}

// ---------------------------------------------------------------------------------------------
// Replay.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- replay --');

/**
 * EVM-REPLAY-001. The same authorization, presented twice.
 *
 * On the network a consumed EIP-3009 authorization cannot transfer twice; offline, the stand-in
 * facilitator refuses the second settlement so the branch is reachable at all. What is asserted is
 * the observed outcome: no second successful transfer, the repeat recorded as a settlement
 * failure. Which internal mechanism a real facilitator or the chain uses to enforce this is
 * deliberately not named, because this suite has no way to observe it.
 */
recordExecution('EVM-REPLAY-001');
{
  const origin = await startOrigin();
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);
    const first = await present(origin, http, payment);
    const second = await present(origin, http, payment);

    check(
      'the first settlement of an authorization succeeds',
      first.status === 200 &&
        first.observation.lifecycle.terminalState === 'response_write_attempted',
      `status ${first.status}, ${first.observation.lifecycle.terminalState}`,
    );
    check(
      'a repeated consumed authorization does not produce a second successful transfer',
      second.observation.lifecycle.terminalState === 'settlement_failed' &&
        second.observation.lifecycle.failureReason === DUPLICATE_SETTLEMENT_REASON,
      `${second.observation.lifecycle.terminalState}, ` +
        `${String(second.observation.lifecycle.failureReason)}`,
    );
    check(
      'the repeated attempt produced the resource but never wrote it to the client',
      second.observation.originResult !== undefined && second.status === 402,
      `status ${second.status}`,
    );
    check(
      'both attempts reached the facilitator, so the refusal was a settlement decision',
      origin.calls.settle === 2,
      `settle calls ${origin.calls.settle}`,
    );
  } finally {
    await origin.close();
  }
}

// Completes EVM-REPLAY-001: consumed-authorization state is scoped to the pair
// (authorizer, nonce), the way EIP-3009 keys `authorizationState(address authorizer, bytes32
// nonce)`. The same authorizer repeating a nonce is a duplicate — under any hex casing — while a
// different authorizer using the same nonce value is a different authorization and must not
// collide with it.
{
  const withAuthorizer = (from: string): PaymentPayload =>
    structuredClone({
      ...F.PAYMENT_PAYLOAD,
      payload: {
        ...F.PAYMENT_PAYLOAD.payload,
        authorization: { ...F.EXACT_EVM_AUTHORIZATION, from },
      },
    });
  const otherAuthorizer = '0x00000000000000000000000000000000000000aa';
  const scoped = createFixtureFacilitator(F.NETWORK);
  const first = await scoped.client.settle(withAuthorizer(F.PAYER), F.PAYMENT_REQUIREMENTS);
  const repeated = await scoped.client.settle(
    withAuthorizer(`0x${F.PAYER.slice(2).toUpperCase()}`),
    F.PAYMENT_REQUIREMENTS,
  );
  const differentAuthorizer = await scoped.client.settle(
    withAuthorizer(otherAuthorizer),
    F.PAYMENT_REQUIREMENTS,
  );
  check(
    'the first settlement of an authorizer-and-nonce pair succeeds',
    first.success === true,
    JSON.stringify(first),
  );
  check(
    'the same authorizer repeating the same nonce is refused as a duplicate, across hex casing',
    repeated.success === false && repeated.errorReason === DUPLICATE_SETTLEMENT_REASON,
    JSON.stringify(repeated),
  );
  check(
    'a different authorizer using the same nonce value does not collide with the consumed pair',
    differentAuthorizer.success === true,
    JSON.stringify(differentAuthorizer),
  );
}

/**
 * EIP3009-REPLAY-001 through EIP3009-REPLAY-005. Only a settlement that actually succeeds may
 * consume the authorization it settled; a refusal, a thrown error, or a term mismatch must leave
 * it exactly as spendable as it was before the attempt, so a caller can retry it.
 */
console.log('\n  -- replay: only success consumes --');

recordExecution('EIP3009-REPLAY-001');
{
  const { client } = createFixtureFacilitator(F.NETWORK, { rejectSettlement: 'insufficient_funds' });
  const first = await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  const retry = await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  check(
    'an explicitly refused settlement does not consume the authorization',
    first.success === false &&
      first.errorReason === 'insufficient_funds' &&
      retry.success === false &&
      retry.errorReason === 'insufficient_funds',
    `first ${JSON.stringify(first)}, retry ${JSON.stringify(retry)}`,
  );
}

recordExecution('EIP3009-REPLAY-002');
{
  // Retried on the SAME instance, not a fresh one: a fresh instance's own state proves nothing
  // about whether `release()` actually cleared the first attempt's 'pending' entry. The injected
  // behavior throws on every call to this instance, so if `release()` worked, a second call
  // re-evaluates the identical (authorizer, nonce) from scratch and throws again. If it did not,
  // the duplicate check at the top of `settle()` finds the identity still 'pending' and returns
  // `duplicate_settlement` WITHOUT ever reaching the throwing behavior a second time -- that
  // silent switch from "threw" to "returned a response" is exactly the failure this proves absent.
  const { client } = createFixtureFacilitator(F.NETWORK, { throwOnSettle: 'endpoint unavailable' });
  let firstThrew = false;
  try {
    await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  } catch {
    firstThrew = true;
  }
  let secondThrew = false;
  let secondResult: unknown;
  try {
    secondResult = await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  } catch {
    secondThrew = true;
  }
  check(
    'a settlement that throws does not consume the authorization: retrying the SAME instance throws again, never duplicate_settlement',
    firstThrew && secondThrew && secondResult === undefined,
    `first threw ${firstThrew}, second threw ${secondThrew}, second result ${JSON.stringify(secondResult)}`,
  );
}

recordExecution('EIP3009-REPLAY-003');
{
  const { client } = createFixtureFacilitator(F.NETWORK, {});
  const mismatchedRequirements = { ...F.PAYMENT_REQUIREMENTS, amount: '999999' };
  const failedAttempt = await client.settle(F.PAYMENT_PAYLOAD, mismatchedRequirements);
  const retryWithCorrectTerms = await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  check(
    'a term-validation failure does not consume the authorization; a retry with correct terms succeeds',
    failedAttempt.success === false &&
      failedAttempt.errorReason === 'amount_mismatch' &&
      retryWithCorrectTerms.success === true,
    `failed ${JSON.stringify(failedAttempt)}, retry ${JSON.stringify(retryWithCorrectTerms)}`,
  );
}

recordExecution('EIP3009-REPLAY-004');
{
  const { client } = createFixtureFacilitator(F.NETWORK, {});
  const first = await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  const retry = await client.settle(F.PAYMENT_PAYLOAD, F.PAYMENT_REQUIREMENTS);
  check(
    'a settlement that succeeds consumes the authorization; a retry is refused as a duplicate',
    first.success === true && retry.success === false && retry.errorReason === DUPLICATE_SETTLEMENT_REASON,
    `first ${JSON.stringify(first)}, retry ${JSON.stringify(retry)}`,
  );
}

recordExecution('EIP3009-REPLAY-005');
{
  const withAuthorizer = (from: string): PaymentPayload =>
    structuredClone({
      ...F.PAYMENT_PAYLOAD,
      payload: { ...F.PAYMENT_PAYLOAD.payload, authorization: { ...F.EXACT_EVM_AUTHORIZATION, from } },
    });
  const otherAuthorizer = '0x00000000000000000000000000000000000000bb';

  // The first authorizer's attempt FAILS; a different authorizer using the same nonce value must
  // still be evaluated on its own terms.
  const failing = createFixtureFacilitator(F.NETWORK, { rejectSettlement: 'insufficient_funds' });
  const firstFailed = await failing.client.settle(withAuthorizer(F.PAYER), F.PAYMENT_REQUIREMENTS);
  const otherAfterFailure = await failing.client.settle(withAuthorizer(otherAuthorizer), F.PAYMENT_REQUIREMENTS);
  check(
    'a different authorizer using the same nonce value is unaffected by the first one failing',
    // Both attempts are refused under this facilitator's configured behavior either way; what
    // this proves is that the different authorizer is evaluated on its own terms and never sees
    // "duplicate_settlement" from the first authorizer's unrelated failure.
    firstFailed.success === false &&
      firstFailed.errorReason === 'insufficient_funds' &&
      otherAfterFailure.success === false &&
      otherAfterFailure.errorReason === 'insufficient_funds',
    `first ${JSON.stringify(firstFailed)}, other ${JSON.stringify(otherAfterFailure)}`,
  );

  // The first authorizer's attempt SUCCEEDS (consuming its own identity); a different authorizer
  // using the same nonce value must still be independent of that consumption.
  const succeeding = createFixtureFacilitator(F.NETWORK, {});
  const firstSucceeded = await succeeding.client.settle(withAuthorizer(F.PAYER), F.PAYMENT_REQUIREMENTS);
  const otherAfterSuccess = await succeeding.client.settle(withAuthorizer(otherAuthorizer), F.PAYMENT_REQUIREMENTS);
  check(
    'a different authorizer using the same nonce value is unaffected by the first one consuming it',
    firstSucceeded.success === true && otherAfterSuccess.success === true,
    `first ${JSON.stringify(firstSucceeded)}, other ${JSON.stringify(otherAfterSuccess)}`,
  );
}

// ---------------------------------------------------------------------------------------------
// Evidence: a receipt is not a payment.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- evidence: receipt versus transfer event --');

/**
 * EVM-EVIDENCE-001. A successful execution status without the expected transfer event is a
 * recorded mismatch, never matching payment evidence. The sealed source below is synthetic and
 * says so; what is being exercised is this repository's own structural verdict, which is exactly
 * the check that keeps "the transaction succeeded" from being read as "the expected payment
 * occurred".
 */
recordExecution('EVM-EVIDENCE-001');
{
  const expectedTransfer = {
    token_contract: F.ASSET_CONTRACT,
    transfer_from: F.PAYER,
    transfer_to: F.PAY_TO,
    transfer_amount: F.AMOUNT_BASE_UNITS,
  };
  const sourceWith = (logs: readonly ObservedLog[]): SealedTransactionSource => ({
    reference: 'synthetic sealed source',
    chainId: async () => 84532n,
    sealedHeadBlockNumber: async () => 1000n,
    transactionReceipt: async () => ({
      status: 'success',
      blockNumber: 900n,
      blockHash: '0x'.padEnd(66, 'b'),
      logs,
    }),
    transactionByHash: async () => ({
      from: F.PAYER,
      blockNumber: 900n,
      blockHash: '0x'.padEnd(66, 'b'),
    }),
    sealedBlockByNumber: async (n) => ({
      number: n,
      hash: '0x'.padEnd(66, 'b'),
      transactionHashes: [F.SETTLEMENT_TX_HASH],
    }),
  });
  const expectationSide = {
    payment_expectation: {
      source: 'native_x402_artifact' as const,
      network: F.NETWORK,
      asset: F.ASSET_CONTRACT,
      amount_base_units: F.AMOUNT_BASE_UNITS,
      asset_decimals: F.TOKEN_DECIMALS,
      recipient: F.PAY_TO,
      payer: F.PAYER,
    },
    chain_observation: {
      source: { kind: 'facilitator' as const, reference: 'synthetic' },
      settlement_outcome: 'succeeded' as const,
      transaction_hash: F.SETTLEMENT_TX_HASH,
      network_reported: F.NETWORK,
      observed_at_unix_seconds: F.FIXED_NOW_UNIX_SECONDS,
    },
  };

  const bare = await observeSealedTransaction({
    source: sourceWith([]),
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  const bareComparison = compareExpectationToObservation({
    ...expectationSide,
    rpc_observation: bare,
  });
  check(
    'a successful receipt without the expected transfer event is a transfer-event mismatch',
    bare.receipt_status === 'success' && bareComparison.transfer_event === 'mismatch',
    `status ${String(bare.receipt_status)}, verdict ${bareComparison.transfer_event}`,
  );

  const wrongAmountLog: ObservedLog = {
    address: F.ASSET_CONTRACT,
    topics: [
      TRANSFER_EVENT_TOPIC,
      `0x${F.PAYER.slice(2).padStart(64, '0')}`,
      `0x${F.PAY_TO.slice(2).padStart(64, '0')}`,
    ],
    data: `0x${(1n).toString(16).padStart(64, '0')}`,
  };
  const wrongAmount = await observeSealedTransaction({
    source: sourceWith([wrongAmountLog]),
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  const wrongAmountComparison = compareExpectationToObservation({
    ...expectationSide,
    rpc_observation: wrongAmount,
  });
  check(
    'a transfer event with a different amount is recorded and is an amount and transfer-event mismatch',
    wrongAmount.token_transfer?.transfer_amount === '1' &&
      wrongAmountComparison.amount === 'mismatch' &&
      wrongAmountComparison.transfer_event === 'mismatch',
    JSON.stringify(wrongAmountComparison),
  );

  // The sealed-observation sequence itself: a receipt whose reported placement disagrees with the
  // sealed block data, and a receipt whose sealed block cannot be queried, both stay without an
  // inclusion level. Receipt existence never carries the claim.
  const disagreeing: SealedTransactionSource = {
    ...sourceWith([]),
    sealedBlockByNumber: async (n) => ({
      number: n,
      hash: '0x'.padEnd(66, 'c'),
      transactionHashes: [F.SETTLEMENT_TX_HASH],
    }),
  };
  const noInclusion = await observeSealedTransaction({
    source: disagreeing,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'sealed inclusion is never recorded when the sealed block data disagrees with the receipt',
    noInclusion.observation_state === 'found' &&
      noInclusion.observation_level === undefined &&
      noInclusion.receipt_status === 'success',
    `level ${String(noInclusion.observation_level)}`,
  );
  const unqueryable: SealedTransactionSource = {
    ...sourceWith([]),
    sealedBlockByNumber: async () => {
      throw new Error('synthetic sealed-block outage');
    },
  };
  const stillNoInclusion = await observeSealedTransaction({
    source: unqueryable,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'sealed inclusion is never inferred from receipt existence when block data cannot be queried',
    stillNoInclusion.observation_state === 'found' &&
      stillNoInclusion.observation_level === undefined,
    `level ${String(stillNoInclusion.observation_level)}`,
  );

  // The strengthened inclusion sequence: every placement fact must agree, including the sealed
  // block's own transaction list containing the transaction. Each vector below breaks exactly one
  // agreement and asserts that the observation keeps its observed facts while carrying no
  // inclusion level.
  check(
    'when every placement fact agrees, and only then, sealed inclusion is recorded',
    bare.observation_level === 'l2_block_inclusion' && bare.receipt_status === 'success',
    `level ${String(bare.observation_level)}`,
  );

  const txAbsentFromSealedList: SealedTransactionSource = {
    ...sourceWith([]),
    sealedBlockByNumber: async (n) => ({
      number: n,
      hash: '0x'.padEnd(66, 'b'),
      transactionHashes: ['0x'.padEnd(66, '9')],
    }),
  };
  const absentFromList = await observeSealedTransaction({
    source: txAbsentFromSealedList,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'a sealed block that agrees on number and hash but does not list the transaction records no inclusion',
    absentFromList.observation_state === 'found' &&
      absentFromList.observation_level === undefined &&
      absentFromList.receipt_status === 'success',
    `level ${String(absentFromList.observation_level)}`,
  );

  const txHashDisagrees: SealedTransactionSource = {
    ...sourceWith([]),
    transactionByHash: async () => ({
      from: F.PAYER,
      blockNumber: 900n,
      blockHash: '0x'.padEnd(66, 'd'),
    }),
  };
  const hashDisagreement = await observeSealedTransaction({
    source: txHashDisagrees,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'a receipt-versus-transaction block hash disagreement records no inclusion',
    hashDisagreement.observation_state === 'found' &&
      hashDisagreement.observation_level === undefined &&
      hashDisagreement.receipt_status === 'success',
    `level ${String(hashDisagreement.observation_level)}`,
  );

  const txNumberDisagrees: SealedTransactionSource = {
    ...sourceWith([]),
    transactionByHash: async () => ({
      from: F.PAYER,
      blockNumber: 901n,
      blockHash: '0x'.padEnd(66, 'b'),
    }),
  };
  const numberDisagreement = await observeSealedTransaction({
    source: txNumberDisagrees,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'a receipt-versus-transaction block number disagreement records no inclusion',
    numberDisagreement.observation_state === 'found' &&
      numberDisagreement.observation_level === undefined,
    `level ${String(numberDisagreement.observation_level)}`,
  );

  const txWithoutPlacement: SealedTransactionSource = {
    ...sourceWith([]),
    transactionByHash: async () => ({ from: F.PAYER, blockNumber: null, blockHash: null }),
  };
  const missingPlacement = await observeSealedTransaction({
    source: txWithoutPlacement,
    transactionHash: F.SETTLEMENT_TX_HASH,
    expectedNetwork: F.NETWORK,
    expectedTransfer,
    observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
  });
  check(
    'a transaction object without block placement records no inclusion',
    missingPlacement.observation_state === 'found' &&
      missingPlacement.observation_level === undefined &&
      missingPlacement.receipt_status === 'success',
    `level ${String(missingPlacement.observation_level)}`,
  );

  console.log('\n  -- chain identity binding --');

  recordExecution('CHAIN-ID-001');
  {
    const wrongChain: SealedTransactionSource = { ...sourceWith([]), chainId: async () => 1n };
    const observation = await observeSealedTransaction({
      source: wrongChain,
      transactionHash: F.SETTLEMENT_TX_HASH,
      expectedTransfer,
      expectedNetwork: F.NETWORK,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
    check(
      'an endpoint reporting the wrong chain id abstains rather than reporting inclusion evidence',
      observation.observation_state === 'unavailable' &&
        observation.observation_level === undefined &&
        observation.receipt_status === undefined &&
        observation.token_transfer === undefined &&
        observation.observed_network === undefined &&
        observation.unavailable_reason?.includes('eip155:1') === true &&
        observation.unavailable_reason?.includes(F.NETWORK) === true,
      JSON.stringify(observation),
    );
  }

  recordExecution('CHAIN-ID-002');
  {
    // Simulates the endpoint's configured URL having been repointed between an earlier preflight
    // (which validated Base Sepolia) and this observation: the same endpoint reference now answers
    // Base mainnet. Nothing here reuses whatever preflight decided; this call re-asks independently
    // and abstains on its own evidence.
    const changedSincePreflight: SealedTransactionSource = {
      ...sourceWith([]),
      chainId: async () => 8453n,
    };
    const observation = await observeSealedTransaction({
      source: changedSincePreflight,
      transactionHash: F.SETTLEMENT_TX_HASH,
      expectedTransfer,
      expectedNetwork: F.NETWORK,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
    check(
      'an endpoint that now answers a different chain than an earlier preflight validated still abstains',
      observation.observation_state === 'unavailable' &&
        observation.unavailable_reason?.includes('eip155:8453') === true,
      JSON.stringify(observation),
    );
  }

  recordExecution('CHAIN-ID-003');
  {
    const malformedChainId: SealedTransactionSource = {
      ...sourceWith([]),
      chainId: async () => {
        throw new Error('the endpoint reported no usable chain id');
      },
    };
    const observation = await observeSealedTransaction({
      source: malformedChainId,
      transactionHash: F.SETTLEMENT_TX_HASH,
      expectedTransfer,
      expectedNetwork: F.NETWORK,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
    check(
      'a malformed or unparseable chain id abstains with a reason distinct from a chain-id mismatch',
      observation.observation_state === 'unavailable' &&
        observation.unavailable_reason === CHAIN_IDENTITY_UNESTABLISHED,
      JSON.stringify(observation),
    );
  }

  recordExecution('CHAIN-ID-004');
  {
    check(
      'an endpoint correctly reporting Base Sepolia establishes the chain identity and inclusion proceeds',
      bare.observed_network === F.NETWORK && bare.observation_level === 'l2_block_inclusion',
      JSON.stringify({ observed_network: bare.observed_network, level: bare.observation_level }),
    );
  }

  console.log('\n  -- ERC-20 transfer multiplicity --');

  const matchingLogForMultiplicity: ObservedLog = {
    address: F.ASSET_CONTRACT,
    topics: [
      TRANSFER_EVENT_TOPIC,
      `0x${F.PAYER.slice(2).padStart(64, '0')}`,
      `0x${F.PAY_TO.slice(2).padStart(64, '0')}`,
    ],
    data: `0x${BigInt(F.AMOUNT_BASE_UNITS).toString(16).padStart(64, '0')}`,
  };

  recordExecution('TRANSFER-001');
  {
    const oneMatch = await observeSealedTransaction({
      source: sourceWith([matchingLogForMultiplicity]),
      transactionHash: F.SETTLEMENT_TX_HASH,
      expectedTransfer,
      expectedNetwork: F.NETWORK,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
    const oneMatchComparison = compareExpectationToObservation({
      ...expectationSide,
      rpc_observation: oneMatch,
    });
    check(
      'exactly one matching Transfer event is recorded as a match, with the counts explicit',
      oneMatch.matching_transfer_count === 1 &&
        oneMatch.expected_contract_transfer_count === 1 &&
        oneMatchComparison.transfer_event === 'match',
      `matching ${String(oneMatch.matching_transfer_count)}, total ${String(oneMatch.expected_contract_transfer_count)}`,
    );
  }

  recordExecution('TRANSFER-002');
  {
    const twoMatches = await observeSealedTransaction({
      source: sourceWith([matchingLogForMultiplicity, matchingLogForMultiplicity]),
      transactionHash: F.SETTLEMENT_TX_HASH,
      expectedTransfer,
      expectedNetwork: F.NETWORK,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
    const twoMatchesComparison = compareExpectationToObservation({
      ...expectationSide,
      rpc_observation: twoMatches,
    });
    check(
      'two matching Transfer events are represented by an explicit count of two, never silently resolved to one match',
      twoMatches.matching_transfer_count === 2 &&
        twoMatches.expected_contract_transfer_count === 2 &&
        // Conservative: "exactly one" is what the pinned settlement path proves, so two matches is
        // not treated as an unambiguous match either.
        twoMatchesComparison.transfer_event !== 'match',
      `matching ${String(twoMatches.matching_transfer_count)}, verdict ${twoMatchesComparison.transfer_event}`,
    );
  }

  recordExecution('TRANSFER-003');
  {
    // `bare` (constructed with `sourceWith([])`, no logs at all) is the zero-transfers case
    // already established earlier in this suite: a successful, sealed-included receipt with no
    // transfer event on the expected contract at all.
    check(
      'zero matching Transfer events on a successful receipt is not matching payment evidence, with the zero count explicit',
      bare.matching_transfer_count === 0 &&
        bare.expected_contract_transfer_count === 0 &&
        bare.receipt_status === 'success' &&
        bareComparison.transfer_event === 'mismatch',
      `matching ${String(bare.matching_transfer_count)}, verdict ${bareComparison.transfer_event}`,
    );
  }
}

// Exact ERC-20 Transfer decoding. Completes EVM-EVIDENCE-001: the structural parser accepts the
// canonical event layout exactly — a well-formed token contract address, the Transfer signature
// topic compared case-insensitively, indexed address topics whose high 12 bytes are zero, and an
// amount of exactly one ABI word — and skips, never truncates or guesses at, anything else.
{
  const pad64 = (address: string): string => `0x${address.slice(2).padStart(64, '0')}`;
  const oneWord = (value: bigint): string => `0x${value.toString(16).padStart(64, '0')}`;
  const validLog: ObservedLog = {
    address: F.ASSET_CONTRACT,
    topics: [TRANSFER_EVENT_TOPIC, pad64(F.PAYER), pad64(F.PAY_TO)],
    data: oneWord(BigInt(F.AMOUNT_BASE_UNITS)),
  };

  const recognized = transfersOnContract([validLog], F.ASSET_CONTRACT);
  check(
    'a canonical Transfer event is recognized with its exact addresses and amount',
    recognized.length === 1 &&
      recognized[0]?.transfer_from === F.PAYER &&
      recognized[0]?.transfer_to === F.PAY_TO &&
      recognized[0]?.transfer_amount === F.AMOUNT_BASE_UNITS,
    JSON.stringify(recognized),
  );

  const upperHexTopic = `0x${TRANSFER_EVENT_TOPIC.slice(2).toUpperCase()}`;
  const upperTopic0 = transfersOnContract(
    [{ ...validLog, topics: [upperHexTopic, pad64(F.PAYER), pad64(F.PAY_TO)] }],
    F.ASSET_CONTRACT,
  );
  check(
    'an upper-hex Transfer signature topic is recognized (case-insensitive comparison)',
    upperTopic0.length === 1,
    JSON.stringify(upperTopic0),
  );

  const paddedFrom = `0x${'11'.repeat(12)}${F.PAYER.slice(2)}`;
  const dirtyFromTopic = transfersOnContract(
    [{ ...validLog, topics: [TRANSFER_EVENT_TOPIC, paddedFrom, pad64(F.PAY_TO)] }],
    F.ASSET_CONTRACT,
  );
  check(
    'a from topic with non-zero high padding bytes is ignored, never sliced to an address',
    dirtyFromTopic.length === 0,
    JSON.stringify(dirtyFromTopic),
  );

  const paddedTo = `0x${'11'.repeat(12)}${F.PAY_TO.slice(2)}`;
  const dirtyToTopic = transfersOnContract(
    [{ ...validLog, topics: [TRANSFER_EVENT_TOPIC, pad64(F.PAYER), paddedTo] }],
    F.ASSET_CONTRACT,
  );
  check(
    'a to topic with non-zero high padding bytes is ignored, never sliced to an address',
    dirtyToTopic.length === 0,
    JSON.stringify(dirtyToTopic),
  );

  check(
    'short uint256 data is ignored: the amount must be exactly one ABI word',
    transfersOnContract([{ ...validLog, data: '0x1' }], F.ASSET_CONTRACT).length === 0 &&
      transfersOnContract([{ ...validLog, data: '0x' }], F.ASSET_CONTRACT).length === 0,
  );

  check(
    'oversized data is ignored: a second ABI word is not a uint256 amount',
    transfersOnContract(
      [{ ...validLog, data: oneWord(BigInt(F.AMOUNT_BASE_UNITS)) + '0'.repeat(64) }],
      F.ASSET_CONTRACT,
    ).length === 0,
  );

  check(
    'a malformed token contract address yields no accepted transfer',
    transfersOnContract([validLog], F.ASSET_CONTRACT.slice(0, 41)).length === 0 &&
      transfersOnContract([validLog], `${F.ASSET_CONTRACT.slice(2)}`).length === 0 &&
      transfersOnContract([{ ...validLog, address: pad64(F.ASSET_CONTRACT) }], F.ASSET_CONTRACT)
        .length === 0,
  );
}

// ---------------------------------------------------------------------------------------------
// Preflight: the locally decidable checks, exercised without a socket.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- preflight: local configuration --');

{
  const usdc = expectedUsdcAsset();
  check('the upstream default-asset registry names Base Sepolia USDC', usdc !== undefined);
  const good = checkLocalConfiguration({
    network: F.NETWORK,
    payTo: F.PAY_TO,
    asset: usdc?.asset ?? '',
  });
  check(
    'a correct local configuration passes every local check',
    good.every((c) => c.status === 'ok'),
    good.map((c) => `${c.name}: ${c.status}`).join('; '),
  );
  const badNetwork = checkLocalConfiguration({
    network: 'eip155:8453',
    payTo: F.PAY_TO,
    asset: usdc?.asset ?? '',
  });
  check(
    'a mainnet network configuration is refused locally',
    badNetwork.some((c) => c.status === 'failed' && c.name === 'network is Base Sepolia'),
  );
  const badRecipient = checkLocalConfiguration({
    network: F.NETWORK,
    payTo: 'not-an-address',
    asset: usdc?.asset ?? '',
  });
  check(
    'a malformed recipient is refused locally',
    badRecipient.some((c) => c.status === 'failed' && c.name === 'recipient is an EVM address'),
  );
  check(
    'a payer that is also the recipient is refused as a demonstration invariant',
    distinctRolesCheck(F.PAY_TO, F.PAY_TO).status === 'failed' &&
      distinctRolesCheck(F.PAY_TO, F.PAYER).status === 'ok',
  );
}

// ---------------------------------------------------------------------------------------------
// Binding: a valid payment presented for something else.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- binding --');

const originalRequestBinding = JSON.parse(
  decoder.decode(honestLayout.files.get('request-binding.json')),
) as PaymentEvidenceRequestBindingV1;

/** A well-formed request binding for a different operation, built the same way as the real one. */
const bindingForResource = (absoluteUri: string): Uint8Array =>
  documentBytes(
    buildRequestBinding({
      components: componentsFromAbsoluteUri({ method: 'GET', absoluteUri }),
      body: F.REQUEST_BODY,
      selectedHeaders: originalRequestBinding.selectedHeaders,
    }),
  );

const OTHER_RESOURCE = 'https://api.example.test/v1/history?region=alpha&units=metric';
const OTHER_QUERY = 'https://api.example.test/v1/forecast?region=beta&units=metric';

recordExecution('EVM-BIND-001');
{
  const report = await verifyWith(
    new Map([['request-binding.json', bindingForResource(OTHER_RESOURCE)]]),
  );
  check(
    'a payment bound to one resource fails when presented for another',
    failedExactly(report, ['request binding digest']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
  check(
    'the record itself still verifies, so the failure is the binding and not the signature',
    passed(report, 'record signature and schema'),
  );
}

recordExecution('EVM-BIND-002');
{
  const report = await verifyWith(
    new Map([['request-binding.json', bindingForResource(OTHER_QUERY)]]),
  );
  check(
    'the same path with a changed query fails request binding',
    failedExactly(report, ['request binding digest']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-BIND-003');
{
  const altered = encoder.encode(
    F.ORIGIN_RESULT_BODY_TEXT.replace('"tempC":17.4', '"tempC":31.9'),
  );
  const report = await verifyWith(new Map([['origin-result-body.bin', altered]]));
  check(
    'an altered origin result fails the result binding',
    failedExactly(report, ['origin result body']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
  check(
    'the result binding document itself still matches the record',
    passed(report, 'origin result binding digest'),
  );
}

/**
 * EVM-BIND-004. The native artifact is valid; the binding names a different one.
 *
 * The failure has to be attributable to the binding alone, so the native payment artifact left in
 * the directory is checked against the upstream validator in the same breath. Blaming x402 for a
 * binding this example got wrong would be exactly the wrong lesson to draw.
 */
recordExecution('EVM-BIND-004');
{
  const observedSignature = honestRun.origin.observedHeaders['payment-signature'];
  if (observedSignature === undefined) throw new Error('the run observed no payment-signature');
  const nativeArtifact = await requireValidX402Artifact({
    name: 'Payment-Signature',
    observedValue: observedSignature,
    capturePoint: 'origin_request_after_http_parsing',
    httpVersion: '1.1',
  });
  check(
    'the native payment artifact is accepted by the upstream validator',
    nativeArtifact.stages['upstream-schema'] === 'accepted' &&
      nativeArtifact.stages['scheme-payload'] === 'accepted',
    JSON.stringify(nativeArtifact.stages),
  );

  // A different, also valid, payment field value: the binding names an artifact that is not the
  // one present, while both are well-formed x402 objects.
  const otherValue = F.OBSERVED_REQUEST_HEADERS['payment-signature'];
  const otherArtifact = await captureObservedX402Artifact({
    name: 'Payment-Signature',
    observedValue: otherValue,
    capturePoint: 'origin_request_after_http_parsing',
    httpVersion: '1.1',
  });
  const mismatchedBinding = documentBytes(
    buildRequestBinding({
      components: componentsFromAbsoluteUri({ method: 'GET', absoluteUri: F.RESOURCE_URL }),
      body: F.REQUEST_BODY,
      selectedHeaders: [
        { name: 'payment-signature', observedValueDigest: otherArtifact.observedValueDigest },
      ],
    }),
  );
  const report = await verifyWith(new Map([['request-binding.json', mismatchedBinding]]));
  check(
    'a valid native artifact with a binding that names another fails at the binding',
    failedExactly(report, ['request binding digest']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

// ---------------------------------------------------------------------------------------------
// Tamper: one edit, one named failure.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- tamper --');

recordExecution('EVM-TAMPER-001');
{
  const binding = JSON.parse(
    decoder.decode(honestLayout.files.get('origin-result-binding.json')),
  ) as { bodyDigest: string };
  const tampered = documentBytes({ ...binding, bodyDigest: `sha256:${'0'.repeat(64)}` });
  const report = await verifyWith(new Map([['origin-result-binding.json', tampered]]));
  check(
    'a tampered result digest fails the bound document, the body it names, and the observation that repeats it',
    failedExactly(report, [
      'origin result binding digest',
      'origin result body',
      'result binding and observation name the same origin result digest',
    ]),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-TAMPER-002');
{
  const observed = honestRun.origin.observedHeaders['payment-signature'];
  if (observed === undefined) throw new Error('the run observed no payment-signature');
  const tampered = encoder.encode(`${observed.slice(0, -4)}AAAA`);
  const report = await verifyWith(new Map([['artifacts/payment-signature.txt', tampered]]));
  check(
    'a tampered observed field value fails its own digest and its own x402 native validation, and nothing else',
    failedExactly(report, ['payment-signature digest', 'x402 native validation: payment-signature']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
  check(
    'the request binding that selected that field still matches the record',
    passed(report, 'request binding digest'),
  );
}

/**
 * EVM-TAMPER-003. The record's own payload is edited into something more favourable.
 *
 * The edit keeps the payload well-formed on purpose: base64url, valid JSON, a plausible value. The
 * signature is what refuses it, and the code is the one the protocol defines for that.
 */
recordExecution('EVM-TAMPER-003');
{
  const [header, payload, signature] = honestLayout.jws.split('.');
  if (header === undefined || payload === undefined || signature === undefined) {
    throw new Error('the record is not a compact serialization');
  }
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
    extensions: Record<string, Record<string, unknown>>;
  };
  const commerce = claims.extensions['org.peacprotocol/commerce'];
  if (commerce === undefined) throw new Error('the record carries no commerce group');
  commerce['amount_minor'] = '1';
  const editedPayload = Buffer.from(JSON.stringify(claims), 'utf8').toString('base64url');
  const editedJws = `${header}.${editedPayload}.${signature}`;
  check('the edited record differs from the issued one', editedJws !== honestLayout.jws);

  const directory = mkdtempSync(join(tmpdir(), 'peac-evidence-'));
  temporaryDirectories.push(directory);
  writeEvidence(directory, {
    jws: editedJws,
    files: new Map(honestLayout.files).set('record.jws', encoder.encode(`${editedJws}\n`)),
  });
  const report = await verifyEvidence(directory, issuerKey.publicKey);
  const recordCheck = report.checks.find((c) => c.name === 'record signature and schema');
  check(
    'an edited record payload is refused with an invalid signature',
    !report.ok && recordCheck?.ok === false && recordCheck.detail === 'E_INVALID_SIGNATURE',
    `${String(recordCheck?.detail)}`,
  );
}

/**
 * EVM-TAMPER-004. The settlement field value is untouched and valid; the observation document
 * beside it is not.
 *
 * This is the attribution case for the settlement side: the native artifact passes its own
 * structural check, and the failure names the observation document this example produced.
 */
recordExecution('EVM-TAMPER-004');
{
  const observedResponse = honestRun.origin.observedHeaders['payment-response'];
  if (observedResponse === undefined) throw new Error('the run observed no payment-response');
  const nativeReceipt = await captureObservedX402Artifact({
    name: 'Payment-Response',
    observedValue: observedResponse,
    capturePoint: 'origin_response_before_gateway',
    httpVersion: '1.1',
  });
  check(
    'the native settlement artifact passes its structural check',
    nativeReceipt.localStructural?.localStructuralStatus === 'accepted',
    JSON.stringify(nativeReceipt.localStructural),
  );

  const observation = JSON.parse(
    decoder.decode(honestLayout.files.get('chain-observation.json')),
  ) as { payment_expectation: Record<string, unknown> } & Record<string, unknown>;
  const tampered = documentBytes({
    ...observation,
    payment_expectation: { ...observation.payment_expectation, amount_base_units: '1' },
  });
  const report = await verifyWith(new Map([['chain-observation.json', tampered]]));
  check(
    'an altered observation document fails its own digest and the amount the record repeats, not the native artifact',
    failedExactly(report, [
      'chain observation digest',
      'evidence projection: amount_minor',
    ]) && passed(report, 'payment-response digest'),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-TAMPER-005');
{
  const report = await verifyWith(new Map([['artifacts/payment-response.txt', null]]));
  check(
    'a missing native artifact fails both its digest and the presence contract',
    failedExactly(report, ['payment-response digest', 'artifact presence contract']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
  check(
    'the presence failure names the artifact and what the terminal state expected',
    report.checks.some(
      (c) =>
        c.name === 'artifact presence contract' &&
        !c.ok &&
        c.detail.includes('artifacts/payment-response.txt') &&
        c.detail.includes('required'),
    ),
  );
}

for (const directory of temporaryDirectories) rmSync(directory, { recursive: true, force: true });

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
