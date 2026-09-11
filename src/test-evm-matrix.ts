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
import { createServer, type Server } from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { registerExactEvmScheme } from '@x402/evm/exact/server';
import { ExactEvmScheme as UpstreamExactEvmFacilitator } from '@x402/evm/exact/facilitator';
import { authorizationTypes, type FacilitatorEvmSigner } from '@x402/evm';
import { privateKeyToAccount } from 'viem/accounts';
import { generateKeypair } from '@peac/crypto';
import { issue, computeJsonDocumentDigestJcs } from '@peac/protocol';
import type { EvidencePillar, JsonValue } from '@peac/kernel';
import { x402Client, x402HTTPClient } from '@x402/core/client';
import {
  PAYMENT_IDENTIFIER,
  declarePaymentIdentifierExtension,
  extractPaymentIdentifier,
} from '@x402/extensions/payment-identifier';
import type { PaymentPayload, PaymentRequired } from '@x402/core/types';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { bindingDigest, buildRequestBinding, type PaymentEvidenceRequestBindingV1 } from './binding.ts';
import { componentsFromAbsoluteUri } from './components.ts';
import { captureObservedX402Artifact, requireValidX402Artifact } from './x402-header.ts';
import { coerceDigest, digestBytes } from './digest.ts';
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
import {
  COMMERCE_GROUP,
  EXPECTED_EVIDENCE_DIR,
  PAYMENT_EVIDENCE_GROUP,
  RECORD_TYPE,
  runEvidenceDir,
  runPublicKeyPath,
  writeEvidence,
  type EvidenceLayout,
} from './flow/issue-record.ts';
import {
  assertCanonicalLiveHttpsIssuer,
  FIXTURE_ISSUER,
  IssuerConfigurationError,
  MAX_STORED_KID_UTF8_BYTES,
  resolveIssuerKey,
  storedIssuerBinding,
} from './flow/issuer-key.ts';
import { InvalidKeyFileError } from './flow/key-file.ts';
import { loadPayerAccount } from './flow/payer-key.ts';
import { compareExpectationToObservation } from './flow/observe-settlement.ts';
import {
  admitReceiptResult,
  admitSealedBlockResult,
  admitTransactionResult,
  baseSealedRpcSource,
  ENDPOINT_RPC_ERROR,
  ENDPOINT_RESPONSE_UNUSABLE,
  ENDPOINT_TEMPORARILY_UNAVAILABLE,
  ENDPOINT_UNREACHABLE,
  MALFORMED_TRANSACTION_REFERENCE,
  MAX_RECEIPT_LOGS,
  observeSealedTransaction,
  TRANSFER_EVENT_TOPIC,
  transfersOnContract,
  type ObservedLog,
  type SealedRpcObservationV1,
  type SealedTransactionSource,
} from './flow/observe-transaction.ts';
import {
  admitAbiUint256Word,
  admitRpcQuantity,
  JsonRpcFailure,
  jsonRpcRequest,
  MAX_RPC_RESPONSE_BYTES,
} from './flow/evm-json-rpc.ts';
import {
  beginLiveAttempt,
  eip3009SelectionGuard,
  executeLiveRun,
  LiveRunFailure,
  observeUntilSealed,
  paymentIdentifierClientExtension,
  type LiveObservationResult,
  type LiveRunPhases,
} from './flow/live-e2e.ts';
import {
  admitEndpointUrl,
  BASE_SEPOLIA_CHAIN_ID,
  checkChainState,
  checkIssuerReadiness,
  checkLocalConfiguration,
  distinctRolesCheck,
  EndpointConfigurationError,
  expectedUsdcAsset,
  jsonRpcChainState,
  MIN_USDC_BASE_UNITS,
  reviewerMaterialWritableCheck,
  runPreflight,
} from './flow/preflight.ts';
import {
  verifyEvidence,
  VERIFIER_PROFILE,
  type EvidenceVerificationReport,
} from './flow/verify-evidence.ts';
import type { EvidenceArtifact } from './flow/presence.ts';
import { readIssuerPublicKeyFile } from './flow/public-key-file.ts';

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
async function startOrigin(
  behavior: FixtureFacilitatorBehavior = {},
  identifierCapacity?: number,
): Promise<Origin> {
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
    ...(identifierCapacity !== undefined ? { identifierCapacity } : {}),
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

/** The claims a record's payload carries, decoded without verifying the signature over them. */
interface DecodedRecordClaims {
  readonly iss: string;
  readonly type: string;
  readonly pillars?: EvidencePillar[];
  readonly occurred_at?: string;
  readonly extensions: Record<string, Record<string, unknown>>;
}

/** Decode a compact JWS payload segment without checking its signature. Tamper cases only. */
function decodeClaims(jws: string): DecodedRecordClaims {
  const payload = jws.split('.')[1];
  if (payload === undefined) throw new Error('the record is not a compact serialization');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as DecodedRecordClaims;
}

/**
 * Re-sign the honest evidence with a native artifact and its bound digest edited, and verify it.
 *
 * `mutate` receives a copy of the honest layout's files and the honest record's decoded claims. It
 * edits a native artifact's decoded object, re-encodes it as standard base64 of `JSON.stringify`,
 * writes the new bytes into `files`, and sets the matching digest inside the payment-evidence
 * extension so the record it is about to be bound to names the artifact actually being shipped.
 * The record is then re-issued over the same iss/type/kid/pillars/occurred_at/extensions as the
 * honest one, with a fresh jti, so the only thing distinguishing this evidence from the honest run
 * is what the case deliberately changed.
 */
async function reissueWith(
  mutate: (
    files: Map<EvidenceArtifact, Uint8Array>,
    claims: DecodedRecordClaims,
  ) => void | Promise<void>,
): Promise<EvidenceVerificationReport> {
  const claims = decodeClaims(honestLayout.jws);
  const files = new Map(honestLayout.files);
  await mutate(files, claims);
  const result = await issue({
    iss: claims.iss,
    kind: 'evidence',
    type: claims.type,
    privateKey: issuerKey.privateKey,
    kid: issuerKey.kid,
    ...(claims.pillars !== undefined ? { pillars: claims.pillars } : {}),
    ...(claims.occurred_at !== undefined ? { occurred_at: claims.occurred_at } : {}),
    extensions: claims.extensions,
  });
  files.set('record.jws', encoder.encode(`${result.jws}\n`));
  const directory = mkdtempSync(join(tmpdir(), 'peac-evidence-'));
  temporaryDirectories.push(directory);
  writeEvidence(directory, { jws: result.jws, files });
  return verifyEvidence(directory, issuerKey.publicKey);
}

/** The evidence extension group's digest fields, so a case can name the one it is refreshing. */
const paymentEvidence = (claims: DecodedRecordClaims): Record<string, unknown> => {
  const group = claims.extensions[PAYMENT_EVIDENCE_GROUP];
  if (group === undefined) throw new Error('the honest record carries no payment-evidence extension');
  return group;
};

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
 * EVM-REPLAY-001. The same authorization, presented twice — under the payment-identifier
 * extension's documented resource-server semantics, which this origin now implements.
 *
 * TWO DISTINCT REPLAYS EXIST, AND THEY MUST BEHAVE DIFFERENTLY. A retry carrying the SAME payment
 * identifier and the same request is the extension's idempotent-retry case: the origin serves the
 * cached settled result and processes no second payment, so the facilitator is asked to settle
 * exactly once. A replay of the same AUTHORIZATION under a DIFFERENT payment identifier is not a
 * retry — it is an independent payment attempt reusing consumed authorization material — and it
 * must reach the facilitator and fail there, because on the network a consumed EIP-3009
 * authorization cannot transfer twice. Which internal mechanism a real facilitator or the chain
 * uses to enforce that is deliberately not named, because this suite has no way to observe it.
 */
recordExecution('EVM-REPLAY-001');
recordExecution('X402-VALID-003');
recordExecution('EVM-IDEM-001');
{
  const origin = await startOrigin();
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);
    const first = await present(origin, http, payment);
    const observationsBeforeReplay = origin.observations.length;
    const firstBody = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(payment),
    });
    const replayedBytes = new Uint8Array(await firstBody.arrayBuffer());

    check(
      'the first settlement of an authorization succeeds',
      first.status === 200 &&
        first.observation.lifecycle.terminalState === 'response_write_attempted',
      `status ${first.status}, ${first.observation.lifecycle.terminalState}`,
    );
    check(
      'a retry with the same payment identifier and the same request is served the cached result',
      firstBody.status === 200 && replayedBytes.length > 0,
      `status ${firstBody.status}`,
    );
    check(
      'the idempotent retry repeats the settlement response of the payment that actually happened',
      firstBody.headers.get('payment-response') !== null &&
        firstBody.headers.get('payment-response') ===
          first.observation.observedHeaders['payment-response'],
    );
    check(
      'the idempotent retry processes no second payment and records no second lifecycle',
      origin.calls.settle === 1 &&
        origin.calls.verify === 1 &&
        origin.observations.length === observationsBeforeReplay,
      `settle calls ${origin.calls.settle}, verify calls ${origin.calls.verify}`,
    );

    // EVM-IDEM-001 a): the reviewer probe. Base64 of `{extensions: <same extensions>}` only --
    // no `payload`, so no authorization and no signature at all. It must not be able to read the
    // cached result on the strength of the identifier alone: presentedAuthorization() returns
    // undefined for it, so this layer leaves the map untouched and passes it through to the
    // payment middleware, which refuses it on its own terms.
    const probeExtensions = (payment as { extensions?: unknown }).extensions;
    const probeHeader = Buffer.from(JSON.stringify({ extensions: probeExtensions })).toString(
      'base64',
    );
    const probe = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: { 'payment-signature': probeHeader },
    });
    const probeBytes = new Uint8Array(await probe.arrayBuffer());
    check(
      'an identifier-only probe with no authorization is not served the cached result',
      probe.status !== 200 &&
        Buffer.compare(Buffer.from(probeBytes), Buffer.from(replayedBytes)) !== 0,
      `status ${probe.status}`,
    );
    check(
      'the identifier-only probe reaches no settlement; the honest settlement stays the only one',
      origin.calls.settle === 1 && origin.calls.verify === 1,
      `settle calls ${origin.calls.settle}, verify calls ${origin.calls.verify}`,
    );

    // EVM-IDEM-001 b): same identifier, same fingerprint, a DIFFERENT authorization (changed
    // nonce). The cached result is bound to the authorization that was actually settled, not to
    // the identifier alone, so this is refused rather than served.
    const differentAuthorization: PaymentPayload = structuredClone(payment);
    (differentAuthorization.payload as { authorization: { nonce: string } }).authorization.nonce =
      `0x${'9d'.repeat(32)}`;
    const differentAuthResponse = await fetch(
      `${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`,
      { method: 'GET', headers: http.encodePaymentSignatureHeader(differentAuthorization) },
    );
    const differentAuthBytes = new Uint8Array(await differentAuthResponse.arrayBuffer());
    check(
      'the same identifier presenting a different authorization is refused, not served the cached result',
      differentAuthResponse.status === 409 &&
        Buffer.compare(Buffer.from(differentAuthBytes), Buffer.from(replayedBytes)) !== 0 &&
        origin.calls.settle === 1,
      `status ${differentAuthResponse.status}, settle calls ${origin.calls.settle}`,
    );

    // The same consumed authorization under a DIFFERENT payment identifier: an independent
    // attempt, not a retry. It passes the idempotency layer (different identifiers are
    // independent) and the facilitator refuses the settlement.
    const freshId = 'pay_00000000000000000000000000replay';
    const reused: PaymentPayload = structuredClone(payment);
    (reused.extensions as Record<string, { info: { id?: string } }>)[
      'payment-identifier'
    ]!.info.id = freshId;
    const second = await present(origin, http, reused);
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
      'the independent attempt reached the facilitator, so the refusal was a settlement decision',
      origin.calls.settle === 2,
      `settle calls ${origin.calls.settle}`,
    );

    // Same identifier, DIFFERENT request: refused without reusing the cached result and without
    // creating a payment — the 409-style refusal the extension's documentation specifies.
    const conflicting = await fetch(
      `${origin.baseUrl}${RESOURCE_PATH}?region=beta&units=metric`,
      { method: 'GET', headers: http.encodePaymentSignatureHeader(payment) },
    );
    const conflictingBytes = new Uint8Array(await conflicting.arrayBuffer());
    check(
      'the same identifier naming a different request is refused, not served the cached result',
      conflicting.status === 409 &&
        Buffer.compare(Buffer.from(conflictingBytes), Buffer.from(replayedBytes)) !== 0 &&
        origin.calls.settle === 2 &&
        origin.calls.verify === 2,
      `status ${conflicting.status}, settle calls ${origin.calls.settle}`,
    );

    // The declaration marks the identifier required: a payload without one is refused with 400
    // before any verification, using the upstream requirement check.
    const withoutIdentifier: PaymentPayload = structuredClone(payment);
    delete (withoutIdentifier as { extensions?: unknown }).extensions;
    const verifiesBefore = origin.calls.verify;
    const missing = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(withoutIdentifier),
    });
    await missing.arrayBuffer();
    check(
      'a required payment identifier that is absent is refused with 400 before verification',
      missing.status === 400 && origin.calls.verify === verifiesBefore,
      `status ${missing.status}, verify calls ${origin.calls.verify}`,
    );
  } finally {
    await origin.close();
  }
}

// The cache never manufactures a settlement: a run whose settlement FAILED caches nothing, so a
// retry with the same identifier and the same request goes through payment processing again
// rather than being served a success that never happened.
{
  const origin = await startOrigin({ rejectSettlement: 'synthetic_settlement_refusal' });
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);
    const first = await present(origin, http, payment);
    const retry = await present(origin, http, payment);
    check(
      'a failed settlement caches nothing: the same-identifier retry is processed, not replayed',
      first.observation.lifecycle.terminalState === 'settlement_failed' &&
        retry.observation.lifecycle.terminalState === 'settlement_failed' &&
        retry.status === 402 &&
        origin.calls.settle === 2,
      `first ${first.observation.lifecycle.terminalState}, retry status ${retry.status}, ` +
        `settle calls ${origin.calls.settle}`,
    );
  } finally {
    await origin.close();
  }
}

// Distinct identifiers over distinct authorizations are fully independent: two settlements, two
// written results, no cross-talk through the idempotency layer.
{
  const origin = await startOrigin();
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const base = await http.createPaymentPayload(paymentRequired);
    const withFreshMaterial = (id: string, nonce: string): PaymentPayload => {
      const cloned: PaymentPayload = structuredClone(base);
      (cloned.payload as { authorization: { nonce: string } }).authorization.nonce = nonce;
      (cloned.extensions as Record<string, { info: { id?: string } }>)[
        'payment-identifier'
      ]!.info.id = id;
      return cloned;
    };
    const a = await present(origin, http, withFreshMaterial('pay_independent000000000a', `0x${'6a'.repeat(32)}`));
    const b = await present(origin, http, withFreshMaterial('pay_independent000000000b', `0x${'6b'.repeat(32)}`));
    check(
      'distinct payment identifiers over distinct authorizations settle independently',
      a.status === 200 && b.status === 200 && origin.calls.settle === 2,
      `a ${a.status}, b ${b.status}, settle calls ${origin.calls.settle}`,
    );
  } finally {
    await origin.close();
  }
}

// ---------------------------------------------------------------------------------------------
// EVM-IDEM-002: overlapping requests under one payment identifier share one operation.
// ---------------------------------------------------------------------------------------------

recordExecution('EVM-IDEM-002');
{
  let releaseBarrier: (() => void) | undefined;
  const barrierProceed = new Promise<void>((resolve) => {
    releaseBarrier = resolve;
  });
  let arrivedResolve: (() => void) | undefined;
  const arrived = new Promise<void>((resolve) => {
    arrivedResolve = resolve;
  });
  const origin = await startOrigin({
    settlementBarrier: { arrived: () => arrivedResolve?.(), proceed: barrierProceed },
  });
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);

    // Request A reaches settlement and is held at the barrier.
    const aPromise = fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(payment),
    });
    await arrived;

    // Request B: the identical header. It must wait on A's pending operation rather than start
    // its own verification and settlement.
    const bPromise = fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(payment),
    });

    // Request C: same identifier, same fingerprint, a DIFFERENT authorization. It must not wait
    // on A — it is refused immediately as bound to a different authorization, so it is awaited
    // in full before the barrier is released.
    const conflicting: PaymentPayload = structuredClone(payment);
    (conflicting.payload as { authorization: { nonce: string } }).authorization.nonce =
      `0x${'c3'.repeat(32)}`;
    const c = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(conflicting),
    });
    await c.arrayBuffer();
    check(
      'a differently-authorized request under the identifier in flight is refused immediately, without waiting on it',
      c.status === 409,
      `status ${c.status}`,
    );

    const observationsBeforeRelease = origin.observations.length;
    releaseBarrier?.();
    const [a, b] = await Promise.all([aPromise, bPromise]);
    const aBytes = new Uint8Array(await a.arrayBuffer());
    const bBytes = new Uint8Array(await b.arrayBuffer());
    check(
      'both the settling request and the one that waited on it observe the identical settled result',
      a.status === 200 &&
        b.status === 200 &&
        Buffer.compare(Buffer.from(aBytes), Buffer.from(bBytes)) === 0 &&
        a.headers.get('payment-response') !== null &&
        a.headers.get('payment-response') === b.headers.get('payment-response'),
      `a ${a.status}, b ${b.status}`,
    );
    check(
      'overlapping requests under one identifier share exactly one verification and one settlement',
      origin.calls.verify === 1 && origin.calls.settle === 1,
      `verify calls ${origin.calls.verify}, settle calls ${origin.calls.settle}`,
    );
    check(
      'the shared operation adds exactly one lifecycle observation for the paid path',
      origin.observations.length === observationsBeforeRelease + 1,
      `observations grew by ${origin.observations.length - observationsBeforeRelease}`,
    );
  } finally {
    await origin.close();
  }
}

// Distinct identifiers over distinct authorizations, held at the same barrier, settle
// independently rather than serializing on each other — the barrier synchronizes this test, it
// does not create cross-identifier contention. Reuses the sequential distinct-identifiers case
// above for the non-concurrent half of this property.
{
  let releaseBarrier: (() => void) | undefined;
  const barrierProceed = new Promise<void>((resolve) => {
    releaseBarrier = resolve;
  });
  let arrivals = 0;
  let bothArrivedResolve: (() => void) | undefined;
  const bothArrived = new Promise<void>((resolve) => {
    bothArrivedResolve = resolve;
  });
  const origin = await startOrigin({
    settlementBarrier: {
      arrived: () => {
        arrivals++;
        if (arrivals === 2) bothArrivedResolve?.();
      },
      proceed: barrierProceed,
    },
  });
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const base = await http.createPaymentPayload(paymentRequired);
    const withFreshMaterial = (id: string, nonce: string): PaymentPayload => {
      const cloned: PaymentPayload = structuredClone(base);
      (cloned.payload as { authorization: { nonce: string } }).authorization.nonce = nonce;
      (cloned.extensions as Record<string, { info: { id?: string } }>)[
        'payment-identifier'
      ]!.info.id = id;
      return cloned;
    };
    const aPromise = fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(
        withFreshMaterial('pay_barrier00000000000000a', `0x${'d4'.repeat(32)}`),
      ),
    });
    const bPromise = fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(
        withFreshMaterial('pay_barrier00000000000000b', `0x${'d5'.repeat(32)}`),
      ),
    });
    await bothArrived;
    releaseBarrier?.();
    const [a, b] = await Promise.all([aPromise, bPromise]);
    await Promise.all([a.arrayBuffer(), b.arrayBuffer()]);
    check(
      'distinct identifiers held at the same barrier settle independently, not serialized on each other',
      a.status === 200 && b.status === 200 && origin.calls.settle === 2,
      `a ${a.status}, b ${b.status}, settle calls ${origin.calls.settle}`,
    );
  } finally {
    await origin.close();
  }
}

// ---------------------------------------------------------------------------------------------
// EVM-IDEM-003: a rejected attempt releases the identifier; an uncertain outcome never does.
// ---------------------------------------------------------------------------------------------

recordExecution('EVM-IDEM-003');

// a) concurrent variant of the sequential rejectSettlement case above: B is sent while A's
// refused settlement is held at the barrier, and is processed — settling a second time — only
// once A has concluded as rejected and released the identifier.
{
  let releaseBarrier: (() => void) | undefined;
  const barrierProceed = new Promise<void>((resolve) => {
    releaseBarrier = resolve;
  });
  let arrivedResolve: (() => void) | undefined;
  const arrived = new Promise<void>((resolve) => {
    arrivedResolve = resolve;
  });
  const origin = await startOrigin({
    rejectSettlement: 'synthetic_settlement_refusal',
    settlementBarrier: { arrived: () => arrivedResolve?.(), proceed: barrierProceed },
  });
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);
    const aPromise = fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(payment),
    });
    await arrived;
    const bPromise = fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(payment),
    });
    releaseBarrier?.();
    const [a, b] = await Promise.all([aPromise, bPromise]);
    await Promise.all([a.arrayBuffer(), b.arrayBuffer()]);
    check(
      'a request that waited through a refused settlement is processed once it releases the identifier',
      a.status === 402 && b.status === 402 && origin.calls.settle === 2,
      `a ${a.status}, b ${b.status}, settle calls ${origin.calls.settle}`,
    );
  } finally {
    await origin.close();
  }
}

// b) settlement that raises rather than answers is uncertain, and an uncertain identifier
// refuses every further attempt, regardless of authorization, for the rest of the run.
{
  const origin = await startOrigin({ throwOnSettle: 'synthetic settlement exception' });
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);
    const first = await present(origin, http, payment);
    check(
      'a settlement that raises is recorded honestly as settlement_failed/settlement_exception',
      first.observation.lifecycle.terminalState === 'settlement_failed' &&
        first.observation.lifecycle.failureReason === 'settlement_exception',
      `${first.observation.lifecycle.terminalState}, ${String(first.observation.lifecycle.failureReason)}`,
    );
    const retrySameAuth = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(payment),
    });
    const retryBody: unknown = await retrySameAuth.json().catch(() => undefined);
    check(
      'a retry under an uncertain identifier is refused with the unknown-outcome message',
      retrySameAuth.status === 409 &&
        typeof retryBody === 'object' &&
        retryBody !== null &&
        (retryBody as { error?: string }).error ===
          'the outcome of an earlier attempt under this payment identifier is unknown; it cannot be retried in this process',
      `status ${retrySameAuth.status}, body ${JSON.stringify(retryBody)}`,
    );
    const differentAuth: PaymentPayload = structuredClone(payment);
    (differentAuth.payload as { authorization: { nonce: string } }).authorization.nonce =
      `0x${'e1'.repeat(32)}`;
    const retryDifferentAuth = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(differentAuth),
    });
    await retryDifferentAuth.arrayBuffer();
    check(
      'an uncertain identifier refuses even a differently-authorized attempt; nothing settles again',
      retryDifferentAuth.status === 409 && origin.calls.settle === 1,
      `status ${retryDifferentAuth.status}, settle calls ${origin.calls.settle}`,
    );
  } finally {
    await origin.close();
  }
}

// c) verification refused before settlement is reached at all: a retry-safe rejection, so a
// corrected attempt under the same identifier is released back to verification.
{
  const origin = await startOrigin({ rejectVerification: 'synthetic_verification_refusal' });
  try {
    const http = upstreamClient();
    const { paymentRequired } = await challenge(origin, http);
    const payment = await http.createPaymentPayload(paymentRequired);
    const first = await present(origin, http, payment);
    check(
      'verification refused ends in verification_rejected with no settlement attempted',
      first.observation.lifecycle.terminalState === 'verification_rejected',
      first.observation.lifecycle.terminalState,
    );
    const corrected: PaymentPayload = structuredClone(payment);
    (corrected.payload as { authorization: { nonce: string } }).authorization.nonce =
      `0x${'f2'.repeat(32)}`;
    await present(origin, http, corrected);
    check(
      'a rejected verification releases the identifier: a corrected attempt reaches verification again',
      origin.calls.verify === 2,
      `verify calls ${origin.calls.verify}`,
    );
  } finally {
    await origin.close();
  }
}

// ---------------------------------------------------------------------------------------------
// EVM-IDEM-004: the identifier store refuses new identifiers at capacity and never evicts.
// ---------------------------------------------------------------------------------------------

recordExecution('EVM-IDEM-004');
{
  const origin = await startOrigin({}, 1);
  try {
    const http = upstreamClient('pay_capacity0000000000001a');
    const { paymentRequired } = await challenge(origin, http);
    const first = await http.createPaymentPayload(paymentRequired);
    const firstResponse = await present(origin, http, first);
    check(
      'the first identifier is admitted under a capacity of one',
      firstResponse.status === 200,
      `status ${firstResponse.status}`,
    );

    const secondHttp = upstreamClient('pay_capacity0000000000002b');
    const secondPayment = await secondHttp.createPaymentPayload(paymentRequired);
    const second = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: secondHttp.encodePaymentSignatureHeader(secondPayment),
    });
    const secondBody: unknown = await second.json().catch(() => undefined);
    check(
      'a new identifier is refused at capacity, before verification, and nothing is evicted',
      second.status === 503 &&
        typeof secondBody === 'object' &&
        secondBody !== null &&
        (secondBody as { error?: string }).error === 'payment identifier store at capacity' &&
        origin.calls.verify === 1,
      `status ${second.status}, verify calls ${origin.calls.verify}`,
    );

    const retryFirst = await fetch(`${origin.baseUrl}${RESOURCE_PATH}${RESOURCE_QUERY}`, {
      method: 'GET',
      headers: http.encodePaymentSignatureHeader(first),
    });
    const retryFirstBytes = new Uint8Array(await retryFirst.arrayBuffer());
    check(
      'a retry of the already-admitted identifier is still served after the store is at capacity',
      retryFirst.status === 200 && retryFirstBytes.length > 0,
      `status ${retryFirst.status}`,
    );
  } finally {
    await origin.close();
  }
}

// Completes EVM-REPLAY-001: consumed-authorization state is scoped to the pair
// (authorizer, nonce), the way EIP-3009 keys `authorizationState(address authorizer, bytes32
// nonce)`. The same authorizer repeating a nonce is a duplicate — under any hex casing — while a
// different authorizer using the same nonce value is a different authorization and must not
// collide with it. And consumption models a SUCCESSFUL settlement only: an attempt that the
// facilitator refuses has not consumed the authorization, so a corrected retry of the same
// authorizer-and-nonce pair must still settle.
{
  const withAuthorization = (from: string, nonce: string = F.AUTHORIZATION_NONCE): PaymentPayload =>
    structuredClone({
      ...F.PAYMENT_PAYLOAD,
      payload: {
        ...F.PAYMENT_PAYLOAD.payload,
        authorization: { ...F.EXACT_EVM_AUTHORIZATION, from, nonce },
      },
    });
  const otherAuthorizer = '0x00000000000000000000000000000000000000aa';
  const otherNonce = `0x${'5c'.repeat(32)}`;
  const scoped = createFixtureFacilitator(F.NETWORK);
  const first = await scoped.client.settle(withAuthorization(F.PAYER), F.PAYMENT_REQUIREMENTS);
  const repeated = await scoped.client.settle(
    withAuthorization(`0x${F.PAYER.slice(2).toUpperCase()}`),
    F.PAYMENT_REQUIREMENTS,
  );
  const differentAuthorizer = await scoped.client.settle(
    withAuthorization(otherAuthorizer),
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

  // A fresh authorization presented against a requirement it does not satisfy is refused — and
  // that refusal must NOT consume it. On the network only the successful call changes the
  // ERC-3009 authorization state; a stand-in that consumed on failure would make the retry
  // branch unreachable and would model a mechanism the standard does not have.
  const refusedAttempt = await scoped.client.settle(withAuthorization(F.PAYER, otherNonce), {
    ...F.PAYMENT_REQUIREMENTS,
    amount: '999999999',
  });
  check(
    'a settlement refused on its requirements reports the refusal and no transaction',
    refusedAttempt.success === false &&
      refusedAttempt.errorReason === 'amount_mismatch' &&
      refusedAttempt.transaction === '',
    JSON.stringify(refusedAttempt),
  );
  const correctedRetry = await scoped.client.settle(
    withAuthorization(F.PAYER, otherNonce),
    F.PAYMENT_REQUIREMENTS,
  );
  check(
    'the same authorization settles after a refused attempt: a failed settlement does not consume it',
    correctedRetry.success === true,
    JSON.stringify(correctedRetry),
  );
  const consumedAfterSuccess = await scoped.client.settle(
    withAuthorization(F.PAYER, otherNonce),
    F.PAYMENT_REQUIREMENTS,
  );
  check(
    'only the successful settlement consumed it: the pair now refuses as a duplicate',
    consumedAfterSuccess.success === false &&
      consumedAfterSuccess.errorReason === DUPLICATE_SETTLEMENT_REASON,
    JSON.stringify(consumedAfterSuccess),
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
// Evidence, continued: strict EIP-1474 shapes and the JSON-RPC envelope.
//
// Completes EVM-EVIDENCE-001 on the observation's input side. A false "the expected transfer is
// absent" can be produced not only by misreading logs but by admitting a response that should
// have been refused: a truncated log list, a silently dropped malformed entry, or a balance word
// read under the wrong RPC type. These vectors hold every admission to the type the RPC method
// actually returns and prove that an inadmissible response withholds the verdict rather than
// shading it.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- evidence: strict RPC admission --');

// EIP-1474 Quantity versus ABI Data, decided by the actual type of each value.
{
  check(
    'canonical quantities are admitted: 0x0, 0x1, 0x400',
    admitRpcQuantity('0x0') === 0n && admitRpcQuantity('0x1') === 1n && admitRpcQuantity('0x400') === 1024n,
  );
  check(
    'leading-zero quantities are refused: 0x00, 0x01, 0x0400',
    admitRpcQuantity('0x00') === undefined &&
      admitRpcQuantity('0x01') === undefined &&
      admitRpcQuantity('0x0400') === undefined,
  );
  check(
    'non-string and empty quantities are refused',
    admitRpcQuantity(1) === undefined && admitRpcQuantity('0x') === undefined && admitRpcQuantity(undefined) === undefined,
  );
  const paddedWord = `0x${'0'.repeat(58)}0f4240`;
  check(
    'a zero-padded 32-byte balanceOf word is admitted as ABI data — it is not a Quantity',
    admitAbiUint256Word(paddedWord) === 1_000_000n,
  );
  check(
    'short or malformed balanceOf results are refused, including quantity-shaped ones',
    admitAbiUint256Word('0x1') === undefined &&
      admitAbiUint256Word('0x') === undefined &&
      admitAbiUint256Word(`0x${'0'.repeat(63)}`) === undefined &&
      admitAbiUint256Word(`0x${'0'.repeat(65)}`) === undefined,
  );
}

// Receipt, transaction and block admissions: one malformed member refuses the whole response.
{
  const blockHash = '0x'.padEnd(66, 'b');
  const goodLog = {
    address: F.ASSET_CONTRACT,
    topics: [TRANSFER_EVENT_TOPIC],
    data: `0x${'0'.repeat(64)}`,
  };
  const receiptWith = (overrides: Record<string, unknown>): unknown => ({
    status: '0x1',
    blockNumber: '0x384',
    blockHash,
    logs: [goodLog],
    ...overrides,
  });
  const refuses = (value: unknown, admit: (v: unknown) => unknown): boolean => {
    try {
      admit(value);
      return false;
    } catch (e) {
      return e instanceof JsonRpcFailure && e.kind === 'unusable';
    }
  };

  check(
    'a well-formed receipt is admitted with its placement and logs intact',
    (() => {
      const admitted = admitReceiptResult(receiptWith({}));
      return admitted.status === 'success' && admitted.blockNumber === 900n && admitted.logs.length === 1;
    })(),
  );
  check(
    'a receipt with a leading-zero block number is refused, never normalized',
    refuses(receiptWith({ blockNumber: '0x0384' }), admitReceiptResult),
  );
  check(
    'a receipt with a malformed block hash is refused',
    refuses(receiptWith({ blockHash: '0xshort' }), admitReceiptResult),
  );
  check(
    'a receipt whose logs member is missing or not an array is refused',
    refuses(receiptWith({ logs: undefined }), admitReceiptResult) &&
      refuses(receiptWith({ logs: 'none' }), admitReceiptResult),
  );
  check(
    'a receipt reporting more logs than the bound is refused whole, never truncated',
    refuses(receiptWith({ logs: Array.from({ length: MAX_RECEIPT_LOGS + 1 }, () => goodLog) }), admitReceiptResult),
  );
  check(
    'one malformed log refuses the receipt: entries are never silently dropped',
    refuses(receiptWith({ logs: [goodLog, { ...goodLog, address: 'not-an-address' }] }), admitReceiptResult) &&
      refuses(receiptWith({ logs: [goodLog, { ...goodLog, topics: ['0x1234'] }] }), admitReceiptResult) &&
      refuses(receiptWith({ logs: [goodLog, { ...goodLog, data: '0xabc' }] }), admitReceiptResult),
  );

  // Log placement fields, measured against the live Base Sepolia response shape (2026-08-27):
  // logs there carry `removed`, `transactionHash`, `blockHash` and `blockNumber`. They are
  // checked when present, never required, and each present field must agree with the receipt
  // this claim rests on. A removed log can never satisfy the expected transfer: the receipt
  // carrying one is refused whole rather than read around.
  const otherHash = '0x'.padEnd(66, 'c');
  const placedLog = {
    ...goodLog,
    removed: false,
    transactionHash: F.SETTLEMENT_TX_HASH,
    blockHash,
    blockNumber: '0x384',
  };
  check(
    'a log whose placement fields all agree with the receipt is admitted',
    admitReceiptResult(receiptWith({ logs: [placedLog] }), F.SETTLEMENT_TX_HASH).logs.length === 1,
  );
  check(
    'a log without placement fields is admitted: optional fields are never required',
    admitReceiptResult(receiptWith({}), F.SETTLEMENT_TX_HASH).logs.length === 1,
  );
  check(
    'a log marked removed refuses the receipt whole: it can never satisfy the expected transfer',
    refuses(receiptWith({ logs: [{ ...placedLog, removed: true }] }), (v) =>
      admitReceiptResult(v, F.SETTLEMENT_TX_HASH),
    ),
  );
  check(
    'a non-boolean removed member refuses the receipt',
    refuses(receiptWith({ logs: [{ ...placedLog, removed: 'no' }] }), (v) =>
      admitReceiptResult(v, F.SETTLEMENT_TX_HASH),
    ),
  );
  check(
    'a log naming a different transaction than the one queried refuses the receipt',
    refuses(receiptWith({ logs: [{ ...placedLog, transactionHash: otherHash }] }), (v) =>
      admitReceiptResult(v, F.SETTLEMENT_TX_HASH),
    ),
  );
  check(
    'a log naming a different block hash than the receipt refuses the receipt',
    refuses(receiptWith({ logs: [{ ...placedLog, blockHash: otherHash }] }), (v) =>
      admitReceiptResult(v, F.SETTLEMENT_TX_HASH),
    ),
  );
  check(
    'a log naming a different block number than the receipt refuses the receipt',
    refuses(receiptWith({ logs: [{ ...placedLog, blockNumber: '0x385' }] }), (v) =>
      admitReceiptResult(v, F.SETTLEMENT_TX_HASH),
    ),
  );
  check(
    'a transaction object with a malformed sender or placement is refused',
    refuses({ from: 'not-an-address', blockNumber: '0x384', blockHash }, admitTransactionResult) &&
      refuses({ from: F.PAYER, blockNumber: '0x0384', blockHash }, admitTransactionResult) &&
      refuses({ from: F.PAYER, blockNumber: '0x384', blockHash: '0x12' }, admitTransactionResult),
  );
  check(
    'a block whose transaction list holds one malformed member is refused for any inclusion claim',
    refuses(
      { number: '0x384', hash: blockHash, transactions: [F.SETTLEMENT_TX_HASH, 'not-a-hash'] },
      admitSealedBlockResult,
    ) && refuses({ number: '0x384', hash: blockHash, transactions: 'none' }, admitSealedBlockResult),
  );
  check(
    'a well-formed block is admitted with its full transaction list',
    admitSealedBlockResult({ number: '0x384', hash: blockHash, transactions: [F.SETTLEMENT_TX_HASH] })
      .transactionHashes.length === 1,
  );
}

// The JSON-RPC envelope itself, against a real HTTP endpoint on the loopback interface. The stub
// is scripted per test; nothing here reaches beyond the process's own listener.
interface RpcStubBehavior {
  status?: number;
  rawBody?: string;
  envelope?: (id: unknown, method: string) => unknown;
}
{
  const requests: string[] = [];
  let behavior: RpcStubBehavior = {};
  const stub: Server = createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => (raw += chunk.toString('utf8')));
    req.on('end', () => {
      const parsed = JSON.parse(raw) as { id: unknown; method: string };
      requests.push(parsed.method);
      res.statusCode = behavior.status ?? 200;
      res.setHeader('content-type', 'application/json');
      res.end(
        behavior.rawBody ??
          JSON.stringify(
            behavior.envelope?.(parsed.id, parsed.method) ?? {
              jsonrpc: '2.0',
              id: parsed.id,
              result: null,
            },
          ),
      );
    });
  });
  await new Promise<void>((resolve) => stub.listen(0, '127.0.0.1', resolve));
  const { port } = stub.address() as AddressInfo;
  const stubUrl = `http://127.0.0.1:${port}`;

  const caughtFailure = async (): Promise<JsonRpcFailure | 'no-failure' | 'unclassified'> => {
    try {
      await jsonRpcRequest(stubUrl, 'eth_chainId', [], 2000);
      return 'no-failure';
    } catch (e) {
      return e instanceof JsonRpcFailure ? e : 'unclassified';
    }
  };
  const failureKind = async (): Promise<string> => {
    const failure = await caughtFailure();
    return typeof failure === 'string' ? failure : failure.kind;
  };

  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, result: '0x14a34' }) };
  check(
    'a well-formed envelope returns its result',
    (await jsonRpcRequest(stubUrl, 'eth_chainId', [], 2000)) === '0x14a34',
  );
  behavior = {};
  check(
    'a null result is returned as null: the not-found fact belongs to the caller',
    (await jsonRpcRequest(stubUrl, 'eth_getTransactionReceipt', [F.SETTLEMENT_TX_HASH], 2000)) === null,
  );

  // Retryable-versus-terminal classification of HTTP statuses, fail-closed: exactly 429 and 503
  // are the admitted temporary set, with only the safe status code retained; every other
  // non-success status is terminal, because this example does not guess which server errors are
  // transient.
  behavior = { status: 500 };
  check('an HTTP 500 is terminal: structurally unusable, never retried', (await failureKind()) === 'unusable');
  behavior = { status: 404 };
  check('an HTTP 404 is terminal: structurally unusable, never retried', (await failureKind()) === 'unusable');
  behavior = { status: 429 };
  {
    const failure = await caughtFailure();
    check(
      'an HTTP 429 is the admitted temporary condition: retryable, safe status code retained',
      typeof failure !== 'string' &&
        failure.kind === 'temporarily_unavailable' &&
        failure.retryable === true &&
        failure.httpStatus === 429,
      JSON.stringify(failure),
    );
  }
  behavior = { status: 503 };
  {
    const failure = await caughtFailure();
    check(
      'an HTTP 503 is the admitted temporary condition: retryable, safe status code retained',
      typeof failure !== 'string' &&
        failure.kind === 'temporarily_unavailable' &&
        failure.retryable === true &&
        failure.httpStatus === 503,
      JSON.stringify(failure),
    );
  }

  behavior = { rawBody: 'not json at all' };
  check('a non-JSON body is structurally unusable', (await failureKind()) === 'unusable');
  behavior = { rawBody: '[]' };
  check('an array body is structurally unusable', (await failureKind()) === 'unusable');

  // The JSON-RPC 2.0 error member is admitted before it is believed: an error object must be a
  // non-null non-array object with an integer `code` and a string `message`; optional `data` is
  // ignored. A malformed error member is a structurally unusable response, never an rpc_error.
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: { code: -32000, message: 'server text' } }) };
  {
    const failure = await caughtFailure();
    check(
      'a well-formed error member is an RPC error: terminal, integer code retained, no text kept',
      typeof failure !== 'string' &&
        failure.kind === 'rpc_error' &&
        failure.retryable === false &&
        failure.rpcErrorCode === -32000 &&
        !failure.message.includes('server text'),
      JSON.stringify(failure),
    );
  }
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: { code: -32005, message: 'limit', data: { retryAfter: 5 } } }) };
  {
    const failure = await caughtFailure();
    check(
      'an error member with optional data is still a well-formed RPC error; the data is ignored',
      typeof failure !== 'string' && failure.kind === 'rpc_error' && failure.rpcErrorCode === -32005,
      JSON.stringify(failure),
    );
  }
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: null }) };
  check('a null error member is structurally unusable, not an RPC error', (await failureKind()) === 'unusable');
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: ['boom'] }) };
  check('an array error member is structurally unusable, not an RPC error', (await failureKind()) === 'unusable');
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: 'boom' }) };
  check('a string error member is structurally unusable, not an RPC error', (await failureKind()) === 'unusable');
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: { code: 'x', message: 'm' } }) };
  check('a non-integer error code is structurally unusable, not an RPC error', (await failureKind()) === 'unusable');
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: { code: 1.5, message: 'm' } }) };
  check('a fractional error code is structurally unusable, not an RPC error', (await failureKind()) === 'unusable');
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: { code: -32000 } }) };
  check('an error member missing its message is structurally unusable', (await failureKind()) === 'unusable');

  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, result: '0x1', error: { code: -32000, message: 'm' } }) };
  check(
    'result and error together are an ambiguity and fail closed as unusable',
    (await failureKind()) === 'unusable',
  );
  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id }) };
  check('neither result nor error fails closed as unusable', (await failureKind()) === 'unusable');
  behavior = { envelope: (id) => ({ jsonrpc: '1.0', id, result: '0x1' }) };
  check('a wrong jsonrpc member fails closed as unusable', (await failureKind()) === 'unusable');
  behavior = { envelope: () => ({ jsonrpc: '2.0', id: 999, result: '0x1' }) };
  check('a response repeating the wrong id fails closed as unusable', (await failureKind()) === 'unusable');

  // The response byte budget, exercised at its exact boundary through the real reader: a body at
  // the budget is admitted, one byte over is refused whole as unusable — never truncated into a
  // shorter response that might then parse.
  {
    const prefix = '{"jsonrpc":"2.0","id":1,"result":"0x14a34","pad":"';
    const suffix = '"}';
    const padTo = (total: number): string =>
      `${prefix}${'a'.repeat(total - prefix.length - suffix.length)}${suffix}`;
    behavior = { rawBody: padTo(MAX_RPC_RESPONSE_BYTES) };
    check(
      'a response body exactly at the byte budget is admitted',
      (await jsonRpcRequest(stubUrl, 'eth_chainId', [], 10_000)) === '0x14a34',
    );
    behavior = { rawBody: padTo(MAX_RPC_RESPONSE_BYTES + 1) };
    check(
      'a response body one byte over the budget is refused whole as unusable',
      (await failureKind()) === 'unusable',
    );
  }

  // The preflight balance read, end to end through the same envelope: a 32-byte zero-padded word
  // is a balance, and a quantity-shaped short value — the exact confusion this fixes — is not.
  const balanceWord = `0x${'0'.repeat(58)}0f4240`;
  behavior = {
    envelope: (id, method) => ({
      jsonrpc: '2.0',
      id,
      result: method === 'eth_chainId' ? '0x14a34' : balanceWord,
    }),
  };
  {
    const chainChecks = await checkChainState(F.PAYER, F.ASSET_CONTRACT, jsonRpcChainState(stubUrl, 2000));
    check(
      'the preflight admits a zero-padded balanceOf word and reads the balance from it',
      chainChecks.every((c) => c.status === 'ok') &&
        chainChecks.some((c) => c.detail === '1000000 base units'),
      JSON.stringify(chainChecks),
    );
  }
  behavior = {
    envelope: (id, method) => ({
      jsonrpc: '2.0',
      id,
      result: method === 'eth_chainId' ? '0x14a34' : '0x1',
    }),
  };
  {
    const chainChecks = await checkChainState(F.PAYER, F.ASSET_CONTRACT, jsonRpcChainState(stubUrl, 2000));
    check(
      'a quantity-shaped balanceOf result is refused as structurally unusable, not read as a balance',
      chainChecks.some(
        (c) => c.name === 'payer holds test USDC' && c.status === 'failed' && c.detail === ENDPOINT_RESPONSE_UNUSABLE,
      ),
      JSON.stringify(chainChecks),
    );
  }

  // The sealed observation through the RPC-backed source, exercising the classification a live
  // run would record. Placement facts here are synthetic; what is under test is this
  // repository's own admission and classification behavior.
  const sealedBlockHash = '0x'.padEnd(66, 'b');
  const wiredReceipt = (logs: unknown[]): unknown => ({
    status: '0x1',
    blockNumber: '0x384',
    blockHash: sealedBlockHash,
    logs,
  });
  const wiredTransaction = { from: F.PAYER, blockNumber: '0x384', blockHash: sealedBlockHash };
  const wiredBlock = (transactions: unknown[]): unknown => ({
    number: '0x384',
    hash: sealedBlockHash,
    transactions,
  });
  const expectedTransfer = {
    token_contract: F.ASSET_CONTRACT,
    transfer_from: F.PAYER,
    transfer_to: F.PAY_TO,
    transfer_amount: F.AMOUNT_BASE_UNITS,
  };
  const observeThroughStub = async (): ReturnType<typeof observeSealedTransaction> =>
    observeSealedTransaction({
      source: baseSealedRpcSource(stubUrl, 2000),
      transactionHash: F.SETTLEMENT_TX_HASH,
      expectedTransfer,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
  const routed = (bodies: Record<string, (id: unknown) => unknown>): void => {
    behavior = {
      envelope: (id, method) => {
        const route = bodies[method];
        return route === undefined ? { jsonrpc: '2.0', id, result: null } : route(id);
      },
    };
  };

  routed({
    eth_getTransactionReceipt: (id) => ({
      jsonrpc: '2.0',
      id,
      result: wiredReceipt(Array.from({ length: MAX_RECEIPT_LOGS + 1 }, () => ({
        address: F.ASSET_CONTRACT,
        topics: [TRANSFER_EVENT_TOPIC],
        data: `0x${'0'.repeat(64)}`,
      }))),
    }),
  });
  {
    const overBound = await observeThroughStub();
    const comparison = compareExpectationToObservation({
      payment_expectation: {
        source: 'native_x402_artifact',
        network: F.NETWORK,
        asset: F.ASSET_CONTRACT,
        amount_base_units: F.AMOUNT_BASE_UNITS,
        asset_decimals: F.TOKEN_DECIMALS,
        recipient: F.PAY_TO,
        payer: F.PAYER,
      },
      chain_observation: {
        source: { kind: 'facilitator', reference: 'synthetic' },
        settlement_outcome: 'succeeded',
        transaction_hash: F.SETTLEMENT_TX_HASH,
        observed_at_unix_seconds: F.FIXED_NOW_UNIX_SECONDS,
      },
      rpc_observation: overBound,
    });
    check(
      'a receipt over the log bound leaves the observation unavailable, never "transfer absent"',
      overBound.observation_state === 'unavailable' &&
        overBound.unavailable_reason === ENDPOINT_RESPONSE_UNUSABLE &&
        comparison.transfer_event === 'not_evaluated',
      JSON.stringify(overBound),
    );
  }

  routed({
    eth_getTransactionReceipt: (id) => ({
      jsonrpc: '2.0',
      id,
      result: wiredReceipt([{ address: F.ASSET_CONTRACT, topics: ['0xdeadbeef'], data: '0x' }]),
    }),
  });
  {
    const malformedLog = await observeThroughStub();
    check(
      'a receipt holding one malformed log leaves the observation unavailable, never a verdict',
      malformedLog.observation_state === 'unavailable' &&
        malformedLog.unavailable_reason === ENDPOINT_RESPONSE_UNUSABLE,
      JSON.stringify(malformedLog),
    );
  }

  behavior = { envelope: (id) => ({ jsonrpc: '2.0', id, error: { code: -32005, message: 'limit' } }) };
  {
    const rpcError = await observeThroughStub();
    check(
      'an endpoint RPC error is recorded under its own fixed reason, with no server text retained',
      rpcError.observation_state === 'unavailable' &&
        rpcError.unavailable_reason === ENDPOINT_RPC_ERROR &&
        !JSON.stringify(rpcError).includes('limit'),
      JSON.stringify(rpcError),
    );
  }

  routed({
    eth_getTransactionReceipt: (id) => ({ jsonrpc: '2.0', id, result: wiredReceipt([]) }),
    eth_getTransactionByHash: (id) => ({ jsonrpc: '2.0', id, result: wiredTransaction }),
    eth_blockNumber: (id) => ({ jsonrpc: '2.0', id, result: '0x3e8' }),
    eth_getBlockByNumber: (id) => ({
      jsonrpc: '2.0',
      id,
      result: wiredBlock([F.SETTLEMENT_TX_HASH, 'not-a-transaction-hash']),
    }),
  });
  {
    const malformedList = await observeThroughStub();
    check(
      'a sealed block with one malformed transaction-list member yields no inclusion claim',
      malformedList.observation_state === 'found' &&
        malformedList.observation_level === undefined &&
        malformedList.receipt_status === 'success',
      JSON.stringify(malformedList),
    );
  }

  routed({
    eth_getTransactionReceipt: (id) => ({ jsonrpc: '2.0', id, result: wiredReceipt([]) }),
    eth_getTransactionByHash: (id) => ({ jsonrpc: '2.0', id, result: wiredTransaction }),
    eth_blockNumber: (id) => ({ jsonrpc: '2.0', id, result: '0x3e8' }),
    eth_getBlockByNumber: (id) => ({ jsonrpc: '2.0', id, result: wiredBlock([F.SETTLEMENT_TX_HASH]) }),
  });
  {
    const completeNoTransfer = await observeThroughStub();
    check(
      'a complete admitted receipt without the expected transfer is a recorded mismatch',
      completeNoTransfer.observation_state === 'found' &&
        completeNoTransfer.observation_level === 'l2_block_inclusion' &&
        completeNoTransfer.token_transfer === undefined,
      JSON.stringify(completeNoTransfer),
    );
  }

  const pad64 = (address: string): string => `0x${'0'.repeat(24)}${address.slice(2)}`;
  routed({
    eth_getTransactionReceipt: (id) => ({
      jsonrpc: '2.0',
      id,
      result: wiredReceipt([
        {
          address: F.ASSET_CONTRACT,
          topics: [TRANSFER_EVENT_TOPIC, pad64(F.PAYER), pad64(F.PAY_TO)],
          data: `0x${BigInt(F.AMOUNT_BASE_UNITS).toString(16).padStart(64, '0')}`,
        },
      ]),
    }),
    eth_getTransactionByHash: (id) => ({ jsonrpc: '2.0', id, result: wiredTransaction }),
    eth_blockNumber: (id) => ({ jsonrpc: '2.0', id, result: '0x3e8' }),
    eth_getBlockByNumber: (id) => ({ jsonrpc: '2.0', id, result: wiredBlock([F.SETTLEMENT_TX_HASH]) }),
  });
  {
    const withTransfer = await observeThroughStub();
    check(
      'a complete admitted receipt with the expected transfer records the transfer and inclusion',
      withTransfer.observation_state === 'found' &&
        withTransfer.observation_level === 'l2_block_inclusion' &&
        withTransfer.token_transfer?.transfer_amount === F.AMOUNT_BASE_UNITS,
      JSON.stringify(withTransfer),
    );
  }

  // The facilitator's transaction reference is validated before any endpoint is queried: a
  // malformed reference produces its own fixed reason and zero HTTP requests.
  requests.length = 0;
  {
    const malformedReference = await observeSealedTransaction({
      source: baseSealedRpcSource(stubUrl, 2000),
      transactionHash: '0xnot-a-hash',
      expectedTransfer,
      observedAtUnixSeconds: F.FIXED_NOW_UNIX_SECONDS,
    });
    check(
      'a malformed transaction reference is refused before any RPC query is made',
      malformedReference.observation_state === 'unavailable' &&
        malformedReference.unavailable_reason === MALFORMED_TRANSACTION_REFERENCE &&
        requests.length === 0,
      `${JSON.stringify(malformedReference)}; requests ${requests.length}`,
    );
  }

  await new Promise<void>((resolve) => stub.close(() => resolve()));
}

// ---------------------------------------------------------------------------------------------
// The live observation loop, exercised deterministically with an injected clock and sleep. The
// loop's contract: retry only transient states within the deadline; stop immediately on a
// definitive admitted result; report honestly on expiry; never poll indefinitely.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- live observation loop (injected clock; no waiting, no sockets) --');

{
  const expectedTransfer = {
    token_contract: F.ASSET_CONTRACT,
    transfer_from: F.PAYER,
    transfer_to: F.PAY_TO,
    transfer_amount: F.AMOUNT_BASE_UNITS,
  };
  const base = {
    source: { kind: 'rpc' as const, reference: 'synthetic loop source' },
    transaction_hash: F.SETTLEMENT_TX_HASH,
    observed_at_unix_seconds: F.FIXED_NOW_UNIX_SECONDS,
    statement: 'synthetic observation for the loop vectors',
  };
  const notFound: SealedRpcObservationV1 = { ...base, observation_state: 'not_found' };
  const unavailableWith = (reason: string): SealedRpcObservationV1 => ({
    ...base,
    observation_state: 'unavailable',
    unavailable_reason: reason,
  });
  const unavailable = unavailableWith(ENDPOINT_UNREACHABLE);
  const foundNoInclusion: SealedRpcObservationV1 = {
    ...base,
    observation_state: 'found',
    receipt_status: 'success',
  };
  const reverted: SealedRpcObservationV1 = {
    ...base,
    observation_state: 'found',
    receipt_status: 'reverted',
  };
  const matchingTransfer = {
    token_contract: F.ASSET_CONTRACT,
    transfer_from: F.PAYER,
    transfer_to: F.PAY_TO,
    transfer_amount: F.AMOUNT_BASE_UNITS,
  };
  const included = (transfer: typeof matchingTransfer | undefined): SealedRpcObservationV1 => ({
    ...base,
    observation_state: 'found',
    observation_level: 'l2_block_inclusion',
    receipt_status: 'success',
    ...(transfer !== undefined ? { token_transfer: transfer } : {}),
  });

  const runLoop = async (
    sequence: readonly SealedRpcObservationV1[],
  ): Promise<{ result: LiveObservationResult; polls: number; slept: number[] }> => {
    let clock = 0;
    let polls = 0;
    const slept: number[] = [];
    const result = await observeUntilSealed({
      observe: async () => {
        const next = sequence[Math.min(polls, sequence.length - 1)];
        polls += 1;
        if (next === undefined) throw new Error('empty observation sequence');
        return next;
      },
      nowMs: () => clock,
      sleep: async (ms) => {
        slept.push(ms);
        clock += ms;
      },
      expectedTransfer,
      pollMs: 2000,
      deadlineMs: 10_000,
    });
    return { result, polls, slept };
  };

  const success = await runLoop([notFound, unavailable, foundNoInclusion, included(matchingTransfer)]);
  check(
    'transient states are retried and a fully matching sealed inclusion stops the loop as matched',
    success.result.outcome === 'matched' && success.polls === 4,
    `${success.result.outcome} after ${success.polls} polls`,
  );
  const revertedRun = await runLoop([notFound, reverted]);
  check(
    'a reverted execution stops the loop immediately as a definitive failure',
    revertedRun.result.outcome === 'reverted' && revertedRun.polls === 2,
    `${revertedRun.result.outcome} after ${revertedRun.polls} polls`,
  );
  const wrongTransfer = await runLoop([included({ ...matchingTransfer, transfer_amount: '1' })]);
  check(
    'an admitted sealed receipt with a definitively wrong transfer stops the loop as wrong_transfer',
    wrongTransfer.result.outcome === 'wrong_transfer' && wrongTransfer.polls === 1,
    `${wrongTransfer.result.outcome} after ${wrongTransfer.polls} polls`,
  );
  const absentTransfer = await runLoop([included(undefined)]);
  check(
    'an admitted sealed receipt without the expected transfer is wrong_transfer, never a pass',
    absentTransfer.result.outcome === 'wrong_transfer',
    absentTransfer.result.outcome,
  );
  const expiry = await runLoop([notFound]);
  check(
    'the deadline bounds the loop: an unestablished observation ends as not_established, not a wait',
    expiry.result.outcome === 'not_established' &&
      expiry.slept.every((ms) => ms === 2000) &&
      expiry.slept.reduce((a, b) => a + b, 0) <= 10_000,
    `${expiry.result.outcome} after ${expiry.polls} polls, slept ${expiry.slept.reduce((a, b) => a + b, 0)}ms`,
  );

  // Terminal-versus-retryable classification of unavailable observations, fail-closed. The
  // retryable set is exactly the transport failure and the admitted temporary condition; an RPC
  // error, a structurally unusable response, a malformed reference and any unrecognized reason
  // stop the loop immediately with the observation preserved.
  const temporarilyUnavailable = await runLoop([
    unavailableWith(ENDPOINT_TEMPORARILY_UNAVAILABLE),
    included(matchingTransfer),
  ]);
  check(
    'the admitted temporary endpoint condition is retried like a transport failure',
    temporarilyUnavailable.result.outcome === 'matched' && temporarilyUnavailable.polls === 2,
    `${temporarilyUnavailable.result.outcome} after ${temporarilyUnavailable.polls} polls`,
  );
  const rpcErrorStop = await runLoop([unavailableWith(ENDPOINT_RPC_ERROR), included(matchingTransfer)]);
  check(
    'an RPC error is terminal: the loop stops immediately as not_established, never retries into it',
    rpcErrorStop.result.outcome === 'not_established' &&
      rpcErrorStop.polls === 1 &&
      rpcErrorStop.result.observation?.unavailable_reason === ENDPOINT_RPC_ERROR,
    `${rpcErrorStop.result.outcome} after ${rpcErrorStop.polls} polls`,
  );
  const unusableStop = await runLoop([
    unavailableWith(ENDPOINT_RESPONSE_UNUSABLE),
    included(matchingTransfer),
  ]);
  check(
    'a structurally unusable response is terminal: asking again cannot make it well-formed',
    unusableStop.result.outcome === 'not_established' && unusableStop.polls === 1,
    `${unusableStop.result.outcome} after ${unusableStop.polls} polls`,
  );
  const malformedStop = await runLoop([
    unavailableWith(MALFORMED_TRANSACTION_REFERENCE),
    included(matchingTransfer),
  ]);
  check(
    'a malformed transaction reference is terminal: no endpoint was queried and none will be',
    malformedStop.result.outcome === 'not_established' && malformedStop.polls === 1,
    `${malformedStop.result.outcome} after ${malformedStop.polls} polls`,
  );
  const unknownReasonStop = await runLoop([
    unavailableWith('a reason this code has never declared'),
    included(matchingTransfer),
  ]);
  check(
    'an unrecognized unavailable reason is terminal: fail closed, never retried on unfamiliarity',
    unknownReasonStop.result.outcome === 'not_established' && unknownReasonStop.polls === 1,
    `${unknownReasonStop.result.outcome} after ${unknownReasonStop.polls} polls`,
  );
}

// ---------------------------------------------------------------------------------------------
// Live-run durability: once a payment can begin, every failing path preserves the material that
// safely exists and never attempts a second payment. Exercised through the real orchestrator
// with injected phases; the payment exchange, where one is needed, is the genuine offline
// fixture run, so preserved material is real material.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- live-run durability across the payment boundary --');

{
  const matchedObservation: LiveObservationResult = {
    outcome: 'matched',
    observation: {
      source: { kind: 'rpc', reference: 'synthetic durability source' },
      transaction_hash: F.SETTLEMENT_TX_HASH,
      observation_state: 'found',
      observation_level: 'l2_block_inclusion',
      receipt_status: 'success',
      observed_at_unix_seconds: F.FIXED_NOW_UNIX_SECONDS,
      statement: 'synthetic observation for the durability vectors',
    },
  };
  const readJson = (directory: string, file: string): Record<string, unknown> =>
    JSON.parse(readFileSync(join(directory, file), 'utf8')) as Record<string, unknown>;
  const noLeaks = (directory: string, file: string): boolean => {
    const text = readFileSync(join(directory, file), 'utf8');
    return (
      !text.includes('privateKeyHex') &&
      !text.includes(tmpdir()) &&
      !text.includes(process.cwd()) &&
      !text.includes('/Users/')
    );
  };

  interface InjectionVector {
    readonly label: string;
    readonly expectStage: string;
    readonly phases: (counters: { payment: number }) => LiveRunPhases;
    readonly expectRunPreserved: boolean;
    readonly expectObservationPreserved: boolean;
  }
  const boom = async (): Promise<never> => {
    throw new Error('synthetic injected failure');
  };
  const vectors: InjectionVector[] = [
    {
      // Payload creation fails before anything could settle: nothing to preserve beyond the
      // attempt record, and above all no fabricated run facts and no fabricated observation.
      label: 'a failure during payload creation, before settlement',
      expectStage: 'payment_exchange',
      phases: (c) => ({
        payment: async () => {
          c.payment += 1;
          return boom();
        },
        observe: async () => matchedObservation,
        assemble: async () => {
          throw new Error('unreachable');
        },
        finalize: async () => undefined,
      }),
      expectRunPreserved: false,
      expectObservationPreserved: false,
    },
    {
      // The exchange completed — settlement was observed, the origin response captured — and the
      // run fails immediately after: the exchange facts and wire artifacts must survive.
      label: 'a failure immediately after the settlement was observed',
      expectStage: 'rpc_observation',
      phases: (c) => ({
        payment: async () => {
          c.payment += 1;
          return honestRun;
        },
        observe: boom,
        assemble: async () => {
          throw new Error('unreachable');
        },
        finalize: async () => undefined,
      }),
      expectRunPreserved: true,
      expectObservationPreserved: false,
    },
    {
      // The RPC observation was made and evidence assembly fails: the observation actually made
      // is preserved exactly, never one fabricated for a phase that did not run.
      label: 'a failure during evidence assembly, after the RPC observation',
      expectStage: 'evidence_assembly',
      phases: (c) => ({
        payment: async () => {
          c.payment += 1;
          return honestRun;
        },
        observe: async () => matchedObservation,
        assemble: boom,
        finalize: async () => undefined,
      }),
      expectRunPreserved: true,
      expectObservationPreserved: true,
    },
    {
      // Finalization or offline verification fails: everything held at that point survives.
      label: 'a failure during finalization and offline verification',
      expectStage: 'evidence_finalization',
      phases: (c) => ({
        payment: async () => {
          c.payment += 1;
          return honestRun;
        },
        observe: async () => matchedObservation,
        assemble: async () => honestLayout,
        finalize: boom,
      }),
      expectRunPreserved: true,
      expectObservationPreserved: true,
    },
  ];

  for (const vector of vectors) {
    const attemptDirectory = mkdtempSync(join(tmpdir(), 'peac-live-attempt-'));
    temporaryDirectories.push(attemptDirectory);
    const counters = { payment: 0 };
    beginLiveAttempt({
      attemptDirectory,
      runId: 'injection-vector',
      metadata: { network: F.NETWORK, payer_address: F.PAYER },
    });
    const before = readJson(attemptDirectory, 'attempt.json');
    let failure: LiveRunFailure | undefined;
    try {
      await executeLiveRun({
        phases: vector.phases(counters),
        attemptDirectory,
        runId: 'injection-vector',
      });
    } catch (e) {
      if (e instanceof LiveRunFailure) failure = e;
      else throw e;
    }
    const attempt = readJson(attemptDirectory, 'attempt.json');
    const material = readJson(attemptDirectory, 'run-material.json');
    const exchange = material['payment_exchange'] as Record<string, unknown> | null;
    check(
      `${vector.label}: fails as LiveRunFailure at the expected stage with the attempt recorded`,
      failure !== undefined &&
        failure.stage === vector.expectStage &&
        before['state'] === 'payment_attempt_begun' &&
        attempt['state'] === 'failed' &&
        attempt['failed_stage'] === vector.expectStage,
      `stage ${String(failure?.stage)}, attempt ${JSON.stringify(attempt)}`,
    );
    check(
      `${vector.label}: the payment phase ran exactly once and was never retried`,
      counters.payment === 1,
      `payment calls ${counters.payment}`,
    );
    check(
      `${vector.label}: the material that safely existed is preserved, and nothing is fabricated`,
      (vector.expectRunPreserved
        ? exchange !== null &&
          exchange['terminal_state'] === 'response_write_attempted' &&
          typeof (exchange['observed_fields'] as Record<string, unknown>)['payment-required'] ===
            'string'
        : exchange === null) &&
        (vector.expectObservationPreserved
          ? material['rpc_observation_outcome'] === 'matched' &&
            (material['rpc_observation'] as Record<string, unknown>)['transaction_hash'] ===
              F.SETTLEMENT_TX_HASH
          : material['rpc_observation'] === null),
      JSON.stringify(material).slice(0, 400),
    );
    check(
      `${vector.label}: the preserved files carry no key material and no absolute paths`,
      noLeaks(attemptDirectory, 'attempt.json') && noLeaks(attemptDirectory, 'run-material.json'),
    );
    check(
      `${vector.label}: the failure message is bounded and names no underlying error text`,
      failure !== undefined && !failure.message.includes('synthetic injected failure'),
      String(failure?.message),
    );
  }

  // The completing path: all phases succeed, the attempt record closes as completed, and no
  // run-material file is written because nothing failed.
  {
    const attemptDirectory = mkdtempSync(join(tmpdir(), 'peac-live-attempt-'));
    temporaryDirectories.push(attemptDirectory);
    const counters = { payment: 0 };
    beginLiveAttempt({
      attemptDirectory,
      runId: 'completion-vector',
      metadata: { network: F.NETWORK },
    });
    const outcome = await executeLiveRun({
      phases: {
        payment: async () => {
          counters.payment += 1;
          return honestRun;
        },
        observe: async () => matchedObservation,
        assemble: async () => honestLayout,
        finalize: async () => undefined,
      },
      attemptDirectory,
      runId: 'completion-vector',
    });
    const attempt = readJson(attemptDirectory, 'attempt.json');
    check(
      'a completing run closes its attempt record and preserves nothing as failure material',
      outcome.observed.outcome === 'matched' &&
        counters.payment === 1 &&
        attempt['state'] === 'completed' &&
        !existsSync(join(attemptDirectory, 'run-material.json')),
      JSON.stringify(attempt),
    );
  }
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

// The balance requirement is least-privilege: exactly the intended spend, derived from the same
// fixture constant the payment uses, with no undocumented buffer. Exercised at its boundary.
{
  check(
    'the required balance is exactly the intended spend, derived from the payment amount',
    MIN_USDC_BASE_UNITS === BigInt(F.AMOUNT_BASE_UNITS),
    `${MIN_USDC_BASE_UNITS} vs ${F.AMOUNT_BASE_UNITS}`,
  );
  const balanceRpc = (word: bigint): Parameters<typeof checkChainState>[2] => ({
    chainId: async () => 84532n,
    erc20Balance: async () => word,
  });
  const exact = await checkChainState(F.PAYER, F.ASSET_CONTRACT, balanceRpc(MIN_USDC_BASE_UNITS));
  check(
    'a balance exactly at the intended spend passes the balance check',
    exact.some((c) => c.name === 'payer holds test USDC' && c.status === 'ok'),
    JSON.stringify(exact),
  );
  const short = await checkChainState(
    F.PAYER,
    F.ASSET_CONTRACT,
    balanceRpc(MIN_USDC_BASE_UNITS - 1n),
  );
  check(
    'a balance one base unit short fails the balance check',
    short.some((c) => c.name === 'payer holds test USDC' && c.status === 'failed'),
    JSON.stringify(short),
  );
}

// Endpoint admission for the two configurable endpoints: absolute URL, https for any
// non-loopback host, loopback http admitted for local fixtures, no embedded credentials, no
// other scheme — and the refused value itself is never echoed.
{
  const admits = (value: string): boolean => {
    try {
      return admitEndpointUrl('PEAC_EXAMPLE_RPC_URL', value) === value;
    } catch {
      return false;
    }
  };
  const refusalMessage = (value: string): string => {
    try {
      admitEndpointUrl('PEAC_EXAMPLE_RPC_URL', value);
      return '(admitted)';
    } catch (e) {
      return e instanceof EndpointConfigurationError ? e.message : '(unclassified)';
    }
  };
  check(
    'https endpoints and loopback http endpoints are admitted',
    admits('https://sepolia.base.org') &&
      admits('https://example.test/rpc') &&
      admits('http://127.0.0.1:8545') &&
      admits('http://localhost:8545'),
  );
  check(
    'non-loopback http, embedded credentials, other schemes and relative values are refused',
    !admits('http://rpc.example.test') &&
      !admits('https://user:secret@rpc.example.test') &&
      !admits('ftp://rpc.example.test') &&
      !admits('file:///etc/hosts') &&
      !admits('sepolia.base.org'),
  );
  const leaky = 'https://user:secret-credential@rpc.example.test/path?key=abc123';
  const message = refusalMessage(leaky);
  check(
    'a refusal names the variable and the rule, never the configured value',
    message.includes('PEAC_EXAMPLE_RPC_URL') &&
      !message.includes('secret-credential') &&
      !message.includes('rpc.example.test') &&
      !message.includes('abc123'),
    message,
  );
}

// The client-side selection guard: EIP-3009 scope admission at the moment the requirement is
// selected, BEFORE anything is signed, through the upstream onBeforePaymentCreation hook.
recordExecution('X402-VALID-005');
recordExecution('X402-REJECT-011');
{
  const clientWith = (extra?: Record<string, unknown>): { client: x402Client; paymentRequired: PaymentRequired } => {
    const client = new x402Client();
    client.setSpendControls({ allowedAssets: [{ network: F.NETWORK, asset: F.ASSET_CONTRACT }] });
    client.register(F.NETWORK, new FixtureExactWallet());
    client.registerExtension(paymentIdentifierClientExtension(F.PAYMENT_ID));
    client.onBeforePaymentCreation(eip3009SelectionGuard());
    const paymentRequired: PaymentRequired = structuredClone(F.PAYMENT_REQUIRED);
    if (extra !== undefined) {
      paymentRequired.accepts[0]!.extra = { ...paymentRequired.accepts[0]!.extra, ...extra };
    }
    return { client, paymentRequired };
  };
  const creates = async (extra?: Record<string, unknown>): Promise<PaymentPayload | undefined> => {
    const { client, paymentRequired } = clientWith(extra);
    try {
      return await client.createPaymentPayload(paymentRequired);
    } catch {
      return undefined;
    }
  };
  const absent = await creates();
  check(
    'an absent asset-transfer method is accepted: the pinned upstream routes it to eip3009',
    absent !== undefined,
  );
  check(
    'the payment identifier is injected through the upstream extension seam, gated on the declaration',
    absent !== undefined &&
      (absent.extensions as Record<string, { info?: { id?: string } }>)['payment-identifier']
        ?.info?.id === F.PAYMENT_ID,
    JSON.stringify(absent?.extensions ?? null),
  );
  check(
    'an explicit eip3009 selection is accepted',
    (await creates({ assetTransferMethod: 'eip3009' })) !== undefined,
  );
  check(
    'a permit2 selection is refused before the payer signs anything',
    (await creates({ assetTransferMethod: 'permit2' })) === undefined,
  );
  check(
    'an unknown asset-transfer method is refused rather than falling through to eip3009 signing',
    (await creates({ assetTransferMethod: 'erc7710' })) === undefined,
  );
}

// Filesystem failures must never leak local directory layout into rendered output. Each vector
// below triggers a REAL filesystem error deterministically (a path through a plain file, a
// directory where a file is expected) and asserts the rendered diagnostic carries the bounded
// errno name and no absolute path.
{
  const scratch = mkdtempSync(join(tmpdir(), 'peac-fs-errors-'));
  temporaryDirectories.push(scratch);

  const plainFile = join(scratch, 'occupied');
  writeFileSync(plainFile, 'not a directory\n');
  const writable = reviewerMaterialWritableCheck(join(plainFile, 'out'));
  check(
    'an unwritable evidence output directory reports the errno name and no absolute path',
    writable.status === 'failed' &&
      writable.name === 'evidence output directory is writable before any payment' &&
      writable.detail.includes('ENOTDIR') &&
      !writable.detail.includes(scratch) &&
      !writable.detail.includes(tmpdir()),
    writable.detail,
  );

  const directoryAsKey = join(scratch, 'key-directory');
  mkdirSync(directoryAsKey);
  let keyError = '';
  try {
    loadPayerAccount(directoryAsKey);
  } catch (e) {
    keyError = e instanceof InvalidKeyFileError ? e.message : `unexpected ${String(e)}`;
  }
  check(
    'an unreadable payer key file reports the errno name, a fixed path label, and no absolute path',
    keyError.includes('EISDIR') &&
      keyError.includes('the configured key path') &&
      !keyError.includes(scratch) &&
      !keyError.includes(tmpdir()),
    keyError,
  );
}

// Issuer readiness for a live run: explicitly configured, usable, and consistent with any
// existing key binding — decided without creating or modifying key material, and failing closed
// when unset. The vectors pass explicit values, so nothing here reads or mutates the process
// environment beyond the one deletion-protected unset case below.
{
  const scratch = mkdtempSync(join(tmpdir(), 'peac-issuer-readiness-'));
  temporaryDirectories.push(scratch);
  const keyPath = join(scratch, 'issuer.json');

  const unset = checkIssuerReadiness(undefined, keyPath);
  check(
    'an unset issuer fails closed and the binding check is not evaluated',
    unset[0]?.status === 'failed' &&
      unset[0].detail.includes('PEAC_EXAMPLE_ISSUER') &&
      unset[1]?.status === 'not_evaluated',
    JSON.stringify(unset),
  );
  const unusable = checkIssuerReadiness('not-an-absolute-url', keyPath);
  check('an unusable issuer value fails closed', unusable[0]?.status === 'failed', JSON.stringify(unusable));
  const noKeyYet = checkIssuerReadiness('https://issuer.example.test', keyPath);
  check(
    'a usable issuer with no key file yet is ready, and no key file was created by checking',
    noKeyYet.every((c) => c.status === 'ok') && !existsSync(keyPath),
    JSON.stringify(noKeyYet),
  );

  const storedKeyBytes = `${JSON.stringify(
    {
      note: 'test vector',
      kid: 'readiness-vector-key-1',
      issuer: 'https://issuer.example.test',
      privateKeyHex: '11'.repeat(32),
    },
    null,
    2,
  )}\n`;
  writeFileSync(keyPath, storedKeyBytes);
  const matching = checkIssuerReadiness('https://issuer.example.test', keyPath);
  check(
    'a stored issuer matching the configured issuer is ready',
    matching.every((c) => c.status === 'ok'),
    JSON.stringify(matching),
  );
  const mismatched = checkIssuerReadiness('https://other.example.test', keyPath);
  check(
    'a stored issuer differing from the configured issuer fails closed and names both identities',
    mismatched[1]?.status === 'failed' &&
      mismatched[1].detail.includes('https://issuer.example.test') &&
      mismatched[1].detail.includes('https://other.example.test'),
    JSON.stringify(mismatched),
  );
  check(
    'the mismatch check modified nothing: the key file bytes are exactly as written',
    readFileSync(keyPath, 'utf8') === storedKeyBytes,
  );

  // Live mode with no configured issuer must fail closed in resolution too: no issuer key is
  // created, so nothing downstream is signable and no payment is attemptable.
  const freshKeyPath = join(scratch, 'never-created.json');
  const savedIssuer = process.env['PEAC_EXAMPLE_ISSUER'];
  delete process.env['PEAC_EXAMPLE_ISSUER'];
  let refusal: unknown;
  try {
    await resolveIssuerKey('live', freshKeyPath);
  } catch (e) {
    refusal = e;
  } finally {
    if (savedIssuer !== undefined) process.env['PEAC_EXAMPLE_ISSUER'] = savedIssuer;
  }
  check(
    'live issuer resolution with no configured issuer fails closed and creates no key file',
    refusal instanceof IssuerConfigurationError && !existsSync(freshKeyPath),
    String(refusal),
  );
}

// Live issuer admission is the record-issuance contract's canonical-origin rule, applied before
// anything can be signed or spent. Live issuer admission must be no weaker than record issuance:
// a deterministic issuer configuration the issuing library will refuse must be refused before
// the reference can reach a payment-capable phase, never discovered at evidence issuance. The
// preflight and the run resolve the issuer through the same function,
// `assertCanonicalLiveHttpsIssuer`, so the two cannot drift apart; these vectors pin the rule,
// and the issuance-parity block below pins the rule to the installed issuing library itself.
{
  const CANONICAL = 'https://issuer.example';
  const admission = (value: string): { admitted: boolean; message: string } => {
    try {
      return { admitted: assertCanonicalLiveHttpsIssuer(value) === value, message: '' };
    } catch (e) {
      return {
        admitted: false,
        message: e instanceof IssuerConfigurationError ? e.message : `unexpected ${String(e)}`,
      };
    }
  };

  check('the canonical https origin is admitted, byte for byte', admission(CANONICAL).admitted);
  check(
    'an explicit non-default port stays part of the canonical origin and is admitted',
    admission('https://payments.example:8443').admitted,
  );

  const slash = admission(`${CANONICAL}/`);
  check(
    'a trailing-slash issuer is rejected, never normalized, and the refusal names the exact canonical value',
    !slash.admitted && slash.message.includes(`accepts exactly ${CANONICAL} (`),
    slash.message,
  );
  check('a path-bearing issuer is rejected', !admission(`${CANONICAL}/records`).admitted);
  check('a query-bearing issuer is rejected', !admission(`${CANONICAL}/?tenant=a`).admitted);
  check('a fragment-bearing issuer is rejected', !admission(`${CANONICAL}#keys`).admitted);
  const credentialed = admission('https://operator:secret-credential@issuer.example');
  check(
    'a credential-bearing issuer is rejected and the refusal never echoes the credential',
    !credentialed.admitted && !credentialed.message.includes('secret-credential'),
    credentialed.message,
  );
  check('a non-https issuer is rejected', !admission('http://issuer.example').admitted);
  check('a malformed issuer is rejected', !admission('not a url').admitted);

  // The preflight reports the same refusal, with the canonical value in the operator-facing
  // detail, because the preflight resolves the issuer through the same admission function.
  const scratch = mkdtempSync(join(tmpdir(), 'peac-issuer-canonical-'));
  temporaryDirectories.push(scratch);
  const preflightChecks = checkIssuerReadiness(`${CANONICAL}/`, join(scratch, 'issuer.json'));
  check(
    'the preflight fails a trailing-slash issuer and its detail names the canonical value',
    preflightChecks[0]?.status === 'failed' &&
      preflightChecks[0].detail.includes(`accepts exactly ${CANONICAL} (`),
    JSON.stringify(preflightChecks),
  );

  // Failing closed means failing with NO side effects: resolution of a non-canonical issuer
  // creates no key file, and an existing key file is not opened, not compared and not modified —
  // the configured value is refused before stored key material is considered at all.
  const savedIssuer = process.env['PEAC_EXAMPLE_ISSUER'];
  process.env['PEAC_EXAMPLE_ISSUER'] = `${CANONICAL}/`;
  const neverCreatedPath = join(scratch, 'never-created.json');
  let slashRefusal: unknown;
  try {
    await resolveIssuerKey('live', neverCreatedPath);
  } catch (e) {
    slashRefusal = e;
  }
  check(
    'live resolution of a trailing-slash issuer fails closed and creates no key file',
    slashRefusal instanceof IssuerConfigurationError && !existsSync(neverCreatedPath),
    String(slashRefusal),
  );

  const existingKeyPath = join(scratch, 'existing-issuer.json');
  const existingKeyBytes = `${JSON.stringify(
    {
      note: 'test vector',
      kid: 'canonical-vector-key-1',
      issuer: CANONICAL,
      privateKeyHex: '11'.repeat(32),
    },
    null,
    2,
  )}\n`;
  writeFileSync(existingKeyPath, existingKeyBytes);
  let existingKeyRefusal: unknown;
  try {
    await resolveIssuerKey('live', existingKeyPath);
  } catch (e) {
    existingKeyRefusal = e;
  }
  check(
    'live resolution of a trailing-slash issuer refuses the configuration itself and leaves an existing key file byte-identical',
    existingKeyRefusal instanceof IssuerConfigurationError &&
      readFileSync(existingKeyPath, 'utf8') === existingKeyBytes,
    String(existingKeyRefusal),
  );
  if (savedIssuer === undefined) delete process.env['PEAC_EXAMPLE_ISSUER'];
  else process.env['PEAC_EXAMPLE_ISSUER'] = savedIssuer;

  // The full preflight a live run must pass: with everything else in order — a loadable payer
  // key vector, a distinct recipient, the upstream asset, a chain endpoint answering correctly
  // and a facilitator advertising the scheme — a trailing-slash issuer alone leaves the run NOT
  // ready, and nothing asked the facilitator to verify or settle anything. The same
  // configuration with the canonical issuer is ready, so the refusal is attributable to the
  // issuer value and to nothing else.
  const payerKeyPath = join(scratch, 'payer.json');
  const payerPrivateKeyHex = `0x${'22'.repeat(32)}` as const;
  writeFileSync(
    payerKeyPath,
    `${JSON.stringify({ note: 'test vector', privateKeyHex: payerPrivateKeyHex }, null, 2)}\n`,
  );
  check(
    'the payer vector and the fixture recipient are distinct accounts',
    privateKeyToAccount(payerPrivateKeyHex).address.toLowerCase() !== F.PAY_TO.toLowerCase(),
  );
  const stubChainState = {
    chainId: async (): Promise<bigint> => BASE_SEPOLIA_CHAIN_ID,
    erc20Balance: async (): Promise<bigint> => MIN_USDC_BASE_UNITS,
  };
  const preflightFor = async (issuerValue: string) => {
    const facilitator = createFixtureFacilitator(F.NETWORK);
    const report = await runPreflight({
      network: F.NETWORK,
      payTo: F.PAY_TO,
      asset: F.ASSET_CONTRACT,
      rpc: stubChainState,
      facilitatorClient: facilitator.client,
      payerKeyMode: 'require-existing',
      payerKeyPath,
      outDirectory: join(scratch, 'out'),
      issuer: { configured: issuerValue, keyPath: join(scratch, 'preflight-issuer.json') },
    });
    return { report, calls: facilitator.calls };
  };
  const notReady = await preflightFor(`${CANONICAL}/`);
  check(
    'a full preflight with a trailing-slash issuer is not ready, the issuer check is the failure, and no payment was verified or settled',
    !notReady.report.ready &&
      notReady.report.checks.some(
        (c) => c.name === 'issuer is explicitly configured for live mode' && c.status === 'failed',
      ) &&
      notReady.report.checks.every(
        (c) => c.name === 'issuer is explicitly configured for live mode' || c.status !== 'failed',
      ) &&
      notReady.calls.verify === 0 &&
      notReady.calls.settle === 0,
    JSON.stringify(notReady.report.checks),
  );
  const ready = await preflightFor(CANONICAL);
  check(
    'the same preflight with the canonical issuer is ready, so the refusal above is attributable to the issuer alone',
    ready.report.ready && ready.calls.verify === 0 && ready.calls.settle === 0,
    JSON.stringify(ready.report.checks),
  );
}

// Issuance parity: what this reference admits as a live issuer must be what the installed
// record-issuing library will actually issue with. The admission rule above is local code, and
// local code can drift from the library it fronts for; this block closes that gap with the
// library itself, using a throwaway in-memory key and the same record type, pillar and extension
// groups the real evidence path uses. If a future protocol version tightens or shifts its
// canonical-issuer contract, the admitted vectors below stop issuing and this fails loudly in
// tests, before any live run can reach a payment-capable phase. No file key, no network.
{
  const throwaway = await generateKeypair();
  const issueWith = async (iss: string): Promise<{ issued: boolean; message: string }> => {
    try {
      const result = await issue({
        iss,
        kind: 'evidence',
        type: RECORD_TYPE,
        privateKey: throwaway.privateKey,
        kid: 'issuance-parity-throwaway-key-1',
        pillars: ['commerce'],
        occurred_at: '2026-08-28T00:00:00Z',
        extensions: {
          [COMMERCE_GROUP]: {
            payment_rail: 'x402',
            amount_minor: F.AMOUNT_BASE_UNITS,
            currency: 'USDC',
            asset: F.ASSET_CONTRACT,
            env: 'test',
          },
          [PAYMENT_EVIDENCE_GROUP]: { note: 'issuance parity vector' },
        },
      });
      return { issued: result.jws.length > 0, message: '' };
    } catch (e) {
      return { issued: false, message: String(e instanceof Error ? e.message : e).split('\n')[0] ?? '' };
    }
  };

  const admittedVectors = [
    'https://issuer.example',
    'https://payments.example:8443',
    FIXTURE_ISSUER,
  ];
  for (const iss of admittedVectors) {
    let admitted = false;
    try {
      admitted = assertCanonicalLiveHttpsIssuer(iss) === iss;
    } catch {
      admitted = false;
    }
    const issuance = await issueWith(iss);
    check(
      `issuance parity: an issuer this reference admits is issuable by the installed library (${iss})`,
      admitted && issuance.issued,
      issuance.message,
    );
  }

  const slashIssuance = await issueWith('https://issuer.example/');
  check(
    'issuance parity: a non-canonical trailing-slash issuer is refused by the installed library',
    !slashIssuance.issued && slashIssuance.message.includes('canonical'),
    slashIssuance.message,
  );
}

// Stored key identifier bound: every deterministic value read from persistent local state that
// the issuing library can reject is validated before a payment-capable phase. The stored `kid`
// is signed into the record header, and issuance bounds it at MAX_STORED_KID_UTF8_BYTES UTF-8
// bytes; a stored identifier past that bound must be refused when the key file is read — at
// preflight, before payment — never discovered at evidence issuance after funds have moved.
// The boundary is pinned to the installed library first, with a throwaway in-memory key, so
// the local constant cannot drift from what issuance actually does. The bound is the ONLY
// admission: short identifiers and identifiers with spaces issue upstream and stay admitted.
{
  const throwaway = await generateKeypair();
  const kidIssues = async (kid: string): Promise<{ issued: boolean; message: string }> => {
    try {
      const result = await issue({
        iss: 'https://issuer.example',
        kind: 'evidence',
        type: RECORD_TYPE,
        privateKey: throwaway.privateKey,
        kid,
        pillars: ['commerce'],
        occurred_at: '2026-08-28T00:00:00Z',
        extensions: {
          [COMMERCE_GROUP]: {
            payment_rail: 'x402',
            amount_minor: F.AMOUNT_BASE_UNITS,
            currency: 'USDC',
            asset: F.ASSET_CONTRACT,
            env: 'test',
          },
          [PAYMENT_EVIDENCE_GROUP]: { note: 'kid boundary vector' },
        },
      });
      return { issued: result.jws.length > 0, message: '' };
    } catch (e) {
      return { issued: false, message: String(e instanceof Error ? e.message : e).split('\n')[0] ?? '' };
    }
  };

  // The boundary itself, confirmed against the installed library. The multibyte vectors use a
  // two-UTF-8-byte character, so character count and byte count disagree — exactly the case a
  // character-based bound would get wrong.
  const ascii256 = 'k'.repeat(MAX_STORED_KID_UTF8_BYTES);
  const ascii257 = 'k'.repeat(MAX_STORED_KID_UTF8_BYTES + 1);
  const multibyte256 = 'é'.repeat(MAX_STORED_KID_UTF8_BYTES / 2);
  const multibyte258 = 'é'.repeat(MAX_STORED_KID_UTF8_BYTES / 2 + 1);
  const ascii256Issuance = await kidIssues(ascii256);
  check(
    'kid parity: an identifier of exactly 256 ASCII bytes is issuable by the installed library',
    ascii256Issuance.issued,
    ascii256Issuance.message,
  );
  check(
    'kid parity: an identifier of 257 ASCII bytes is refused by the installed library',
    !(await kidIssues(ascii257)).issued,
  );
  const multibyte256Issuance = await kidIssues(multibyte256);
  check(
    'kid parity: an identifier of exactly 256 UTF-8 bytes via multibyte characters is issuable',
    Buffer.byteLength(multibyte256, 'utf8') === MAX_STORED_KID_UTF8_BYTES && multibyte256Issuance.issued,
    multibyte256Issuance.message,
  );
  check(
    'kid parity: a multibyte identifier past 256 UTF-8 bytes is refused by the installed library',
    !(await kidIssues(multibyte258)).issued,
  );

  // Stored-key admission agrees with that boundary in both directions, and a refusal is
  // observation-only: the key file on disk stays byte-identical.
  const scratch = mkdtempSync(join(tmpdir(), 'peac-stored-kid-'));
  temporaryDirectories.push(scratch);
  const storedKeyFile = (name: string, kid: string): { path: string; bytes: string } => {
    const path = join(scratch, name);
    const bytes = `${JSON.stringify(
      { note: 'test vector', kid, issuer: 'https://issuer.example.test', privateKeyHex: '11'.repeat(32) },
      null,
      2,
    )}\n`;
    writeFileSync(path, bytes);
    return { path, bytes };
  };
  const loads = (path: string): { loaded: boolean; message: string } => {
    try {
      return { loaded: storedIssuerBinding(path) === 'https://issuer.example.test', message: '' };
    } catch (e) {
      return { loaded: false, message: e instanceof InvalidKeyFileError ? e.message : `unexpected ${String(e)}` };
    }
  };

  const storedAscii256 = storedKeyFile('kid-ascii-256.json', ascii256);
  check('a stored key identifier of exactly 256 ASCII bytes is admitted', loads(storedAscii256.path).loaded);
  const storedAscii257 = storedKeyFile('kid-ascii-257.json', ascii257);
  const ascii257Refusal = loads(storedAscii257.path);
  check(
    'a stored key identifier of 257 ASCII bytes is refused before it can reach issuance',
    !ascii257Refusal.loaded && ascii257Refusal.message.includes('UTF-8 bytes'),
    ascii257Refusal.message,
  );
  check(
    'the stored admission matches the installed library on the exact multibyte boundary',
    loads(storedKeyFile('kid-multibyte-256.json', multibyte256).path).loaded === multibyte256Issuance.issued,
  );
  const storedMultibyte258 = storedKeyFile('kid-multibyte-258.json', multibyte258);
  const multibyteRefusal = loads(storedMultibyte258.path);
  check(
    'a stored multibyte identifier past 256 UTF-8 bytes is refused',
    !multibyteRefusal.loaded && multibyteRefusal.message.includes('UTF-8 bytes'),
    multibyteRefusal.message,
  );
  check(
    'the refusals modified nothing: both refused key files are byte-identical on disk',
    readFileSync(storedAscii257.path, 'utf8') === storedAscii257.bytes &&
      readFileSync(storedMultibyte258.path, 'utf8') === storedMultibyte258.bytes,
  );

  // The full preflight a live run must pass: with everything else in order, an oversized stored
  // identifier alone leaves the run NOT ready, the binding check names the refusal, and nothing
  // asked the facilitator to verify or settle anything.
  const payerKeyPath = join(scratch, 'payer.json');
  writeFileSync(
    payerKeyPath,
    `${JSON.stringify({ note: 'test vector', privateKeyHex: `0x${'22'.repeat(32)}` }, null, 2)}\n`,
  );
  const facilitator = createFixtureFacilitator(F.NETWORK);
  const report = await runPreflight({
    network: F.NETWORK,
    payTo: F.PAY_TO,
    asset: F.ASSET_CONTRACT,
    rpc: {
      chainId: async (): Promise<bigint> => BASE_SEPOLIA_CHAIN_ID,
      erc20Balance: async (): Promise<bigint> => MIN_USDC_BASE_UNITS,
    },
    facilitatorClient: facilitator.client,
    payerKeyMode: 'require-existing',
    payerKeyPath,
    outDirectory: join(scratch, 'out'),
    issuer: { configured: 'https://issuer.example.test', keyPath: storedAscii257.path },
  });
  check(
    'a full preflight with an oversized stored key identifier is not ready, the binding check is the failure, and no payment was verified or settled',
    !report.ready &&
      report.checks.some(
        (c) =>
          c.name === 'existing issuer key records the configured issuer' &&
          c.status === 'failed' &&
          c.detail.includes('UTF-8 bytes'),
      ) &&
      report.checks.every(
        (c) => c.name === 'existing issuer key records the configured issuer' || c.status !== 'failed',
      ) &&
      facilitator.calls.verify === 0 &&
      facilitator.calls.settle === 0,
    JSON.stringify(report.checks),
  );
  check(
    'the preflight refusal modified nothing: the oversized key file is byte-identical on disk',
    readFileSync(storedAscii257.path, 'utf8') === storedAscii257.bytes,
  );

  // A key generated by the live path itself stays admissible: the identifier it writes is
  // within the issuance bound, and the file it wrote loads straight back.
  const liveKeyPath = join(scratch, 'generated-issuer.json');
  const savedIssuer = process.env['PEAC_EXAMPLE_ISSUER'];
  process.env['PEAC_EXAMPLE_ISSUER'] = 'https://issuer.example.test';
  try {
    const generated = await resolveIssuerKey('live', liveKeyPath);
    check(
      'a normally generated live key identifier is within the issuance bound and loads back admitted',
      Buffer.byteLength(generated.kid, 'utf8') <= MAX_STORED_KID_UTF8_BYTES &&
        storedIssuerBinding(liveKeyPath) === 'https://issuer.example.test',
    );
  } finally {
    if (savedIssuer === undefined) delete process.env['PEAC_EXAMPLE_ISSUER'];
    else process.env['PEAC_EXAMPLE_ISSUER'] = savedIssuer;
  }
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
    // The substituted binding also names a resource the native payment-signature does not, so the
    // native cross-check between the two fails alongside the binding digest itself.
    failedExactly(report, [
      'request binding digest',
      'payment-signature resource matches the request binding',
    ]),
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
    // Same cascade as EVM-BIND-001: the binding now names a different query, which the native
    // resource-agreement check also catches.
    failedExactly(report, [
      'request binding digest',
      'payment-signature resource matches the request binding',
    ]),
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
// Native: the captured x402 artifacts, decoded and compared against the record and observation.
// ---------------------------------------------------------------------------------------------

console.log('\n  -- native --');

recordExecution('EVM-NATIVE-001');
{
  // The reviewer's probe (exactly): a re-signed native payment-signature whose accepted amount and
  // authorization value both disagree with the record and the observation, while the digest that
  // binds the artifact is refreshed to match, so nothing upstream of the native checks can catch
  // it. This also breaks what the payment-required document advertised, because the accepted
  // terms it must contain no longer match: a producer that shipped this would fail three named
  // checks, not the two the terms/authorization comparison alone would suggest, and the honest
  // count is asserted rather than assumed.
  const report = await reissueWith((files, claims) => {
    const original = decoder.decode(files.get('artifacts/payment-signature.txt'));
    const decoded = JSON.parse(Buffer.from(original, 'base64').toString('utf8')) as {
      accepted: { amount: unknown };
      payload: { authorization: { value: unknown } };
    };
    decoded.accepted.amount = '999999';
    decoded.payload.authorization.value = '999999';
    const newBytes = encoder.encode(Buffer.from(JSON.stringify(decoded)).toString('base64'));
    files.set('artifacts/payment-signature.txt', newBytes);
    paymentEvidence(claims)['payment_signature_digest'] = digestBytes(newBytes);
  });
  check(
    'a re-signed native payment-signature whose amount disagrees with the record fails the named terms and authorization checks',
    failedExactly(report, [
      'payment-signature terms match the expectation',
      'payment-signature authorization matches the expectation',
      'payment-required advertises the accepted terms',
    ]) && passed(report, 'payment-signature digest'),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-NATIVE-002');
{
  const report = await reissueWith((files, claims) => {
    const original = decoder.decode(files.get('artifacts/payment-response.txt'));
    const decoded = JSON.parse(Buffer.from(original, 'base64').toString('utf8')) as {
      transaction: unknown;
    };
    decoded.transaction = `0x${'ab'.repeat(32)}`;
    const newBytes = encoder.encode(Buffer.from(JSON.stringify(decoded)).toString('base64'));
    files.set('artifacts/payment-response.txt', newBytes);
    paymentEvidence(claims)['payment_response_digest'] = digestBytes(newBytes);
  });
  check(
    'a re-signed native payment-response whose transaction disagrees with the observation fails the named settlement check',
    // The observation document still names the honest response digest, so the two documents
    // disagree about what settled as well as disagreeing about the transaction itself: both are
    // legitimate consequences of the one edit, and the record's own digest recomputes intact.
    failedExactly(report, [
      'payment-response matches the settlement observation',
      'record and observation name the same settlement response digest',
    ]) && passed(report, 'payment-response digest'),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-NATIVE-003');
{
  const report = await reissueWith((files, claims) => {
    const original = decoder.decode(files.get('artifacts/payment-signature.txt'));
    const decoded = JSON.parse(Buffer.from(original, 'base64').toString('utf8')) as {
      resource: { url: unknown };
    };
    decoded.resource = {
      ...decoded.resource,
      url: 'https://api.example.test/v1/other?region=zzz&units=metric',
    };
    const newBytes = encoder.encode(Buffer.from(JSON.stringify(decoded)).toString('base64'));
    files.set('artifacts/payment-signature.txt', newBytes);
    paymentEvidence(claims)['payment_signature_digest'] = digestBytes(newBytes);
  });
  check(
    'a re-signed native payment-signature naming a different resource fails the request-binding agreement check',
    // Also breaks the payment-required cross-check, since it compares the resource url on both
    // native artifacts and the two no longer agree.
    failedExactly(report, [
      'payment-signature resource matches the request binding',
      'payment-required advertises the accepted terms',
    ]) && passed(report, 'payment-signature digest'),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-NATIVE-004');
{
  const report = await reissueWith((files, claims) => {
    const original = decoder.decode(files.get('artifacts/payment-signature.txt'));
    const decoded = JSON.parse(Buffer.from(original, 'base64').toString('utf8')) as {
      extensions: { 'payment-identifier': { info: { id: unknown } } };
    };
    decoded.extensions['payment-identifier'].info.id = 'pay_0000000000000000000000000000f1x3';
    const newBytes = encoder.encode(Buffer.from(JSON.stringify(decoded)).toString('base64'));
    files.set('artifacts/payment-signature.txt', newBytes);
    paymentEvidence(claims)['payment_signature_digest'] = digestBytes(newBytes);
  });
  check(
    'a payment identifier that disagrees with the record reference fails by name',
    failedExactly(report, ['payment-signature identifier matches the record reference']),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-NATIVE-005');
{
  // Not held: verification was refused before the handler ran, so no settlement was ever
  // expected. A malformed presented payment is still evidence of the attempt, and the preserved
  // rule reports it as such rather than measuring it against an expectation it never had.
  const rejectedRun = await runOnce({
    facilitator: { rejectVerification: 'synthetic_verification_refusal' },
  });
  const rejectedLayout = await buildEvidence(rejectedRun);
  const claims = decodeClaims(rejectedLayout.jws);
  const files = new Map(rejectedLayout.files);

  const malformedValue = Buffer.from(JSON.stringify({ x402Version: 2 })).toString('base64');
  const malformedBytes = encoder.encode(malformedValue);
  files.set('artifacts/payment-signature.txt', malformedBytes);
  const signatureDigest = digestBytes(malformedBytes);
  paymentEvidence(claims)['payment_signature_digest'] = signatureDigest;

  const originalBinding = JSON.parse(
    decoder.decode(files.get('request-binding.json')),
  ) as PaymentEvidenceRequestBindingV1;
  const refreshedBinding = buildRequestBinding({
    components: originalBinding.components,
    body: F.REQUEST_BODY,
    selectedHeaders: [{ name: 'payment-signature', observedValueDigest: signatureDigest }],
  });
  files.set('request-binding.json', documentBytes(refreshedBinding));
  paymentEvidence(claims)['request_binding_digest'] = await bindingDigest(refreshedBinding);

  const result = await issue({
    iss: claims.iss,
    kind: 'evidence',
    type: claims.type,
    privateKey: issuerKey.privateKey,
    kid: issuerKey.kid,
    ...(claims.pillars !== undefined ? { pillars: claims.pillars } : {}),
    ...(claims.occurred_at !== undefined ? { occurred_at: claims.occurred_at } : {}),
    extensions: claims.extensions,
  });
  files.set('record.jws', encoder.encode(`${result.jws}\n`));
  const directory = mkdtempSync(join(tmpdir(), 'peac-evidence-'));
  temporaryDirectories.push(directory);
  writeEvidence(directory, { jws: result.jws, files });
  const report = await verifyEvidence(directory, issuerKey.publicKey);
  check(
    'evidence of a rejected payment attempt with a malformed native artifact stays verifiable under the preserved rule',
    report.ok && passed(report, 'native artifacts/payment-signature.txt preserved as presented'),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-NATIVE-006');
{
  const report = await reissueWith(async (files, claims) => {
    const observation = JSON.parse(decoder.decode(files.get('chain-observation.json'))) as Record<
      string,
      unknown
    >;
    const tampered = { ...observation, unexpected_member: 'x' };
    files.set('chain-observation.json', documentBytes(tampered));
    paymentEvidence(claims)['chain_observation_digest'] = coerceDigest(
      await computeJsonDocumentDigestJcs(tampered as JsonValue),
    );
  });
  check(
    'the chain observation document is held to its closed schema; an unknown member fails by name',
    failedExactly(report, ['chain observation local profile schema']) &&
      report.checks.some(
        (c) => c.name === 'chain observation local profile schema' && c.detail.includes('unexpected_member'),
      ),
    failedChecks(report).join(', ') || 'nothing failed',
  );
}

recordExecution('EVM-NATIVE-007');
{
  const fixtureKey = await resolveIssuerKey('fixture');
  const fixtureReport = await verifyEvidence(EXPECTED_EVIDENCE_DIR, fixtureKey.publicKey);
  const fixtureNativeChecks = fixtureReport.checks.filter((c) => c.category === 'native');
  check(
    'the committed fixture evidence verifies under profile 2 with every native check passing',
    fixtureReport.ok &&
      fixtureReport.profile === VERIFIER_PROFILE &&
      fixtureNativeChecks.length > 0 &&
      fixtureNativeChecks.every((c) => c.ok),
    failedChecks(fixtureReport).join(', ') || 'nothing failed',
  );

  const liveDir = 'out/live-20260828T214534z';
  const liveKeyFile = 'out/live-20260828T214534z-issuer.pub.json';
  if (!existsSync(liveDir) || !existsSync(liveKeyFile)) {
    console.log('    (skipping the archived live-evidence half: the directory is absent here)');
  } else {
    const liveKey = readIssuerPublicKeyFile(liveKeyFile);
    const liveReport = await verifyEvidence(liveDir, liveKey.publicKey);
    const liveNativeChecks = liveReport.checks.filter((c) => c.category === 'native');
    check(
      'the archived live evidence verifies under profile 2 with every native check passing',
      liveReport.ok &&
        liveReport.profile === VERIFIER_PROFILE &&
        liveNativeChecks.length > 0 &&
        liveNativeChecks.every((c) => c.ok),
      failedChecks(liveReport).join(', ') || 'nothing failed',
    );
  }
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
    'a tampered observed field value fails its own digest and, since the tamper also breaks the base64 it decodes from, the native decode check',
    // Replacing the last four characters with 'AAAA' corrupts the base64/JSON the artifact decodes
    // to, so this edit legitimately trips the native decode check as well as the digest: not a
    // cascade from a shared cause, but two separate, correct verdicts about the same bad bytes.
    failedExactly(report, ['payment-signature digest', 'native payment-signature decodes']),
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
    'an altered observation document fails its own digest and the amount the record repeats, and, since the native payment-signature still names the honest amount, the two native checks that compare it against the now-tampered expectation',
    // The native artifact itself is untouched: `payment-signature digest` still recomputes. But
    // the expectation these native checks compare it against now says '1', so the native terms and
    // authorization checks legitimately disagree with it too -- correctly attributing the defect to
    // the observation document, never to the native artifact.
    failedExactly(report, [
      'chain observation digest',
      'record and observation name the same amount',
      'payment-signature terms match the expectation',
      'payment-signature authorization matches the expectation',
    ]) && passed(report, 'payment-response digest') && passed(report, 'payment-signature digest'),
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
