/**
 * Deterministic fixture data.
 *
 * Every artifact here is built against the upstream x402 v2 types and accepted by the upstream
 * runtime validators, so the deterministic validation vectors describe real x402 objects rather than
 * shapes invented locally. Nothing is cast: if an upstream type changes, these fixtures stop
 * compiling, which is the point.
 *
 * SYNTHETIC ONLY. The network is Base Sepolia (the CAIP-2 identifier declared below) and the asset
 * is the public Base Sepolia USDC contract, taken from the upstream package's own default-asset
 * registry. The payer, recipient, authorization nonce, transaction hash and signature are
 * deterministic synthetic placeholders: each
 * is derived from a descriptive label via SHA-256 (see the comment on each constant). This repository
 * generates and possesses no private key for any of them and does not use these values for onchain
 * execution; that is a claim about what this repository does, not a claim that no account with a
 * matching address could ever exist on any network, which this repository has no way to verify.
 * Hexadecimal cannot spell a readable label the way SVM's base58 placeholders could
 * ("SyntheticRecipient..."), so the derivation is documented instead.
 */
import {
  encodePaymentRequiredHeader,
  encodePaymentSignatureHeader,
  encodePaymentResponseHeader,
} from '@x402/core/http';
import type {
  PaymentRequired,
  PaymentRequirements,
  PaymentPayload,
  SettleResponse,
  ResourceInfo,
} from '@x402/core/types';
import { DEFAULT_ASSETS } from '@x402/evm';
import {
  PAYMENT_IDENTIFIER,
  declarePaymentIdentifierExtension,
  appendPaymentIdentifierToExtensions,
} from '@x402/extensions/payment-identifier';

/** Fixed instant so binding digests are reproducible across runs. */
export const FIXED_NOW_UNIX_SECONDS = 1_785_000_000;

export const RESOURCE_URL = 'https://api.example.test/v1/forecast?region=alpha&units=metric';

/**
 * The x402 v2 / CAIP-2 network identifier for Base Sepolia: `eip155:` plus chain ID 84532.
 * Declared locally as an explicit protocol constant: the pinned upstream packages export no
 * v2-native CAIP-2 constant for Base Sepolia (`EVM_NETWORK_CHAIN_ID_MAP` is an explicitly
 * v1-legacy export), and the fail-fast check below proves the upstream default-asset registry
 * still keys an entry under this identifier.
 */
export const NETWORK = 'eip155:84532' as const;
export const SCHEME = 'exact';
/** The default Base Sepolia USDC entry, from the upstream default-asset registry. */
const BASE_SEPOLIA_USDC = DEFAULT_ASSETS[NETWORK]?.[0];
if (BASE_SEPOLIA_USDC === undefined) {
  // Upstream-compatibility invariant, checked explicitly at fixture initialization: if the pinned
  // @x402/evm default-asset registry stops carrying a Base Sepolia default asset, fail immediately
  // instead of falling back to, or inventing, a substitute token.
  throw new Error(
    `fixtures/deterministic.ts: the pinned @x402/evm DEFAULT_ASSETS registry has no default asset ` +
      `for ${NETWORK} (Base Sepolia). The upstream registry changed; update the @x402/* pin or ` +
      `this fixture deliberately rather than substituting an asset.`,
  );
}
export const ASSET_CONTRACT = BASE_SEPOLIA_USDC.asset;
export const ASSET_NAME = BASE_SEPOLIA_USDC.name;
export const ASSET_EIP712_VERSION = BASE_SEPOLIA_USDC.version;
export const TOKEN_DECIMALS = BASE_SEPOLIA_USDC.decimals;
export const AMOUNT_BASE_UNITS = '250000';
export const MAX_TIMEOUT_SECONDS = 60;

// Placeholder EVM accounts and values. Each is sha256("x402-base-evidence:<label>"), truncated to
// the required byte length. These are deterministic synthetic placeholders; this repository
// generates and possesses no corresponding private keys and never uses these values for onchain
// execution.
export const PAY_TO = '0x0a419cb4517abd08f809400cc6a1236f41ee6919'; // sha256(...:synthetic-recipient)[0:40]
export const PAYER = '0xaf75ffa7ffe35f491516746bf0e01a576169b27b'; // sha256(...:synthetic-payer)[0:40]
export const AUTHORIZATION_NONCE =
  '0xaeebcbc536d7ba4007d2c1d3c27c10970681439eccbe1cb74829124c933dfac0'; // sha256(...:synthetic-authorization-nonce)
export const SETTLEMENT_TX_HASH =
  '0x131655d7f0bee785962ee1c41431672593279a49b3cc010e467c6b2427c3cbff'; // sha256(...:synthetic-transaction-hash)
/** r || s || v, so the length matches a real 65-byte EIP-3009 signature. */
export const EXACT_EVM_SIGNATURE =
  '0x519c7a4aa9c5d21a9fe8c29a0954febffab4de44191b9d91601904ea57cf0cc1b61e9e3d4c536b298d3063e033681d15d9026dc40269b50f18bc1d9c9e6205671b';

export const VALID_AFTER_UNIX_SECONDS = FIXED_NOW_UNIX_SECONDS - 60;
export const VALID_BEFORE_UNIX_SECONDS = FIXED_NOW_UNIX_SECONDS + MAX_TIMEOUT_SECONDS;

/** Fixed identifier matching the upstream grammar: 16 to 128 chars of [A-Za-z0-9_-]. */
export const PAYMENT_ID = 'pay_0000000000000000000000000000f1x2';

/**
 * The scheme-specific payload member for exact on EVM: EIP-3009 `transferWithAuthorization`,
 * the asset-transfer method native USDC and compatible tokens implement (the alternative,
 * Permit2, is out of scope for this profile). Field shapes follow the upstream `authorization`
 * type: hex addresses, decimal-string amounts and timestamps, a bytes32 nonce.
 */
export const EXACT_EVM_AUTHORIZATION = {
  from: PAYER,
  to: PAY_TO,
  value: AMOUNT_BASE_UNITS,
  validAfter: String(VALID_AFTER_UNIX_SECONDS),
  validBefore: String(VALID_BEFORE_UNIX_SECONDS),
  nonce: AUTHORIZATION_NONCE,
};

export const RESOURCE_INFO: ResourceInfo = {
  url: RESOURCE_URL,
  description: 'Synthetic forecast resource used by the deterministic fixtures',
  mimeType: 'application/json',
};

export const PAYMENT_REQUIREMENTS: PaymentRequirements = {
  scheme: SCHEME,
  network: NETWORK,
  asset: ASSET_CONTRACT,
  amount: AMOUNT_BASE_UNITS,
  payTo: PAY_TO,
  maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
  // EIP-712 domain fields for the asset contract, as a resource server would advertise them.
  extra: { name: ASSET_NAME, version: ASSET_EIP712_VERSION },
};

/** Extensions as a resource server would declare them, built with the upstream declaration API. */
export const DECLARED_EXTENSIONS: Record<string, unknown> = {
  [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true),
};

export const PAYMENT_REQUIRED: PaymentRequired = {
  x402Version: 2,
  resource: RESOURCE_INFO,
  accepts: [PAYMENT_REQUIREMENTS],
  extensions: DECLARED_EXTENSIONS,
};

/**
 * Extensions as a client would send them: the server's declaration with the client's identifier
 * appended by the upstream client API, so the structure is whatever x402 actually defines.
 */
export const PAYLOAD_EXTENSIONS: Record<string, unknown> = appendPaymentIdentifierToExtensions(
  { [PAYMENT_IDENTIFIER]: declarePaymentIdentifierExtension(true) },
  PAYMENT_ID,
);

export const PAYMENT_PAYLOAD: PaymentPayload = {
  x402Version: 2,
  resource: RESOURCE_INFO,
  accepted: PAYMENT_REQUIREMENTS,
  payload: { authorization: EXACT_EVM_AUTHORIZATION, signature: EXACT_EVM_SIGNATURE },
  extensions: PAYLOAD_EXTENSIONS,
};

/** Settlement response as the origin observed it, in the shape upstream declares for it. */
export const SETTLEMENT_RESPONSE: SettleResponse = {
  success: true,
  transaction: SETTLEMENT_TX_HASH,
  network: NETWORK,
  payer: PAYER,
};

/** The x402 signed offer, shaped like the offer-receipt extension's offer object. */
export const SIGNED_OFFER = {
  resourceUrl: RESOURCE_URL,
  network: NETWORK,
  scheme: SCHEME,
  asset: ASSET_CONTRACT,
  amount: AMOUNT_BASE_UNITS,
  decimals: TOKEN_DECIMALS,
  payTo: PAY_TO,
  validUntilUnixSeconds: FIXED_NOW_UNIX_SECONDS + 300,
  paymentId: PAYMENT_ID,
} as const;

/** The x402 signed receipt: resource, payer, network, issuance time, optional tx hash. */
export const SIGNED_RECEIPT = {
  resourceUrl: RESOURCE_URL,
  payer: PAYER,
  network: NETWORK,
  issuedAtUnixSeconds: FIXED_NOW_UNIX_SECONDS + 12,
  transactionSignature: SETTLEMENT_TX_HASH,
  paymentId: PAYMENT_ID,
} as const;

/** The request body the customer sent (empty for a GET). */
export const REQUEST_BODY = new Uint8Array(0);

/** The bytes the origin application handed to its response API. */
export const ORIGIN_RESULT_BODY_TEXT = JSON.stringify({
  region: 'alpha',
  units: 'metric',
  generatedAtUnixSeconds: FIXED_NOW_UNIX_SECONDS + 13,
  forecast: [
    { hour: 0, tempC: 17.4 },
    { hour: 1, tempC: 17.1 },
    { hour: 2, tempC: 16.8 },
  ],
});

/** Bodies are bound as bytes, never as strings with an implied encoding. */
export const ORIGIN_RESULT_BODY = new TextEncoder().encode(ORIGIN_RESULT_BODY_TEXT);

/**
 * Field values are produced by the installed x402 encoders, so the fixtures carry the real
 * transport encoding rather than one assumed locally.
 *
 * Names are lowercased, as an origin application observes them after HTTP parsing.
 */
export const OBSERVED_CHALLENGE_HEADERS = {
  'payment-required': encodePaymentRequiredHeader(PAYMENT_REQUIRED),
} as const;

export const OBSERVED_REQUEST_HEADERS = {
  'payment-signature': encodePaymentSignatureHeader(PAYMENT_PAYLOAD),
} as const;

export const OBSERVED_RESPONSE_HEADERS = {
  'payment-response': encodePaymentResponseHeader(SETTLEMENT_RESPONSE),
} as const;

export const HTTP_VERSION = '2.0';
