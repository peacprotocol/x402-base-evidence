/**
 * Staged observation and validation of x402 payment field values.
 *
 * The central rule: DECODING IS NOT VALIDATION. The upstream `decode*Header` functions are
 * transport decoders. They accept any base64-encoded JSON object, including one with no x402
 * structure at all, so treating a successful decode as "this is a valid x402 object" reports a
 * transport fact as a schema fact.
 *
 * Validation is therefore split into ordered stages, each reported independently as
 * `accepted`, `rejected` or `not_evaluated`:
 *
 *   transport          strict standard base64, within the declared size bound
 *   json               UTF-8 text that the upstream decoder accepts as a JSON object
 *   duplicate-members  no ambiguous object members (see strict-json.ts for why)
 *   upstream-schema    the x402 v2 schema for this artifact type, evaluated by upstream code
 *   scheme-payload     the scheme-specific payload member, for payment payloads
 *   extensions         declared x402 extensions, evaluated by upstream extension APIs
 *
 * Validation authority is always named. For payment-required and payment-signature the authority
 * is the upstream x402 schema. For payment-response the upstream package ships no runtime
 * validator at any export path, so `upstream-schema` stays `not_evaluated` for ever and a
 * separate, explicitly local structural check is reported instead. That result is never labelled
 * x402 schema validation.
 *
 * Capture preserves what was observed, valid or not: recording that a counterparty sent something
 * invalid is evidence. Only a promoted, type-distinct artifact may gate payment verification or
 * fulfillment, and promotion fails closed.
 */
import {
  decodePaymentRequiredHeader,
  decodePaymentSignatureHeader,
  decodePaymentResponseHeader,
} from '@x402/core/http';
import { PaymentRequiredV2Schema, PaymentPayloadV2Schema } from '@x402/core/schemas';
import type { PaymentRequired, PaymentPayload, SettleResponse } from '@x402/core/types';
import { isEIP3009Payload, type ExactEvmPayloadV2 } from '@x402/evm';
import {
  PAYMENT_IDENTIFIER,
  validatePaymentIdentifier,
} from '@x402/extensions/payment-identifier';
import { computeJsonDocumentDigestJcs } from '@peac/protocol';
import type { JsonValue } from '@peac/kernel';
import { digestBytes, coerceDigest, type Sha256Digest } from './digest.ts';
import { scanForDuplicateMembers } from './strict-json.ts';

export class HeaderParseError extends Error {}
export class X402ValidationError extends Error {}
/** Raised when an artifact that has not satisfied its stage requirements is promoted. */
export class X402PromotionError extends Error {}

/**
 * The exact upstream version this profile is written against. The import smoke test asserts that
 * the installed package matches, so a silent upgrade cannot invalidate the authority strings below.
 */
export const X402_PINNED_VERSION = '2.23.0';

/** Named validation authorities. Every reported status is attributable to one of these. */
export const UPSTREAM_SCHEMA_AUTHORITY = `@x402/core@${X402_PINNED_VERSION}/schemas` as const;
/**
 * The settle-response structural authority is LOCAL, not upstream.
 *
 * The name is first-party (`x402-base-evidence/...`), never shaped like an `@x402/core` identifier,
 * so a reader cannot mistake a local structural verdict for an upstream one at a glance. Its basis
 * is recorded separately: it reproduces the exported TypeScript declaration of `SettleResponse` from
 * the pinned upstream package, and nothing more. See SETTLE_RESPONSE_LOCAL_AUTHORITY_BASIS.
 */
export const SETTLE_RESPONSE_LOCAL_AUTHORITY = 'x402-base-evidence/local-settle-response-shape@1' as const;
/** What SETTLE_RESPONSE_LOCAL_AUTHORITY's check is actually derived from. Documentation, not code. */
export const SETTLE_RESPONSE_LOCAL_AUTHORITY_BASIS =
  `@x402/core@${X402_PINNED_VERSION} SettleResponse TypeScript declaration` as const;

export type CapturePoint =
  | 'origin_request_after_http_parsing'
  | 'origin_response_before_gateway'
  | 'client_response_after_http_parsing';

/** The three x402 v2 payment fields. payment-identifier is an extension, not a field. */
export const X402_HEADERS = {
  'payment-required': 'PaymentRequired',
  'payment-signature': 'PaymentPayload',
  'payment-response': 'SettleResponse',
} as const;
export type X402HeaderName = keyof typeof X402_HEADERS;
export type X402ObjectType = (typeof X402_HEADERS)[X402HeaderName];

export const X402_STAGES = [
  'transport',
  'json',
  'duplicate-members',
  'upstream-schema',
  'scheme-payload',
  'extensions',
] as const;
export type X402Stage = (typeof X402_STAGES)[number];
export type StageStatus = 'accepted' | 'rejected' | 'not_evaluated';
export type StageReport = Readonly<Record<X402Stage, StageStatus>>;

/**
 * Bounds on retained input and on what is reported back about it.
 *
 * `maxEncodedValueBytes` is an APPLICATION-LOCAL safety bound chosen by this example. It is not
 * derived from, and implies nothing about, any HTTP parser limit: a runtime header-block limit
 * covers an entire header block, and x402 defines no per-field payload limit.
 *
 * `maxDecodedPayloadBytes` follows from the encoded bound at the base64 3/4 ratio. Within the
 * encoded bound it therefore cannot be the first bound to trigger; it is enforced anyway so that
 * decoded payloads reaching this module by any other route are still bounded.
 */
export const X402_LIMITS = {
  maxEncodedValueBytes: 16_384,
  maxDecodedPayloadBytes: 12 * 1024,
} as const;

/** Diagnostics are bounded so an attacker-supplied payload cannot inflate what is retained. */
export const DIAGNOSTIC_LIMITS = {
  maxIssues: 8,
  maxPathDepth: 8,
  maxPathSegmentChars: 64,
  maxSerializedBytes: 1024,
} as const;

/**
 * Where a diagnostic came from. `local-structural` is listed separately from the ordered stages
 * because it is this example's own check, not one of the x402 validation stages.
 */
export type DiagnosticStage = X402Stage | 'local-structural';

/**
 * The fixed, closed vocabulary of diagnostic codes this profile ever reports. `code` is typed to
 * this union, not `string`, so a producer cannot introduce an unaudited code and a consumer cannot
 * be handed one that was never reviewed for safety.
 *
 * `unspecified` is the fallback for anything that does not match this vocabulary: an upstream
 * validator's issue code is bounded by the runtime check in `boundDiagnostic` against exactly this
 * list, never trusted verbatim just because it happens to look like a safe token. The upstream-issue
 * entries below are the Zod issue codes the pinned schema version is known to produce; the fallback
 * is what protects this profile if an upstream version adds a code this list does not name.
 */
export const X402_DIAGNOSTIC_CODES = [
  // transport / json stages
  'not_standard_base64',
  'empty_payload',
  'decoded_payload_too_large',
  'not_valid_utf8',
  'upstream_decode_failed',
  'not_a_json_object',
  // duplicate-members stage (mirrors DuplicateScanCode in strict-json.ts)
  'duplicate_member',
  'depth_limit_exceeded',
  'scan_incomplete',
  // local-structural stage (settle response)
  'expected_boolean',
  'expected_string',
  'expected_caip2_network',
  'expected_object',
  // scheme-payload stage
  'unsupported_scheme',
  'unsupported_asset_transfer_method',
  'expected_eip3009_authorization',
  'expected_hex_address',
  'expected_decimal_string',
  'expected_bytes32',
  'expected_hex_signature',
  // extensions stage
  'invalid_payment_identifier',
  // upstream-schema stage: known Zod issue codes. An issue code outside this list is never
  // reported verbatim; it is reported as 'unspecified' instead.
  'invalid_type',
  'invalid_literal',
  'unrecognized_keys',
  'invalid_union',
  'invalid_union_discriminator',
  'invalid_enum_value',
  'invalid_arguments',
  'invalid_return_type',
  'invalid_date',
  'invalid_string',
  'too_small',
  'too_big',
  'invalid_intersection_types',
  'not_multiple_of',
  'not_finite',
  'custom',
  // fallback: any code outside every category above
  'unspecified',
] as const;
export type X402DiagnosticCode = (typeof X402_DIAGNOSTIC_CODES)[number];
const KNOWN_DIAGNOSTIC_CODES: ReadonlySet<string> = new Set(X402_DIAGNOSTIC_CODES);

/**
 * A bounded, non-quoting description of one failure.
 *
 * `code` comes from the closed X402DiagnosticCode vocabulary above, enforced at runtime by
 * `boundDiagnostic`, never accepted verbatim from a validator. No message text produced by a
 * validator over attacker-controlled input is retained, because that text can embed the input
 * itself.
 */
export interface X402Diagnostic {
  readonly stage: DiagnosticStage;
  readonly code: X402DiagnosticCode;
  readonly path: readonly string[];
}

/** Settle-response reporting. Kept separate so it can never read as an x402 schema verdict. */
export interface LocalStructuralReport {
  readonly upstreamSchemaStatus: 'not_evaluated';
  readonly localStructuralStatus: StageStatus;
  readonly localStructuralAuthority: typeof SETTLE_RESPONSE_LOCAL_AUTHORITY;
}

/**
 * An observed field value and how far validation got. It authorizes nothing, and no function that
 * requires a validated artifact will accept it.
 */
export interface CapturedX402Artifact {
  readonly name: X402HeaderName;
  readonly artifactType: X402ObjectType;
  /** The field value exactly as observed at the application capture boundary. */
  readonly observedValue: string;
  /** SHA-256 over the UTF-8 bytes of the accepted field value. */
  readonly observedValueDigest: Sha256Digest;
  readonly decodedPayloadDigest?: Sha256Digest;
  /** Present only when a named validation authority accepted the object. */
  readonly validatedObjectJcsDigest?: Sha256Digest;
  /** The decoded object, present once the json stage is accepted. */
  readonly decoded?: JsonValue;
  readonly stages: StageReport;
  readonly diagnostics: readonly X402Diagnostic[];
  readonly upstreamSchemaAuthority: typeof UPSTREAM_SCHEMA_AUTHORITY;
  /** Present only for payment-response, where upstream defines no runtime validator. */
  readonly localStructural?: LocalStructuralReport;
  readonly capturePoint: CapturePoint;
  readonly httpVersion: string;
}

// Brands make the validated states distinct TYPES rather than a flag a caller might forget to
// inspect. A CapturedX402Artifact is not assignable to any of them.
declare const paymentRequiredBrand: unique symbol;
declare const paymentPayloadBrand: unique symbol;
declare const settleResponseBrand: unique symbol;

/**
 * The promoted types REFINE the properties a capture actually carries. They introduce no second
 * copy of the decoded object.
 *
 * `decoded` is that single property: optional on a capture, because a value that never reached the
 * json stage has none, and REQUIRED here, because promotion refuses to refine an artifact that has
 * none. Its type narrows from `JsonValue` to the x402 type whose named authority accepted it.
 *
 * An earlier revision declared a separate `value` property instead. No promotion ever assigned it,
 * so the compiler reported a field that was `undefined` at runtime for every promoted artifact.
 * Refining the property that exists is what makes the type-state truthful.
 */
export interface SchemaValidatedPaymentRequiredArtifact
  extends Omit<CapturedX402Artifact, 'decoded'> {
  readonly [paymentRequiredBrand]: true;
  readonly artifactType: 'PaymentRequired';
  readonly validatedObjectJcsDigest: Sha256Digest;
  readonly decoded: PaymentRequired;
}

export interface SchemaValidatedPaymentPayloadArtifact
  extends Omit<CapturedX402Artifact, 'decoded'> {
  readonly [paymentPayloadBrand]: true;
  readonly artifactType: 'PaymentPayload';
  readonly validatedObjectJcsDigest: Sha256Digest;
  readonly decoded: PaymentPayload;
}

export interface StructurallyCheckedSettleResponseArtifact
  extends Omit<CapturedX402Artifact, 'decoded'> {
  readonly [settleResponseBrand]: true;
  readonly artifactType: 'SettleResponse';
  readonly validatedObjectJcsDigest: Sha256Digest;
  readonly localStructural: LocalStructuralReport;
  readonly decoded: SettleResponse;
}

export type ValidatedX402Artifact =
  | SchemaValidatedPaymentRequiredArtifact
  | SchemaValidatedPaymentPayloadArtifact
  | StructurallyCheckedSettleResponseArtifact;

/** Schemes whose payload member this profile knows how to check. */
export const SUPPORTED_SCHEMES = ['exact'] as const;

/**
 * Asset-transfer methods this profile knows how to check for the exact scheme on EVM.
 *
 * x402 v2 exact/EVM selects an asset-transfer method through `extra.assetTransferMethod` on the
 * payment requirements, which a payment payload echoes at `accepted.extra.assetTransferMethod`.
 * The specification defines `eip3009`, `permit2` and `erc7710`, and states that a client defaults
 * to `eip3009` when the field is absent. The pinned upstream package implements two of them for
 * this scheme: `AssetTransferMethod` is `"eip3009" | "permit2"`, and `ExactEvmScheme` routes on
 * `paymentRequirements.extra?.assetTransferMethod ?? "eip3009"`.
 *
 * THIS REFERENCE IMPLEMENTS THE EIP-3009 PROFILE ONLY, so the list below has one member. That is a
 * deliberate narrowing, not an oversight, and it is enforced rather than merely documented: a
 * requirement selecting `permit2` carries a `permit2Authorization` payload, and interpreting it as
 * an EIP-3009 `authorization` would report a verdict about a shape the counterparty never sent.
 */
export const SUPPORTED_ASSET_TRANSFER_METHODS = ['eip3009'] as const;

const DECODERS: Record<X402HeaderName, (value: string) => unknown> = {
  'payment-required': decodePaymentRequiredHeader,
  'payment-signature': decodePaymentSignatureHeader,
  'payment-response': decodePaymentResponseHeader,
};

const ASCII_VISIBLE = /^[\x21-\x7e]+$/;
/** Standard base64 alphabet with optional padding, matching the x402 transport encoding. */
const STANDARD_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const UNSAFE_PATH_CHARS = /[^A-Za-z0-9._-]/g;

const NOT_EVALUATED: StageReport = {
  transport: 'not_evaluated',
  json: 'not_evaluated',
  'duplicate-members': 'not_evaluated',
  'upstream-schema': 'not_evaluated',
  'scheme-payload': 'not_evaluated',
  extensions: 'not_evaluated',
};

/** Reduce one issue to a bounded shape that quotes nothing from the input's values. */
function boundDiagnostic(stage: DiagnosticStage, code: unknown, path: readonly unknown[]): X402Diagnostic {
  const safeCode: X402DiagnosticCode =
    typeof code === 'string' && KNOWN_DIAGNOSTIC_CODES.has(code)
      ? (code as X402DiagnosticCode)
      : 'unspecified';
  const safePath = path.slice(0, DIAGNOSTIC_LIMITS.maxPathDepth).map((segment) =>
    String(segment).replace(UNSAFE_PATH_CHARS, '_').slice(0, DIAGNOSTIC_LIMITS.maxPathSegmentChars),
  );
  return { stage, code: safeCode, path: safePath };
}

/** Apply the count and total-size caps. Truncation is silent by design: it is a bound, not a fact. */
function boundDiagnostics(issues: readonly X402Diagnostic[]): readonly X402Diagnostic[] {
  const kept = issues.slice(0, DIAGNOSTIC_LIMITS.maxIssues);
  while (
    kept.length > 0 &&
    Buffer.byteLength(JSON.stringify(kept), 'utf8') > DIAGNOSTIC_LIMITS.maxSerializedBytes
  ) {
    kept.pop();
  }
  return kept;
}

/** True when a decoded payload exceeds the declared bound. Exported so the bound is testable. */
export function exceedsDecodedPayloadBound(byteLength: number): boolean {
  return byteLength > X402_LIMITS.maxDecodedPayloadBytes;
}

interface ZodLikeIssue {
  readonly code?: unknown;
  readonly path?: readonly unknown[];
}

function issuesFrom(error: unknown): readonly ZodLikeIssue[] {
  const issues = (error as { issues?: unknown } | undefined)?.issues;
  return Array.isArray(issues) ? (issues as ZodLikeIssue[]) : [];
}

/**
 * Preserve an observed field value and report exactly how far validation got.
 *
 * Never throws for malformed payloads. It throws only when the input cannot be treated as an
 * observed x402 field value at all: an unknown field name, an empty value, a value beyond the
 * declared bound, or a value that is not visible ASCII.
 */
export async function captureObservedX402Artifact(input: {
  name: string;
  observedValue: string;
  capturePoint: CapturePoint;
  httpVersion: string;
}): Promise<CapturedX402Artifact> {
  const name = input.name.toLowerCase() as X402HeaderName;
  if (!(name in X402_HEADERS)) {
    throw new HeaderParseError(`not an x402 payment field: ${input.name.slice(0, 40)}`);
  }

  const value = input.observedValue;
  if (typeof value !== 'string' || value.length === 0) throw new HeaderParseError('empty field value');
  if (Buffer.byteLength(value, 'utf8') > X402_LIMITS.maxEncodedValueBytes) {
    throw new HeaderParseError(`field value exceeds ${X402_LIMITS.maxEncodedValueBytes} bytes`);
  }
  // Payment field values are ASCII. Binding a non-ASCII string would make the digest depend on how
  // an intermediary happened to expose the bytes.
  if (!ASCII_VISIBLE.test(value)) throw new HeaderParseError('field value must be visible ASCII');

  const artifactType = X402_HEADERS[name];
  const stages: Record<X402Stage, StageStatus> = { ...NOT_EVALUATED };
  const diagnostics: X402Diagnostic[] = [];

  // The value has passed the visible-ASCII gate, so its UTF-8 encoding is exactly the bytes that
  // were observed. It is digested as UTF-8; the lossy 'ascii' codec is never used.
  const base: CapturedX402Artifact = {
    name,
    artifactType,
    observedValue: value,
    observedValueDigest: digestBytes(Buffer.from(value, 'utf8')),
    stages,
    diagnostics,
    upstreamSchemaAuthority: UPSTREAM_SCHEMA_AUTHORITY,
    capturePoint: input.capturePoint,
    httpVersion: input.httpVersion,
    ...(name === 'payment-response'
      ? {
          localStructural: {
            upstreamSchemaStatus: 'not_evaluated',
            localStructuralStatus: 'not_evaluated',
            localStructuralAuthority: SETTLE_RESPONSE_LOCAL_AUTHORITY,
          } satisfies LocalStructuralReport,
        }
      : {}),
  };
  const artifact = base as {
    -readonly [K in keyof CapturedX402Artifact]: CapturedX402Artifact[K];
  };
  /** Every exit applies the diagnostic caps, so no path can return unbounded detail. */
  const finish = (): CapturedX402Artifact => {
    artifact.diagnostics = boundDiagnostics(diagnostics);
    return artifact;
  };

  // -- transport ------------------------------------------------------------------------------
  if (!STANDARD_BASE64.test(value)) {
    stages.transport = 'rejected';
    diagnostics.push(boundDiagnostic('transport', 'not_standard_base64', []));
    return finish();
  }
  const decodedBytes = Buffer.from(value, 'base64');
  if (decodedBytes.byteLength === 0) {
    stages.transport = 'rejected';
    diagnostics.push(boundDiagnostic('transport', 'empty_payload', []));
    return finish();
  }
  if (exceedsDecodedPayloadBound(decodedBytes.byteLength)) {
    stages.transport = 'rejected';
    diagnostics.push(boundDiagnostic('transport', 'decoded_payload_too_large', []));
    return finish();
  }
  artifact.decodedPayloadDigest = digestBytes(decodedBytes);
  stages.transport = 'accepted';

  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(decodedBytes);
  } catch {
    stages.json = 'rejected';
    diagnostics.push(boundDiagnostic('json', 'not_valid_utf8', []));
    return finish();
  }

  // -- json -----------------------------------------------------------------------------------
  // The object itself comes from the upstream decoder, so this profile never defines a competing
  // transport encoding. The bytes above are decoded separately only to digest them and to give the
  // duplicate scanner the exact source text.
  let decoded: unknown;
  try {
    decoded = DECODERS[name](value);
  } catch {
    stages.json = 'rejected';
    diagnostics.push(boundDiagnostic('json', 'upstream_decode_failed', []));
    return finish();
  }
  if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
    stages.json = 'rejected';
    diagnostics.push(boundDiagnostic('json', 'not_a_json_object', []));
    return finish();
  }
  stages.json = 'accepted';
  artifact.decoded = decoded as JsonValue;

  // -- duplicate-members ----------------------------------------------------------------------
  const scan = scanForDuplicateMembers(text);
  if (scan.status !== 'accepted') {
    stages['duplicate-members'] = 'rejected';
    diagnostics.push(boundDiagnostic('duplicate-members', scan.code, scan.path));
    return finish();
  }
  stages['duplicate-members'] = 'accepted';

  // -- upstream-schema ------------------------------------------------------------------------
  if (name === 'payment-required' || name === 'payment-signature') {
    const schema = name === 'payment-required' ? PaymentRequiredV2Schema : PaymentPayloadV2Schema;
    const result = schema.safeParse(decoded);
    if (!result.success) {
      stages['upstream-schema'] = 'rejected';
      for (const issue of issuesFrom(result.error)) {
        diagnostics.push(boundDiagnostic('upstream-schema', issue.code, issue.path ?? []));
      }
      return finish();
    }
    stages['upstream-schema'] = 'accepted';
  } else {
    // No upstream runtime validator exists for this artifact type at any export path of the
    // pinned version, so the upstream stage stays not_evaluated and a local structural check is
    // reported instead, under its own authority.
    const structural = checkSettleResponseStructure(decoded as Record<string, unknown>);
    artifact.localStructural = {
      upstreamSchemaStatus: 'not_evaluated',
      localStructuralStatus: structural.ok ? 'accepted' : 'rejected',
      localStructuralAuthority: SETTLE_RESPONSE_LOCAL_AUTHORITY,
    };
    if (!structural.ok) {
      for (const issue of structural.issues) {
        diagnostics.push(boundDiagnostic('local-structural', issue.code, issue.path));
      }
      return finish();
    }
  }

  // -- scheme-payload -------------------------------------------------------------------------
  if (name === 'payment-signature') {
    const payload = decoded as PaymentPayload;
    const schemeIssue = checkSchemePayload(payload);
    if (schemeIssue) {
      stages['scheme-payload'] = 'rejected';
      diagnostics.push(boundDiagnostic('scheme-payload', schemeIssue.code, schemeIssue.path));
      return finish();
    }
    stages['scheme-payload'] = 'accepted';
  }

  // -- extensions -----------------------------------------------------------------------------
  if (name === 'payment-signature') {
    const extensions = (decoded as PaymentPayload).extensions;
    const declared = extensions?.[PAYMENT_IDENTIFIER];
    if (declared !== undefined) {
      const result = validatePaymentIdentifier(declared);
      if (result.valid) {
        stages.extensions = 'accepted';
      } else {
        stages.extensions = 'rejected';
        diagnostics.push(boundDiagnostic('extensions', 'invalid_payment_identifier', [PAYMENT_IDENTIFIER]));
        return finish();
      }
    }
  }

  // The object is canonicalized only after a named authority accepted it AND its members were
  // proven unambiguous, so the bound digest always covers a well-defined document.
  artifact.validatedObjectJcsDigest = coerceDigest(
    await computeJsonDocumentDigestJcs(decoded as JsonValue),
  );
  return finish();
}

interface StructuralIssue {
  readonly code: string;
  readonly path: readonly string[];
}

/**
 * Local structural check for a settle response, reproducing the exported TypeScript shape.
 * This is deliberately not called schema validation: no upstream validator exists for it.
 */
function checkSettleResponseStructure(
  value: Record<string, unknown>,
): { ok: true } | { ok: false; issues: readonly StructuralIssue[] } {
  const issues: StructuralIssue[] = [];
  const require = (key: string, ok: boolean, code: string) => {
    if (!ok) issues.push({ code, path: [key] });
  };
  require('success', typeof value.success === 'boolean', 'expected_boolean');
  require('transaction', typeof value.transaction === 'string', 'expected_string');
  require(
    'network',
    typeof value.network === 'string' && /^[^:]+:[^:]+$/.test(value.network),
    'expected_caip2_network',
  );
  for (const key of ['errorReason', 'errorMessage', 'payer', 'amount'] as const) {
    if (value[key] !== undefined) require(key, typeof value[key] === 'string', 'expected_string');
  }
  for (const key of ['extensions', 'extra'] as const) {
    if (value[key] !== undefined) {
      require(
        key,
        typeof value[key] === 'object' && value[key] !== null && !Array.isArray(value[key]),
        'expected_object',
      );
    }
  }
  return issues.length === 0 ? { ok: true } : { ok: false, issues };
}

/**
 * EVM address / hash shape checks. The upstream v2 schema types x402 payload members loosely
 * (a free-string scheme, an open payload record), so these are this profile's own checks, not an
 * x402 conformance rule.
 */
const HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX_BYTES32 = /^0x[0-9a-fA-F]{64}$/;
const HEX_SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const DECIMAL_STRING = /^[0-9]+$/;

/**
 * Check the scheme-specific payload member of a payment payload.
 *
 * The upstream v2 schema types `payload` as an open record and `scheme` as a free string, so a
 * payload naming an unsupported scheme, or carrying the wrong payload member for the scheme it
 * names, passes upstream schema validation. That check belongs to the scheme profile, and this
 * is where this example performs it.
 *
 * This profile supports exactly one asset-transfer method for the exact scheme on EVM: EIP-3009
 * `transferWithAuthorization` (the method native USDC and compatible tokens implement). The
 * upstream `isEIP3009Payload` guard only checks for the presence of an `authorization` member; the
 * field-level shape of that member (hex addresses, a bytes32 nonce, decimal-string amounts) is
 * this profile's own check, exactly as SVM's transaction-shape check was.
 *
 * ORDER MATTERS. The selected asset-transfer method is resolved BEFORE the payload member is
 * interpreted. Checking the EIP-3009 shape first would let a requirement selecting `permit2`, paired
 * with an EIP-3009-shaped payload, pass this profile's scheme-payload stage: the shape check would
 * succeed and nothing afterwards would ever look at the method that was actually selected.
 *
 * What this profile does NOT check here, deliberately: `extra.name` and `extra.version`. Measured
 * against the pinned upstream package rather than assumed -- they are the EIP-712 domain parameters
 * that the client supplies at SIGNING time (`signEIP3009Authorization` throws without them), and
 * that the facilitator cross-checks against the token contract's own on-chain `name()` and
 * `version()` reads, conditionally and via RPC. Neither is an envelope-shape property of a captured
 * payload, and this reference performs no chain access, so a presence-only check here would add no
 * assurance while duplicating upstream verification. They stay native x402/facilitator semantics.
 */
function checkSchemePayload(payload: PaymentPayload): StructuralIssue | undefined {
  const scheme = payload.accepted?.scheme;
  if (typeof scheme !== 'string' || !(SUPPORTED_SCHEMES as readonly string[]).includes(scheme)) {
    return { code: 'unsupported_scheme', path: ['accepted', 'scheme'] };
  }
  // x402 v2 exact/EVM: an ABSENT `assetTransferMethod` means the EIP-3009 default, which this
  // profile supports. An explicit value is honoured only when this profile implements it; every
  // other value -- `permit2`, `erc7710`, or anything a later revision adds -- is refused here,
  // before a single byte of the payload member is read as an EIP-3009 authorization.
  const declaredMethod = (payload.accepted?.extra as { assetTransferMethod?: unknown } | undefined)
    ?.assetTransferMethod;
  if (
    declaredMethod !== undefined &&
    (typeof declaredMethod !== 'string' ||
      !(SUPPORTED_ASSET_TRANSFER_METHODS as readonly string[]).includes(declaredMethod))
  ) {
    return {
      code: 'unsupported_asset_transfer_method',
      path: ['accepted', 'extra', 'assetTransferMethod'],
    };
  }
  const candidate = payload.payload as ExactEvmPayloadV2 | undefined;
  if (!candidate || typeof candidate !== 'object' || !isEIP3009Payload(candidate)) {
    return { code: 'expected_eip3009_authorization', path: ['payload', 'authorization'] };
  }
  const auth = candidate.authorization as
    | { from?: unknown; to?: unknown; value?: unknown; validAfter?: unknown; validBefore?: unknown; nonce?: unknown }
    | undefined;
  if (!auth || typeof auth !== 'object') {
    return { code: 'expected_object', path: ['payload', 'authorization'] };
  }
  if (typeof auth.from !== 'string' || !HEX_ADDRESS.test(auth.from)) {
    return { code: 'expected_hex_address', path: ['payload', 'authorization', 'from'] };
  }
  if (typeof auth.to !== 'string' || !HEX_ADDRESS.test(auth.to)) {
    return { code: 'expected_hex_address', path: ['payload', 'authorization', 'to'] };
  }
  if (typeof auth.value !== 'string' || !DECIMAL_STRING.test(auth.value)) {
    return { code: 'expected_decimal_string', path: ['payload', 'authorization', 'value'] };
  }
  if (typeof auth.validAfter !== 'string' || !DECIMAL_STRING.test(auth.validAfter)) {
    return { code: 'expected_decimal_string', path: ['payload', 'authorization', 'validAfter'] };
  }
  if (typeof auth.validBefore !== 'string' || !DECIMAL_STRING.test(auth.validBefore)) {
    return { code: 'expected_decimal_string', path: ['payload', 'authorization', 'validBefore'] };
  }
  if (typeof auth.nonce !== 'string' || !HEX_BYTES32.test(auth.nonce)) {
    return { code: 'expected_bytes32', path: ['payload', 'authorization', 'nonce'] };
  }
  // x402 v2 section 5.2.2 marks BOTH `signature` and `authorization` Required for the exact scheme
  // on EVM. Treating the signature as optional accepted an authorization that nobody had authorized.
  // This is a SHAPE check only: EIP-712 validity, signer recovery, authorization-window validity and
  // matching against the payment requirement are native x402/facilitator semantics, not this
  // reference's to decide.
  const signature = candidate.signature;
  if (typeof signature !== 'string' || !HEX_SIGNATURE.test(signature)) {
    return { code: 'expected_hex_signature', path: ['payload', 'signature'] };
  }
  return undefined;
}

function stageFailure(artifact: CapturedX402Artifact): string {
  const failed = X402_STAGES.filter((stage) => artifact.stages[stage] === 'rejected');
  const codes = artifact.diagnostics.map((d) => `${d.stage}:${d.code}`).join(', ');
  const stageText = failed.length > 0 ? failed.join(', ') : 'stage requirements not satisfied';
  return codes.length > 0 ? `${stageText} (${codes})` : stageText;
}

/**
 * Record, in the type, the two facts a caller's stage checks have just established at runtime: that
 * `decoded` is present, and that a canonical digest was computed over it.
 *
 * Both refined values are passed as ARGUMENTS rather than read from `artifact` inside this helper,
 * so a promotion cannot reach a promoted type without having narrowed them first. The compiler
 * checks the whole object against the target type; the only unchecked step left is the brand, a
 * `declare const` unique symbol that exists at compile time only and therefore has no runtime
 * property to assign. That is what the brands are for: they make the validated states distinct
 * TYPES, and they are never claimed to be observable fields.
 */
function refine<T extends ValidatedX402Artifact>(
  artifact: CapturedX402Artifact,
  decoded: T['decoded'],
  validatedObjectJcsDigest: Sha256Digest,
): T {
  return { ...artifact, decoded, validatedObjectJcsDigest } as T;
}

/**
 * Promote a captured artifact to the schema-validated payment-required type.
 * Fails closed: nothing but an accepted upstream-schema stage over unambiguous members qualifies.
 */
export function promoteToPaymentRequired(
  artifact: CapturedX402Artifact,
): SchemaValidatedPaymentRequiredArtifact {
  if (artifact.artifactType !== 'PaymentRequired') {
    throw new X402PromotionError(`expected PaymentRequired, observed ${artifact.artifactType}`);
  }
  if (
    artifact.stages['duplicate-members'] !== 'accepted' ||
    artifact.stages['upstream-schema'] !== 'accepted' ||
    artifact.validatedObjectJcsDigest === undefined ||
    artifact.decoded === undefined
  ) {
    throw new X402PromotionError(`payment-required not promotable: ${stageFailure(artifact)}`);
  }
  return refine<SchemaValidatedPaymentRequiredArtifact>(
    artifact,
    // `decoded` is retained as a generic JsonValue; narrowing it to the x402 type is exactly
    // what the accepted stage above established about THIS object, and nothing more.
    artifact.decoded as unknown as PaymentRequired,
    artifact.validatedObjectJcsDigest,
  );
}

/**
 * Promote a captured artifact to the schema-validated payment-payload type.
 * Requires the scheme payload to have been checked as well: an upstream-valid payload naming an
 * unsupported scheme must never reach fulfillment.
 */
export function promoteToPaymentPayload(
  artifact: CapturedX402Artifact,
): SchemaValidatedPaymentPayloadArtifact {
  if (artifact.artifactType !== 'PaymentPayload') {
    throw new X402PromotionError(`expected PaymentPayload, observed ${artifact.artifactType}`);
  }
  if (
    artifact.stages['duplicate-members'] !== 'accepted' ||
    artifact.stages['upstream-schema'] !== 'accepted' ||
    artifact.stages['scheme-payload'] !== 'accepted' ||
    artifact.stages.extensions === 'rejected' ||
    artifact.validatedObjectJcsDigest === undefined ||
    artifact.decoded === undefined
  ) {
    throw new X402PromotionError(`payment-payload not promotable: ${stageFailure(artifact)}`);
  }
  return refine<SchemaValidatedPaymentPayloadArtifact>(
    artifact,
    // `decoded` is retained as a generic JsonValue; narrowing it to the x402 type is exactly
    // what the accepted stage above established about THIS object, and nothing more.
    artifact.decoded as unknown as PaymentPayload,
    artifact.validatedObjectJcsDigest,
  );
}

/**
 * Promote a captured artifact to the structurally checked settle-response type.
 * The upstream-schema stage stays `not_evaluated` here for ever, by construction.
 */
export function promoteToSettleResponse(
  artifact: CapturedX402Artifact,
): StructurallyCheckedSettleResponseArtifact {
  if (artifact.artifactType !== 'SettleResponse') {
    throw new X402PromotionError(`expected SettleResponse, observed ${artifact.artifactType}`);
  }
  if (
    artifact.stages['duplicate-members'] !== 'accepted' ||
    artifact.localStructural?.localStructuralStatus !== 'accepted' ||
    artifact.validatedObjectJcsDigest === undefined ||
    artifact.decoded === undefined
  ) {
    throw new X402PromotionError(`settle-response not promotable: ${stageFailure(artifact)}`);
  }
  return refine<StructurallyCheckedSettleResponseArtifact>(
    artifact,
    // `decoded` is retained as a generic JsonValue; narrowing it to the x402 type is exactly
    // what the accepted stage above established about THIS object, and nothing more.
    artifact.decoded as unknown as SettleResponse,
    artifact.validatedObjectJcsDigest,
  );
}

/**
 * Capture and promote in one step. Use before payment verification or fulfillment; the result is
 * type-distinct from a capture, so a caller cannot reach acceptance by forgetting a check.
 */
export async function requireValidX402Artifact(input: {
  name: string;
  observedValue: string;
  capturePoint: CapturePoint;
  httpVersion: string;
  requiredExtensions?: readonly string[];
}): Promise<ValidatedX402Artifact> {
  const artifact = await captureObservedX402Artifact(input);
  let promoted: ValidatedX402Artifact;
  try {
    promoted =
      artifact.artifactType === 'PaymentRequired'
        ? promoteToPaymentRequired(artifact)
        : artifact.artifactType === 'PaymentPayload'
          ? promoteToPaymentPayload(artifact)
          : promoteToSettleResponse(artifact);
  } catch (e) {
    throw new X402ValidationError((e as Error).message);
  }
  for (const extension of input.requiredExtensions ?? []) {
    if (extension !== PAYMENT_IDENTIFIER || promoted.stages.extensions !== 'accepted') {
      throw new X402ValidationError(
        `${artifact.name}: required extension "${extension}" is absent or invalid`,
      );
    }
  }
  return promoted;
}
