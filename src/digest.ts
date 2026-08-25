/**
 * The single digest representation used throughout this example: `sha256:<64 lowercase hex>`.
 *
 * One syntax everywhere. Mixing a prefixed form with bare hex would make it ambiguous whether two
 * digest fields are comparable.
 *
 * The rule is about PROVENANCE, not about the characters. A digest arriving from outside this module
 * -- a field on a caller-constructed binding, a value read back from a document -- is rejected unless
 * it is already canonical: that is `isSha256Digest` and `asSha256Digest`, and bare hex does not pass
 * them. `coerceDigest` is the one deliberate exception, and it is applied to exactly one kind of
 * input: the return value of the trusted in-process PEAC canonicalization helper, which this module
 * calls itself. Normalizing that return value guards against the helper's output form changing;
 * it never widens what an external digest may look like.
 */
import { createHash } from 'node:crypto';

export type Sha256Digest = `sha256:${string}`;

const HEX64 = /^[0-9a-f]{64}$/;

export function isSha256Digest(v: unknown): v is Sha256Digest {
  return typeof v === 'string' && v.startsWith('sha256:') && HEX64.test(v.slice(7));
}

/** Assert-and-return, so a malformed digest cannot silently propagate into a binding. */
export function asSha256Digest(v: string): Sha256Digest {
  if (!isSha256Digest(v)) throw new TypeError(`not a sha256 digest: ${v.slice(0, 80)}`);
  return v;
}

/** SHA-256 over exact bytes, returned in the single canonical representation. */
export function digestBytes(bytes: Uint8Array | string): Sha256Digest {
  const buf = typeof bytes === 'string' ? Buffer.from(bytes, 'utf8') : bytes;
  return `sha256:${createHash('sha256').update(buf).digest('hex')}`;
}

/**
 * Normalise the return value of the trusted in-process PEAC canonicalization helper into a
 * Sha256Digest. It already emits the `sha256:` form; accepting bare hex here guards against that
 * form changing rather than assuming it.
 *
 * NOT for external input. Untrusted or caller-supplied digests go through `asSha256Digest`, which
 * rejects bare hex instead of coercing it. Call sites: `x402-header.ts` and `binding.ts`, both
 * wrapping `computeJsonDocumentDigestJcs` directly.
 */
export function coerceDigest(v: string): Sha256Digest {
  if (isSha256Digest(v)) return v;
  if (HEX64.test(v)) return `sha256:${v}`;
  throw new TypeError(`unrecognised digest form: ${v.slice(0, 80)}`);
}
