/**
 * Bounded reads of files handed over by someone else.
 *
 * WHY THIS EXISTS. An evidence directory is the one input this example accepts from a party it has
 * no relationship with. Reading it with `readFileSync` trusts that directory twice over: once about
 * how large a file is, and once about what a name in it actually points at. Neither is safe to
 * assume. A file sized to exhaust memory, a name pointing at a device or a named pipe, or a symlink
 * aimed at something outside the directory are all things a directory can contain, and a verifier
 * that hangs or dies on one of them has told its reader nothing about the evidence.
 *
 * So every read goes through here, and every refusal is a named result rather than an exception:
 * the caller reports "this artifact was refused, for this reason" as a verification failure, which
 * is a verdict a reader can act on.
 *
 * ABSENCE IS ONE SPECIFIC THING. Only `ENOENT` means a file is not there. Everything else, a
 * symlink, a directory, a pipe, a file too large, a file this process may not open, is a refusal.
 * Collapsing any of them into absence would let a directory whose files cannot be read verify as a
 * smaller and perfectly consistent one.
 *
 * WHAT THE NO-FOLLOW HANDLING DOES AND DOES NOT PROVIDE. The order is `lstat` first, so a symlink
 * is refused without being opened; then `open` with `O_NOFOLLOW` and `O_NONBLOCK` where the
 * platform defines them, so a name swapped for a symlink or a named pipe between the two calls is
 * refused or returns immediately rather than following the swap or blocking on it; then `fstat` on
 * the descriptor actually opened, so the size and the file type that bound the read are the ones
 * belonging to the bytes being read. Where `O_NOFOLLOW` is not defined the sequence is `lstat`
 * then `fstat`, which detects a swap after the fact rather than preventing the open, and this file
 * claims nothing stronger than that.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, type Stats } from 'node:fs';
import { LIMITS } from '../binding.ts';
import { EVIDENCE_ARTIFACTS, type EvidenceArtifact } from './presence.ts';

/**
 * The bound on a captured x402 field value, restated here rather than imported.
 *
 * It is the same number as `X402_LIMITS.maxEncodedValueBytes` in `src/x402-header.ts`, which is the
 * bound the capture path enforced when these files were written: a value larger than that could
 * not have been captured, so reading one back is already evidence of something other than a run.
 * Importing that module would give the verification path the entire payment SDK it deliberately
 * does not need, so the number is stated here and a test asserts the two have not drifted apart.
 */
const CAPTURED_FIELD_VALUE_MAX_BYTES = 16_384;

/**
 * How many bytes each artifact may be, before any of it is allocated.
 *
 * Every bound is stated in one place so a caller never carries a number of its own. Two are the
 * producer's own limits: the origin result body is bounded by `LIMITS.maxBodyBytes`, the bound the
 * binding path enforces when it digests a body, and the three captured field values are bounded by
 * the encoded-value bound above. The JSON sidecars have no producer bound of their own, so they get
 * conservative caps: they are small structured documents, and anything approaching these sizes is
 * not one.
 */
export const ARTIFACT_MAX_BYTES: Readonly<Record<EvidenceArtifact, number>> = {
  'record.jws': 64 * 1024,
  'request-binding.json': 64 * 1024,
  'origin-result-binding.json': 64 * 1024,
  'origin-result-body.bin': LIMITS.maxBodyBytes,
  'chain-observation.json': 128 * 1024,
  'artifacts/payment-required.txt': CAPTURED_FIELD_VALUE_MAX_BYTES,
  'artifacts/payment-signature.txt': CAPTURED_FIELD_VALUE_MAX_BYTES,
  'artifacts/payment-response.txt': CAPTURED_FIELD_VALUE_MAX_BYTES,
};

/**
 * The bound on a supplied public key file.
 *
 * A key file is five short members. The bound exists because the file arrives from wherever the
 * evidence did, so it is an untrusted input on the same footing as the directory.
 */
export const PUBLIC_KEY_FILE_MAX_BYTES = 16 * 1024;

/**
 * Directories the artifact set names below the evidence root.
 *
 * Derived from the artifact list rather than written out, so a nested artifact added later cannot
 * introduce a container nobody checks.
 */
export const ARTIFACT_CONTAINERS: readonly string[] = [
  ...new Set(
    EVIDENCE_ARTIFACTS.filter((artifact) => artifact.includes('/')).map((artifact) =>
      artifact.slice(0, artifact.lastIndexOf('/')),
    ),
  ),
];

/**
 * Why a path was refused. Each value is a distinct state a report can name.
 *
 * `unreadable` is the residual: a permission denial or an I/O error, which says something about
 * this machine rather than about the shape of the evidence, and is still never absence.
 */
export type ReadRefusal =
  | 'symbolic_link'
  | 'not_a_regular_file'
  | 'too_large'
  | 'unreadable';

export type BoundedFileRead =
  | { readonly kind: 'read'; readonly bytes: Uint8Array }
  | { readonly kind: 'absent' }
  | {
      readonly kind: 'refused';
      readonly refusal: ReadRefusal;
      /** Bounded explanation. Never quotes file contents or a caller-supplied path. */
      readonly detail: string;
    };

export type ContainerCheck =
  | { readonly kind: 'directory' }
  | { readonly kind: 'absent' }
  | {
      readonly kind: 'refused';
      readonly refusal: 'symbolic_link' | 'not_a_directory' | 'unreadable';
      readonly detail: string;
    };

/**
 * Whether this platform can refuse to follow a symlink at open time.
 *
 * Exported so the property can be reported honestly rather than assumed: where it is false the
 * sequence still refuses symlinks, just one call later.
 */
export const NO_FOLLOW_AT_OPEN = typeof constants.O_NOFOLLOW === 'number';

/** Flags for a read that follows nothing and waits for nothing. */
const OPEN_FLAGS =
  constants.O_RDONLY |
  (typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0) |
  // A named pipe opened for reading blocks until a writer arrives. Refusing one at `lstat` covers
  // the ordinary case; this covers the swap, so the verifier cannot be made to wait forever.
  (typeof constants.O_NONBLOCK === 'number' ? constants.O_NONBLOCK : 0);

const refuse = (refusal: ReadRefusal, detail: string): BoundedFileRead => ({
  kind: 'refused',
  refusal,
  detail,
});

/** What a stat says the path is, in one word, for a report that never quotes the path. */
function describeType(stats: Stats): string {
  if (stats.isDirectory()) return 'a directory';
  if (stats.isFIFO()) return 'a named pipe';
  if (stats.isSocket()) return 'a socket';
  if (stats.isCharacterDevice()) return 'a character device';
  if (stats.isBlockDevice()) return 'a block device';
  return 'not a regular file';
}

/** The errno of a failed filesystem call, or a fixed word when there is none. */
const errnoOf = (e: unknown): string => (e as NodeJS.ErrnoException).code ?? 'unreadable';

/**
 * Read a regular file, or say why not.
 *
 * @param path - The file to read.
 * @param maxBytes - The most this file may contain. Checked against the size on the descriptor
 *   before anything is allocated, and again against what was actually read, so a file that grows
 *   between the two is refused rather than truncated silently.
 */
export function readBoundedFile(path: string, maxBytes: number): BoundedFileRead {
  let link: Stats;
  try {
    link = lstatSync(path);
  } catch (e) {
    if (errnoOf(e) === 'ENOENT') return { kind: 'absent' };
    return refuse('unreadable', errnoOf(e));
  }
  // Refused before the open, which is what keeps a named pipe from ever being waited on and keeps
  // a symlink from being resolved at all.
  if (link.isSymbolicLink()) return refuse('symbolic_link', 'the name points at another path');
  if (!link.isFile()) return refuse('not_a_regular_file', describeType(link));

  let fd: number;
  try {
    fd = openSync(path, OPEN_FLAGS);
  } catch (e) {
    const code = errnoOf(e);
    if (code === 'ENOENT') return { kind: 'absent' };
    // ELOOP is what `O_NOFOLLOW` reports when the name became a symlink after the check above.
    if (code === 'ELOOP') return refuse('symbolic_link', 'the name points at another path');
    return refuse('unreadable', code);
  }

  try {
    // The descriptor, not the name: this is the file the bytes will come from, whatever the name
    // points at by now.
    const opened = fstatSync(fd);
    if (!opened.isFile()) return refuse('not_a_regular_file', describeType(opened));
    if (opened.size > maxBytes) {
      return refuse('too_large', `${opened.size} bytes, bound is ${maxBytes}`);
    }

    // One byte of headroom, so a file that grew after the size check fills the buffer and is
    // refused, rather than being read back as a shorter document that never existed.
    const cap = Math.min(opened.size, maxBytes);
    const buffer = Buffer.allocUnsafe(cap + 1);
    let filled = 0;
    for (;;) {
      const read = readSync(fd, buffer, filled, buffer.length - filled, null);
      if (read === 0) break;
      filled += read;
      if (filled > cap) return refuse('too_large', `more than ${cap} bytes while being read`);
    }
    // Constructed from the filled region only, so no uninitialised memory can leave this function.
    return { kind: 'read', bytes: new Uint8Array(buffer.subarray(0, filled)) };
  } catch (e) {
    return refuse('unreadable', errnoOf(e));
  } finally {
    try {
      closeSync(fd);
    } catch {
      // A descriptor that cannot be closed is not a fact about the evidence, and reporting it as
      // one would turn a local condition into a verdict about someone else's files.
    }
  }
}

/**
 * Check that a directory an artifact path descends through is a real directory.
 *
 * Absence is allowed and reported as such: whether a container has to exist is decided by the
 * presence contract for the terminal state inside the record, not here. What is not allowed is a
 * symlink standing in for it, because every bounded read below it would then be reading somewhere
 * else while the paths still look like they name this directory.
 */
export function checkContainerDirectory(path: string): ContainerCheck {
  let link: Stats;
  try {
    link = lstatSync(path);
  } catch (e) {
    if (errnoOf(e) === 'ENOENT') return { kind: 'absent' };
    return { kind: 'refused', refusal: 'unreadable', detail: errnoOf(e) };
  }
  if (link.isSymbolicLink()) {
    return { kind: 'refused', refusal: 'symbolic_link', detail: 'the name points at another path' };
  }
  if (!link.isDirectory()) {
    return { kind: 'refused', refusal: 'not_a_directory', detail: describeType(link) };
  }
  return { kind: 'directory' };
}
