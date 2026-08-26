/**
 * The public half of an issuer key, as a file that can be handed to someone else.
 *
 * WHY IT EXISTS. Verification needs the evidence directory and a public key, and nothing else. A
 * run whose evidence is meant to be checked by another person therefore has to hand that key over,
 * so a live run writes it out beside the run it belongs to. Only the public half is ever written;
 * the private key stays in `.local/keys/` and no code path here reads it.
 *
 * WHAT A SUPPLIED KEY ESTABLISHES, AND WHAT IT DOES NOT. It makes the record cryptographically
 * verifiable: the signature either matches or it does not. It establishes nothing about who holds
 * the matching private key. A reader who takes the key from the same place they took the evidence
 * has checked that the evidence is internally consistent and was signed by whoever produced it,
 * which is a smaller claim than it looks. An identity claim needs a key obtained through a channel
 * independent of the evidence, and this example provides no such channel and claims no such thing.
 *
 * FAILING CLOSED. Every rejection names the file and the reason. A key file that cannot be read as
 * a key is never guessed at: verifying under a key nobody can describe would report a result about
 * material the reader did not choose.
 */
import { writeFileSync } from 'node:fs';
import { displayKeyPath } from './key-file.ts';
import { parseStrictJson, type StrictJsonRefusal } from '../strict-json.ts';
import { PUBLIC_KEY_FILE_MAX_BYTES, readBoundedFile } from './safe-read.ts';

/** The only algorithm this example issues or verifies under. */
export const PUBLIC_KEY_ALGORITHM = 'Ed25519';

/** Exactly the 32 bytes of an Ed25519 public key, as hex. */
const PUBLIC_KEY_HEX = /^[0-9a-fA-F]{64}$/;

export interface IssuerPublicKeyFileV1 {
  readonly algorithm: typeof PUBLIC_KEY_ALGORITHM;
  readonly kid: string;
  readonly issuer: string;
  /** The 32-byte Ed25519 public key, lowercase hex. */
  readonly publicKey: string;
  readonly note: string;
}

export interface LoadedIssuerPublicKey {
  readonly publicKey: Uint8Array;
  /** The algorithm the file declared. Carried so a report states it rather than assuming it. */
  readonly algorithm: string;
  readonly kid: string;
  readonly issuer: string;
}

/**
 * The sentence that has to travel with any verification performed under a supplied key.
 *
 * Kept as one exported string so the command output, the file itself and the documentation cannot
 * drift into three different statements of the same boundary.
 */
export const SUPPLIED_KEY_CAVEAT = [
  'A supplied public key makes the record cryptographically verifiable.',
  'It is not an independently trusted identity: it says nothing about who holds the',
  'private key, and a key obtained from the same place as the evidence establishes',
  'internal consistency only.',
  'The key file also declares an algorithm, a key identifier and an issuer, and those',
  'are checked against the record. Agreement means the file describes the key that',
  'signed it; it is still consistency, and never identity.',
].join('\n  ');

export class InvalidPublicKeyFileError extends Error {
  readonly path: string;
  readonly reason: string;
  constructor(path: string, reason: string) {
    super(
      `Public key file cannot be used: ${displayKeyPath(path)}\n` +
        `  reason: ${reason}\n` +
        '  expected: {"algorithm":"Ed25519","kid":...,"issuer":...,"publicKey":<64 hex chars>}',
    );
    this.name = 'InvalidPublicKeyFileError';
    this.path = path;
    this.reason = reason;
  }
}

/**
 * Write the public half of an issuer key.
 *
 * @param path - Where to write. An existing file is never replaced: a run's key belongs to that
 *   run, and overwriting one would silently restate which key verifies an earlier directory.
 * @param key - The key material. Only `publicKey`, `kid` and `iss` are read.
 */
export function writeIssuerPublicKeyFile(
  path: string,
  key: { readonly publicKey: Uint8Array; readonly kid: string; readonly iss: string },
): void {
  const contents: IssuerPublicKeyFileV1 = {
    algorithm: PUBLIC_KEY_ALGORITHM,
    kid: key.kid,
    issuer: key.iss,
    publicKey: Buffer.from(key.publicKey).toString('hex'),
    note:
      'Public key only. Verifying under it shows the record is intact; ' +
      'it does not establish who holds the private key.',
  };
  writeFileSync(path, `${JSON.stringify(contents, null, 2)}\n`, { flag: 'wx' });
}

/** Why a key file was not admitted, said in the words a reader of the message needs. */
const KEY_FILE_REFUSALS: Readonly<Record<StrictJsonRefusal, string>> = {
  invalid_utf8: 'it is not valid UTF-8, and repairing the bytes would change what it declares',
  not_json: 'it is not valid JSON',
  scan_incomplete: 'it is not valid JSON',
  duplicate_member:
    'it declares the same member twice, so which key it names depends on the parser reading it',
  depth_limit_exceeded: 'it nests deeper than a key file is read',
};

/**
 * Read a public key file, or refuse it.
 *
 * @param path - The file to read.
 * @throws InvalidPublicKeyFileError for anything that is not a usable Ed25519 public key.
 */
export function readIssuerPublicKeyFile(path: string): LoadedIssuerPublicKey {
  // A key file arrives from wherever the evidence did, so it is read the way the evidence is read:
  // bounded, regular files only, and every refusal named rather than collapsed into "unreadable".
  const read = readBoundedFile(path, PUBLIC_KEY_FILE_MAX_BYTES);
  if (read.kind === 'absent') {
    throw new InvalidPublicKeyFileError(path, 'there is no file at this path');
  }
  if (read.kind === 'refused') {
    const reason =
      read.refusal === 'symbolic_link'
        ? 'it is a symbolic link, and this reads regular files only'
        : read.refusal === 'not_a_regular_file'
          ? `it is not a regular file (${read.detail})`
          : read.refusal === 'too_large'
            ? `it is larger than a key file can be (${read.detail})`
            : `it could not be read (${read.detail})`;
    throw new InvalidPublicKeyFileError(path, reason);
  }
  // The same admission rules the evidence documents get, for the same reason: this file arrives
  // from outside, and a key file whose members are ambiguous describes two different keys depending
  // on which parser reads it.
  const admitted = parseStrictJson(read.bytes);
  if (admitted.status === 'refused') {
    throw new InvalidPublicKeyFileError(path, KEY_FILE_REFUSALS[admitted.refusal]);
  }
  const parsed: unknown = admitted.value;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new InvalidPublicKeyFileError(path, 'it does not hold a key object');
  }

  const file = parsed as Partial<IssuerPublicKeyFileV1>;
  if (file.algorithm !== PUBLIC_KEY_ALGORITHM) {
    throw new InvalidPublicKeyFileError(
      path,
      `algorithm must be ${PUBLIC_KEY_ALGORITHM}, this example verifies nothing else`,
    );
  }
  if (typeof file.kid !== 'string' || file.kid.length === 0) {
    throw new InvalidPublicKeyFileError(path, 'it has no key identifier');
  }
  if (typeof file.issuer !== 'string' || file.issuer.length === 0) {
    throw new InvalidPublicKeyFileError(path, 'it names no issuer');
  }
  // Checked as hex before decoding, because the decoder discards characters it does not recognise:
  // a damaged field would otherwise decode to a shorter, entirely different key.
  if (typeof file.publicKey !== 'string' || !PUBLIC_KEY_HEX.test(file.publicKey)) {
    throw new InvalidPublicKeyFileError(path, 'its public key is not 32 bytes of hex');
  }

  return {
    publicKey: Uint8Array.from(Buffer.from(file.publicKey, 'hex')),
    algorithm: file.algorithm,
    kid: file.kid,
    issuer: file.issuer,
  };
}
