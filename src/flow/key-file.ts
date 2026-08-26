/**
 * Reading and writing key files, with one rule: an existing key file is never replaced.
 *
 * The dangerous shape for key storage is a loader that treats every failure as "no key yet". A
 * malformed byte, a truncated write, a half-finished edit, or a file from a different tool then
 * looks identical to a first run, and the caller generates a new key over the top of one that may
 * hold funds or may be the identity other parties already recognise. The original is gone, and
 * nothing reported that anything was lost.
 *
 * So absence and invalidity are kept apart here. Absence, and only absence, means no key exists
 * yet. Anything else is refused with the path and the reason, the file is left exactly as it was,
 * and the person decides what happens to it. New files are created exclusively, so a key that
 * appeared between the check and the write is never overwritten either.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseStrictJson, type StrictJsonRefusal } from '../strict-json.ts';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

/** Path as shown in messages: relative to the repository, so no local directory layout is printed. */
export function displayKeyPath(path: string): string {
  return path.startsWith(APP_ROOT) ? `.${path.slice(APP_ROOT.length)}` : path;
}

/** An existing key file that could not be loaded. Never raised for a file that does not exist. */
export class InvalidKeyFileError extends Error {
  readonly path: string;
  readonly reason: string;
  constructor(path: string, reason: string) {
    super(
      `Existing key file is invalid. It was not modified. ` +
        `Move or repair ${displayKeyPath(path)} explicitly before continuing.\n` +
        `  reason: ${reason}`,
    );
    this.name = 'InvalidKeyFileError';
    this.path = path;
    this.reason = reason;
  }
}

/** Refuse an existing key file. Callers use this instead of falling back to generating a key. */
export function refuseKeyFile(path: string, reason: string): never {
  throw new InvalidKeyFileError(path, reason);
}

function isFileNotFound(e: unknown): boolean {
  return (e as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';
}

/**
 * Read a key file.
 *
 * @param path - The key file to read.
 * @returns Its contents, or `undefined` when the file does not exist.
 * @throws InvalidKeyFileError when the file exists and cannot be read.
 */
export function readKeyFile(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch (e) {
    if (isFileNotFound(e)) return undefined;
    refuseKeyFile(path, `it could not be read (${(e as Error).message.split('\n')[0]})`);
  }
}

/**
 * Write a key file that must not already exist.
 *
 * @param path - Where to write.
 * @param contents - What to write.
 * @throws InvalidKeyFileError when a file is already there, which is never overwritten.
 */
export function writeNewKeyFile(path: string, contents: string): void {
  try {
    writeFileSync(path, contents, { mode: 0o600, flag: 'wx' });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') {
      refuseKeyFile(path, 'a key file appeared at this path and was not replaced');
    }
    throw e;
  }
}

/**
 * Parse a key file as JSON.
 *
 * @param path - The file the text came from, named in any failure.
 * @param text - The file contents.
 * @throws InvalidKeyFileError when the contents are not JSON.
 */
export function parseKeyFileJson(path: string, text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (e) {
    refuseKeyFile(path, `it is not valid JSON (${(e as Error).message.split('\n')[0]})`);
  }
}

/** Why a key file was not admitted, said in the words a reader of the message needs. */
const STRICT_REFUSALS: Readonly<Record<StrictJsonRefusal, string>> = {
  invalid_utf8: 'it is not valid UTF-8, and repairing the bytes would change what it declares',
  not_json: 'it is not valid JSON',
  scan_incomplete: 'it is not valid JSON',
  duplicate_member:
    'it declares the same member twice, so what it names depends on the parser reading it',
  depth_limit_exceeded: 'it nests deeper than a key file is read',
};

/**
 * Read and admit a key file under the same rules a document from outside gets.
 *
 * WHY THE STRICTER PATH. `readKeyFile` decodes as UTF-8 with replacement, so bytes that are not
 * text arrive as text nobody wrote, and `JSON.parse` keeps the last of two members with the same
 * name, so a file declaring one twice names different things to different parsers. For a document
 * that decides which key a run signs with, neither is a difference to resolve quietly: both are
 * refused, and the file is left exactly as it is.
 *
 * These files are written by this process into a private directory rather than handed over by
 * another party, so what this guards against is damage and ambiguity rather than a hostile
 * directory. The rule is the same either way: never reinterpret, never replace.
 *
 * @param path - The key file to read.
 * @returns The admitted JSON value, or `undefined` when the file does not exist.
 * @throws InvalidKeyFileError when the file exists and cannot be admitted.
 */
export function readAdmittedKeyFile(path: string): unknown {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    if (isFileNotFound(e)) return undefined;
    refuseKeyFile(path, `it could not be read (${(e as Error).message.split('\n')[0]})`);
  }
  const admitted = parseStrictJson(bytes);
  if (admitted.status === 'refused') refuseKeyFile(path, STRICT_REFUSALS[admitted.refusal]);
  return admitted.value;
}
