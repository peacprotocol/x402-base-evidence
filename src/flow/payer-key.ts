/**
 * The test-network payer key.
 *
 * A payer key must survive between runs. Regenerating one per run would strand every test-USDC
 * balance already sent to the previous address, so the key is created once, written to a
 * gitignored directory with owner-only permissions, and reused afterwards. Only the address is
 * ever printed: a key that appears in output ends up in logs, terminal history and pasted
 * transcripts.
 *
 * WHAT THE FILE HOLDS. The 32-byte secp256k1 private key, as lowercase hex behind a `0x` prefix,
 * inside a small JSON object that also names what the file is. The address is not stored: it is
 * recomputed from the private key on every load through the same published account derivation the
 * signing path uses, so the file never has to be trusted for anything but the private half, and a
 * file assembled from mismatched halves cannot exist.
 *
 * A key file that exists but cannot be loaded is refused, never replaced: see `key-file.ts`. New
 * files are created exclusively, so a key that appeared between the check and the write is never
 * overwritten either.
 */
import { chmodSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { privateKeyToAccount, type PrivateKeyAccount } from 'viem/accounts';
import { parseKeyFileJson, readKeyFile, refuseKeyFile, writeNewKeyFile } from './key-file.ts';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const KEY_DIR = join(APP_ROOT, '.local', 'keys');

/** Where the payer key lives. Gitignored, and the one file a person must not lose or share. */
export const PAYER_KEY_PATH = join(KEY_DIR, 'payer.json');

/** Exactly the 32 bytes of a secp256k1 private key, as hex behind a 0x prefix. */
const PRIVATE_KEY_HEX = /^0x[0-9a-fA-F]{64}$/;

interface StoredPayerKey {
  readonly note: string;
  readonly privateKeyHex: string;
}

/**
 * Create the payer key file and return its account.
 *
 * @param path - Where to write the key file. Defaults to the test-network payer key.
 * @throws InvalidKeyFileError when a key file is already there, which is never overwritten.
 */
export function createPayerKeyFile(path: string = PAYER_KEY_PATH): PrivateKeyAccount {
  const privateKeyHex = `0x${randomBytes(32).toString('hex')}` as const;
  // Derived before anything is written, so a byte sequence the curve rejects is discovered here
  // and no file is created for it.
  const account = privateKeyToAccount(privateKeyHex);

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const payload: StoredPayerKey = {
    note: 'Test-network payer key for the Base Sepolia reference flow. Never fund on mainnet.',
    privateKeyHex,
  };
  writeNewKeyFile(path, `${JSON.stringify(payload, null, 2)}\n`);
  // Set separately as well, in case the file's mode did not come from the create above.
  chmodSync(path, 0o600);
  return account;
}

/**
 * Load the payer key from its file.
 *
 * @param path - Where to read the key file from. Defaults to the test-network payer key.
 * @returns The account, or `undefined` when the file does not exist.
 * @throws InvalidKeyFileError when the file exists and does not hold a usable key.
 */
export function loadPayerAccount(path: string = PAYER_KEY_PATH): PrivateKeyAccount | undefined {
  const text = readKeyFile(path);
  if (text === undefined) return undefined;

  const stored = parseKeyFileJson(path, text);
  if (typeof stored !== 'object' || stored === null || Array.isArray(stored)) {
    refuseKeyFile(path, 'it does not hold a key object');
  }
  const key = stored as Partial<StoredPayerKey>;
  // Validated as prefixed hex before derivation, because a decoder that discards characters it
  // does not recognise would otherwise reshape a damaged file into a different key.
  if (typeof key.privateKeyHex !== 'string' || !PRIVATE_KEY_HEX.test(key.privateKeyHex)) {
    refuseKeyFile(path, 'its private key is not 32 bytes of 0x-prefixed hex');
  }
  try {
    // Rejects a value outside the curve order, so a damaged field cannot load as a working key.
    return privateKeyToAccount(key.privateKeyHex as `0x${string}`);
  } catch {
    // The library's message is not echoed: this diagnostic surfaces in command output, and fixed
    // prose says everything a reader can act on about a key file that must not be quoted anyway.
    refuseKeyFile(path, 'it is not a usable key: the curve library refused the private key');
  }
}

/**
 * Load the payer key, creating it only when no key file exists.
 *
 * @param path - Where the key file lives. Defaults to the test-network payer key.
 * @throws InvalidKeyFileError when a key file exists and cannot be loaded. It is left untouched.
 */
export function resolvePayerAccount(path: string = PAYER_KEY_PATH): PrivateKeyAccount {
  return loadPayerAccount(path) ?? createPayerKeyFile(path);
}
