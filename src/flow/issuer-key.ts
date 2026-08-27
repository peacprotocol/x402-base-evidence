/**
 * Record-issuing keys for the two run modes.
 *
 * The offline path uses a fixed key so a repeated run produces identical bytes. That key is
 * written here in the source, in the open, because it is test material: it protects nothing, it is
 * published in a public repository, and treating it as a secret would be theatre. It is refused
 * outside the fixture mode so it cannot be reached by accident on a live run.
 *
 * The live path generates a key into a gitignored directory with owner-only permissions and
 * keeps it across runs, so the same issuer can be recognised between runs. It is a demonstration
 * key on a test network, not an organizational identity.
 *
 * WHAT THE KEY FILE BINDS. The issuer a record claims is not a free-standing configuration value:
 * it is the identity a key has been signing under. A key file that stored only the key would let
 * one key and one key identifier claim `https://a.example` on Monday and `https://b.example` on
 * Tuesday, purely because an environment variable changed, and both records would verify under the
 * same public key. A reader holding the two would have no way to tell which claim the key holder
 * meant, and this example would have demonstrated exactly the ambiguity it exists to avoid.
 *
 * So the issuer is written into the key file when the key is created, and every later run must be
 * configured for that same issuer. A disagreement stops the run and changes nothing on disk: the
 * two ways out are to configure the issuer the key already claims, or to set the key aside so a new
 * one is created for the new issuer. Neither is guessed at here, because both are decisions about
 * what an identity means, and only the person running it can make them.
 *
 * WHAT VERIFICATION MEANS HERE. A record that verifies against one of these keys shows that its
 * contents are intact relative to the key material supplied to the verifier. It does not show that
 * the key belongs to any particular organization, and nothing in this example establishes that.
 *
 * HOW THE KEY IS CREATED. Through the published surface of the protocol's own crypto package:
 * `generateKeypair` produces the 32-byte private key and its public key, and `derivePublicKey`
 * recomputes the public key from the private one on reload, so the stored file never has to be
 * trusted for anything but the private half. Nothing here reaches past those functions into
 * internals, and no key bytes are assembled by hand.
 */
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { derivePublicKey, generateKeypair } from '@peac/crypto';
import { displayKeyPath, readAdmittedKeyFile, refuseKeyFile, writeNewKeyFile } from './key-file.ts';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const KEY_DIR = join(APP_ROOT, '.local', 'keys');

/** Where the live-mode issuer key lives. Gitignored, and a demonstration key rather than an identity. */
export const ISSUER_KEY_PATH = join(KEY_DIR, 'issuer.json');

export type RunMode = 'fixture' | 'live';

export interface IssuerKey {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
  /** Key identifier carried in the record header. */
  readonly kid: string;
  /** Issuer identity claimed by the record. */
  readonly iss: string;
}

/**
 * TEST-ONLY issuer key for the offline path. Not a secret, not reused anywhere, and never valid
 * for anything beyond this example's fixture output.
 */
const FIXTURE_ISSUER_PRIVATE_KEY = Uint8Array.from(
  Array.from({ length: 32 }, (_, i) => (i * 11 + 5) % 256),
);

export const FIXTURE_ISSUER = 'https://origin.example.test';
export const FIXTURE_KID = 'base-payment-evidence-fixture-key-1';

/**
 * The issuer identity a live run claims. REQUIRED in live mode, with no default: the issuer is
 * the identity the operator's records claim, and no fictional or project-owned fallback may
 * stand in for it. A live run without an explicit issuer stops before any key is created and
 * before any payment is attemptable. The fixture issuer above belongs to the fixture mode only.
 */
export const LIVE_ISSUER_ENV = 'PEAC_EXAMPLE_ISSUER';

interface StoredIssuerKey {
  readonly note: string;
  readonly kid: string;
  /** The issuer this key has been claiming. Written when the key is created, never rewritten. */
  readonly issuer: string;
  readonly privateKeyHex: string;
}

/** Exactly the 32 bytes of an Ed25519 private key, written as lower or upper case hex. */
const PRIVATE_KEY_HEX = /^[0-9a-fA-F]{64}$/;

/** A configured issuer this example will not sign under. Never raised about a key file. */
export class IssuerConfigurationError extends Error {
  constructor(reason: string) {
    super(
      `The configured issuer cannot be used: ${reason}\n` +
        `  Set ${LIVE_ISSUER_ENV} to an absolute http or https URL naming the party that issues ` +
        'these records. A live run has no default issuer.',
    );
    this.name = 'IssuerConfigurationError';
  }
}

/** An existing key already claims a different issuer. Nothing is written and nothing is guessed. */
export class IssuerBindingError extends Error {
  readonly path: string;
  readonly storedIssuer: string;
  readonly configuredIssuer: string;
  constructor(path: string, storedIssuer: string, configuredIssuer: string) {
    super(
      `The issuer key at ${displayKeyPath(path)} records a different issuer. It was not modified, ` +
        'and nothing was signed.\n' +
        `  the key file records : ${storedIssuer}\n` +
        `  this run is configured for: ${configuredIssuer}\n` +
        '  One key claiming two issuers would produce records that verify under the same public\n' +
        '  key while naming different parties. Either configure the issuer this key already\n' +
        '  claims, or move the key file aside so a new key is created for the new issuer.',
    );
    this.name = 'IssuerBindingError';
    this.path = path;
    this.storedIssuer = storedIssuer;
    this.configuredIssuer = configuredIssuer;
  }
}

/**
 * Check that a value can be used as the issuer a record claims.
 *
 * An issuer identifies a party, so it has to be something a reader could resolve: an absolute http
 * or https URL. Credentials and fragments are refused rather than stripped, because this value is
 * signed into a document meant to be handed to someone else, and quietly publishing a trimmed
 * version of what was configured is worse than refusing it.
 *
 * The value is returned exactly as supplied. Nothing is normalized: a trailing slash added here
 * would mean the record claims an issuer nobody configured.
 *
 * @param value - The configured issuer, exactly as it arrived.
 * @throws IssuerConfigurationError when it is not usable as an issuer identity.
 */
export function assertUsableIssuer(value: string): string {
  if (value.length === 0) throw new IssuerConfigurationError('it is empty');
  if (value.length > 256) throw new IssuerConfigurationError('it is longer than 256 characters');
  if (value.trim() !== value) throw new IssuerConfigurationError('it has leading or trailing whitespace');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new IssuerConfigurationError('it is not an absolute URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new IssuerConfigurationError('it is not an http or https URL');
  }
  if (url.username.length > 0 || url.password.length > 0) {
    throw new IssuerConfigurationError('it carries credentials, which would be signed into records');
  }
  if (url.hash.length > 0) throw new IssuerConfigurationError('it carries a fragment');
  return value;
}

/**
 * The issuer a live run claims, taken from the environment and checked before it is used.
 *
 * FAILS CLOSED when the variable is unset: live mode has no default issuer, so an unconfigured
 * run stops here — before any key file is opened or created — rather than signing records that
 * claim an identity nobody configured.
 */
function configuredLiveIssuer(): string {
  const configured = process.env[LIVE_ISSUER_ENV];
  if (configured === undefined) {
    throw new IssuerConfigurationError(`${LIVE_ISSUER_ENV} is not set, and live mode has no default issuer`);
  }
  return assertUsableIssuer(configured);
}

/**
 * The issuer an existing key file records, without creating anything.
 *
 * For readiness checks that must be able to report a binding mismatch BEFORE a run starts,
 * without generating a key as a side effect.
 *
 * @returns The recorded issuer, or `undefined` when no key file exists.
 * @throws InvalidKeyFileError when a file exists and does not hold a usable key.
 */
export function storedIssuerBinding(path: string = ISSUER_KEY_PATH): string | undefined {
  return loadStoredKey(path)?.issuer;
}

/**
 * Load the stored issuer key.
 *
 * @param path - The key file to read.
 * @returns The stored key, or `undefined` when the file does not exist.
 * @throws InvalidKeyFileError when the file exists and does not hold a usable key.
 */
function loadStoredKey(path: string): StoredIssuerKey | undefined {
  const parsed = readAdmittedKeyFile(path);
  if (parsed === undefined) return undefined;

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    refuseKeyFile(path, 'it does not hold a key object');
  }
  const stored = parsed as Partial<StoredIssuerKey>;
  if (typeof stored.kid !== 'string' || stored.kid.length === 0) {
    refuseKeyFile(path, 'it has no key identifier');
  }
  // Validated as hex before decoding, because the decoder discards characters it does not
  // recognise: a damaged field would otherwise decode to a shorter, entirely different key.
  if (typeof stored.privateKeyHex !== 'string' || !PRIVATE_KEY_HEX.test(stored.privateKeyHex)) {
    refuseKeyFile(path, 'its private key is not 32 bytes of hex');
  }
  // A key file written before the issuer was recorded. What issuer it has already claimed is not
  // knowable from the file, and assuming the currently configured one would be inventing exactly
  // the fact this binding exists to establish.
  if (stored.issuer === undefined) {
    refuseKeyFile(
      path,
      'it records no issuer, so the issuer this key has already claimed cannot be established; ' +
        'move it aside so a new key is created, or add the issuer this key has been using if you ' +
        'know it',
    );
  }
  if (typeof stored.issuer !== 'string' || stored.issuer.length === 0) {
    refuseKeyFile(path, 'its issuer is not a non-empty string');
  }
  return {
    note: String(stored.note ?? ''),
    kid: stored.kid,
    issuer: stored.issuer,
    privateKeyHex: stored.privateKeyHex,
  };
}

/**
 * Resolve the issuer key for a run.
 *
 * @param mode - `fixture` returns the fixed test key; `live` reuses or creates the local key.
 * @param path - Where the live-mode key file lives. Defaults to the gitignored local key.
 * @throws IssuerConfigurationError when the configured issuer is not usable as an identity.
 * @throws IssuerBindingError when an existing key records a different issuer. The file is not
 *   modified, and no key is generated.
 */
export async function resolveIssuerKey(
  mode: RunMode,
  path: string = ISSUER_KEY_PATH,
): Promise<IssuerKey> {
  if (mode === 'fixture') {
    return {
      privateKey: FIXTURE_ISSUER_PRIVATE_KEY,
      publicKey: await derivePublicKey(FIXTURE_ISSUER_PRIVATE_KEY),
      kid: FIXTURE_KID,
      iss: FIXTURE_ISSUER,
    };
  }

  // Decided before the key file is opened, so a run configured with an issuer this example will not
  // sign under stops without having touched stored key material at all.
  const iss = configuredLiveIssuer();
  const stored = loadStoredKey(path);
  if (stored !== undefined) {
    if (stored.issuer !== iss) throw new IssuerBindingError(path, stored.issuer, iss);
    const privateKey = Uint8Array.from(Buffer.from(stored.privateKeyHex, 'hex'));
    try {
      return { privateKey, publicKey: await derivePublicKey(privateKey), kid: stored.kid, iss };
    } catch {
      // The library's message is not echoed: this diagnostic surfaces in command output, and
      // fixed prose says everything a reader can act on.
      refuseKeyFile(path, 'its private key is not usable: public-key derivation refused it');
    }
  }

  const generated = await generateKeypair();
  const kid = `payment-evidence-live-${Date.now().toString(36)}`;
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const payload: StoredIssuerKey = {
    note: 'Demonstration key for a test network. Not an organizational identity.',
    kid,
    issuer: iss,
    privateKeyHex: Buffer.from(generated.privateKey).toString('hex'),
  };
  // Written exclusively, so a key file that appeared since the load above is refused rather than
  // replaced, and the issuer recorded here is the one this key will claim from now on.
  writeNewKeyFile(path, `${JSON.stringify(payload, null, 2)}\n`);
  // Set separately as well, in case the file's mode did not come from the create above.
  chmodSync(path, 0o600);
  return { privateKey: generated.privateKey, publicKey: generated.publicKey, kid, iss };
}
