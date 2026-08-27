/**
 * Terminal-safe rendering, and the public key file's closed schema and PEAC-exact field
 * constraints.
 *
 * Every case below feeds a hostile string through the render path a reader's terminal actually
 * sees, or a hostile key file through the reader that admits one, and asserts what came out: a
 * control character never survives as itself, and a field outside PEAC's own grammar is refused
 * rather than accepted as a bare non-empty string.
 */
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { issue } from '@peac/protocol';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { escapeForTerminal, terminalSafe } from './terminal-safe.ts';
import { readIssuerPublicKeyFile, InvalidPublicKeyFileError } from './flow/public-key-file.ts';
import { runOnce, buildEvidence } from './flow/fixture-e2e.ts';
import { resolveIssuerKey } from './flow/issuer-key.ts';
import { writeEvidence, type EvidenceLayout } from './flow/issue-record.ts';
import { verifyEvidence, formatReport } from './flow/verify-evidence.ts';
import type { EvidenceArtifact } from './flow/presence.ts';

beginAcceptanceSuite('terminal-safe');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

/** Whether a rendered string contains the RAW character, un-escaped. */
const containsRaw = (rendered: string, raw: string): boolean => rendered.includes(raw);

recordExecution('TERMINAL-001');
{
  const hostile = 'before\x00\x01\x02\x1fafter';
  const rendered = escapeForTerminal(hostile);
  check(
    'every C0 control character is escaped, never left as a raw control byte',
    !containsRaw(rendered, '\x00') &&
      !containsRaw(rendered, '\x01') &&
      !containsRaw(rendered, '\x02') &&
      !containsRaw(rendered, '\x1f') &&
      rendered.includes('\\u0000') &&
      rendered.includes('\\u0001') &&
      rendered.includes('\\u0002') &&
      rendered.includes('\\u001f'),
    JSON.stringify(rendered),
  );
  const del = escapeForTerminal('x\x7fy');
  check(
    'DEL is escaped, never left as a raw control byte',
    !containsRaw(del, '\x7f') && del.includes('\\u007f'),
    JSON.stringify(del),
  );
  const c1 = escapeForTerminal('x\x9ay');
  check(
    'a C1 control character is escaped, never left as a raw control byte',
    !containsRaw(c1, '\x9a') && c1.includes('\\u009a'),
    JSON.stringify(c1),
  );
}

recordExecution('TERMINAL-002');
{
  const hostile = 'before\x1b[31mRED\x1b[0mafter';
  const rendered = escapeForTerminal(hostile);
  check(
    'an ESC byte is escaped, never interpreted as a terminal escape sequence',
    !containsRaw(rendered, '\x1b') && rendered.includes('\\u001b'),
    JSON.stringify(rendered),
  );
  check(
    'the escaped ANSI sequence is inert text, not an ANSI code point',
    rendered === 'before\\u001b[31mRED\\u001b[0mafter',
    rendered,
  );
}

recordExecution('TERMINAL-003');
{
  const hostile = 'ok    real check\r\n  ok    FORGED CHECK: everything is fine';
  const rendered = escapeForTerminal(hostile);
  check(
    'CR and LF are escaped, never left as raw bytes that render as a forged additional line',
    !containsRaw(rendered, '\r') &&
      !containsRaw(rendered, '\n') &&
      rendered.includes('\\u000d') &&
      rendered.includes('\\u000a'),
    JSON.stringify(rendered),
  );
  check(
    'the escaped text is a single line',
    rendered.split('\n').length === 1,
    JSON.stringify(rendered.split('\n')),
  );
}

recordExecution('TERMINAL-004');
{
  const rlo = '\u202eattack';
  const rendered = escapeForTerminal(rlo);
  check(
    'a right-to-left-override character is escaped, never left to reorder surrounding text',
    !containsRaw(rendered, '\u202e') && rendered.includes('\\u202e'),
    JSON.stringify(rendered),
  );
  const isolates = '\u2066isolated\u2069';
  const renderedIsolates = escapeForTerminal(isolates);
  check(
    'directional isolate controls are escaped the same way',
    !containsRaw(renderedIsolates, '\u2066') &&
      !containsRaw(renderedIsolates, '\u2069') &&
      renderedIsolates.includes('\\u2066') &&
      renderedIsolates.includes('\\u2069'),
    JSON.stringify(renderedIsolates),
  );
  check(
    'ordinary printable text is never altered',
    terminalSafe('https://origin.example.test') === 'https://origin.example.test',
  );
  check(
    'length bounding applies AFTER escaping, not before',
    terminalSafe('\x1b'.repeat(5), 10).length <= 13, // 10 chars + '...'
    terminalSafe('\x1b'.repeat(5), 10),
  );
}

function withKeyFile<T>(contents: unknown, fn: (path: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'peac-terminal-keyfile-'));
  try {
    const path = join(dir, 'key.json');
    writeFileSync(path, JSON.stringify(contents));
    return fn(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const VALID_KEY_FILE = {
  algorithm: 'Ed25519',
  kid: 'k1',
  issuer: 'https://origin.example.test',
  publicKey: 'aa'.repeat(32),
  note: 'test key',
};

function rejectedReason(contents: unknown): string {
  try {
    withKeyFile(contents, (path) => readIssuerPublicKeyFile(path));
    return '';
  } catch (e) {
    if (e instanceof InvalidPublicKeyFileError) return e.reason;
    throw e;
  }
}

recordExecution('TERMINAL-005');
{
  const reason = rejectedReason({ ...VALID_KEY_FILE, unexpectedMember: 'anything' });
  check(
    'a public key file declaring an unknown member is refused as a closed schema',
    reason.length > 0,
    reason,
  );
  const accepted = withKeyFile(VALID_KEY_FILE, (path) => {
    try {
      readIssuerPublicKeyFile(path);
      return true;
    } catch {
      return false;
    }
  });
  check('the same file with only the declared members is accepted', accepted);
}

recordExecution('TERMINAL-006');
{
  const bareString = rejectedReason({ ...VALID_KEY_FILE, issuer: 'not-a-uri' });
  check(
    'a bare non-empty string issuer is refused, not accepted',
    bareString.length > 0,
    bareString,
  );
  const trailingSlash = rejectedReason({
    ...VALID_KEY_FILE,
    issuer: 'https://origin.example.test/',
  });
  check(
    'an issuer that is not the bare https origin is refused',
    trailingSlash.length > 0,
    trailingSlash,
  );
  const didAccepted = withKeyFile({ ...VALID_KEY_FILE, issuer: 'did:web:example.com' }, (path) => {
    try {
      readIssuerPublicKeyFile(path);
      return true;
    } catch {
      return false;
    }
  });
  check('a canonical did: issuer is accepted', didAccepted);
}

recordExecution('TERMINAL-007');
{
  const oversized = rejectedReason({ ...VALID_KEY_FILE, kid: 'k'.repeat(257) });
  check(
    'a kid exceeding 256 UTF-8 bytes is refused, not accepted as a bare non-empty string',
    oversized.length > 0,
    oversized,
  );
  const atBound = withKeyFile({ ...VALID_KEY_FILE, kid: 'k'.repeat(256) }, (path) => {
    try {
      readIssuerPublicKeyFile(path);
      return true;
    } catch {
      return false;
    }
  });
  check('a kid at exactly 256 UTF-8 bytes is accepted', atBound);
}

/**
 * The real verifier, not just the escaping primitive.
 *
 * PEAC's `kid` rule bounds only UTF-8 byte length and well-formed Unicode (no lone surrogate); it
 * does not forbid control characters, CR/LF, ESC/ANSI, or bidi overrides. A genuinely re-signed
 * record can therefore carry a `kid` that would forge a report line or inject a terminal escape
 * sequence if it ever reached printed output unescaped — which is exactly what
 * `verifyEvidence`/`formatReport` are checked against here, not just `escapeForTerminal` in
 * isolation.
 */
const HOSTILE_KID =
  'k1\r\n  ok    FORGED CHECK: everything is fine\x1b[31mRED\x1b[0m\u202eattack';

const issuerKey = await resolveIssuerKey('fixture');
const honestRun = await runOnce();
const honestLayout = await buildEvidence(honestRun);

async function resignWithHostileKid(): Promise<string> {
  const [, payload] = honestLayout.jws.split('.');
  if (payload === undefined) throw new Error('the honest record has no payload segment');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
    iss: string;
    kind: 'evidence' | 'challenge';
    type: string;
    jti: string;
    pillars: readonly string[];
    occurred_at: string;
    extensions: Record<string, Record<string, unknown>>;
  };
  const result = await issue({
    iss: claims.iss,
    kind: claims.kind,
    type: claims.type,
    privateKey: issuerKey.privateKey,
    kid: HOSTILE_KID,
    jti: claims.jti,
    // The decoded pillar list is already a valid enum member; it just is not literally typed as
    // one after a JSON round trip.
    pillars: claims.pillars as any,
    occurred_at: claims.occurred_at,
    extensions: claims.extensions,
  });
  return result.jws;
}

const hostileTemporaryDirectories: string[] = [];
function evidenceWithHostileRecord(jws: string): string {
  const directory = mkdtempSync(join(tmpdir(), 'peac-terminal-kid-'));
  hostileTemporaryDirectories.push(directory);
  const files = new Map<EvidenceArtifact, Uint8Array>(honestLayout.files);
  files.set('record.jws', new TextEncoder().encode(`${jws}\n`));
  const layout: EvidenceLayout = { jws, files };
  writeEvidence(directory, layout);
  return directory;
}

/** Whether rendered report text is free of every raw hostile byte the kid carried. */
function freeOfRawHostileBytes(text: string): boolean {
  return (
    !text.includes('\r') &&
    !text.includes('\x1b') &&
    !text.includes('\u202e') &&
    // The forged line must never appear as an actual report line: an escaped rendering keeps it
    // as inert `\uXXXX` text glued to whatever came before/after it on one physical line.
    !text.split('\n').some((line) => /^\s*ok\s+FORGED CHECK/.test(line))
  );
}

recordExecution('TERMINAL-008');
{
  const jws = await resignWithHostileKid();
  const directory = evidenceWithHostileRecord(jws);
  const report = await verifyEvidence(directory, issuerKey.publicKey);
  const signatureCheck = report.checks.find((c) => c.name === 'record signature and schema');
  check(
    'the record signature itself still verifies (this is a genuine re-signature)',
    signatureCheck?.ok === true,
    JSON.stringify(signatureCheck),
  );
  check(
    // The detail is bounded (80 characters after escaping), so the tail of a hostile string this
    // long — including the bidi override near the end — is cut off by the `...` truncation before
    // it would ever appear; what matters is that nothing RAW survives, truncated or not, and that
    // the escape markers within the retained prefix are genuinely escaped rather than raw.
    "the hostile kid appears only as escaped text in the check's own detail (no raw bytes, truncated or not)",
    signatureCheck !== undefined &&
      freeOfRawHostileBytes(signatureCheck.detail) &&
      signatureCheck.detail.includes('\\u000d') &&
      signatureCheck.detail.includes('\\u000a') &&
      signatureCheck.detail.includes('\\u001b'),
    JSON.stringify(signatureCheck),
  );
  const rendered = formatReport(directory, report);
  check(
    'the full rendered report (default, no supplied key) carries no raw hostile bytes or forged line',
    freeOfRawHostileBytes(rendered),
    JSON.stringify(rendered),
  );
}

recordExecution('TERMINAL-009');
{
  const jws = await resignWithHostileKid();
  const directory = evidenceWithHostileRecord(jws);
  const report = await verifyEvidence(directory, issuerKey.publicKey, {
    algorithm: 'Ed25519',
    kid: HOSTILE_KID, // matches the record exactly, so the PASS branch (not the FAIL branch) fires
    issuer: issuerKey.iss,
  });
  const identifierCheck = report.checks.find(
    (c) => c.name === 'supplied key identifier matches the record',
  );
  check(
    'the supplied-key identifier check passes (the PASS branch, proving it is also escaped)',
    identifierCheck?.ok === true,
    JSON.stringify(identifierCheck),
  );
  check(
    "the hostile kid appears only as escaped text in that check's detail too",
    identifierCheck !== undefined && freeOfRawHostileBytes(identifierCheck.detail),
    JSON.stringify(identifierCheck),
  );
  const rendered = formatReport(directory, report);
  check(
    'the full rendered report (--public-key supplied-key path) carries no raw hostile bytes or forged line',
    freeOfRawHostileBytes(rendered),
    JSON.stringify(rendered),
  );
}

for (const directory of hostileTemporaryDirectories) rmSync(directory, { recursive: true, force: true });

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
