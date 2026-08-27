/**
 * Crash-durability of the live-run write paths, at each fsync/rename/publish boundary named in
 * `durable-write.ts`.
 *
 * Every case injects a fault at exactly one named boundary — via the test-only
 * `__testOnlyFaultInjector` seam, never by patching `node:fs` globally — and inspects the
 * filesystem state left behind, so each claim this module's own doc comments make is proven rather
 * than assumed.
 */
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { writeFileDurably, isCrossDeviceError } from './flow/durable-write.ts';
import { writeEvidenceTransactionally, prepareRunOutputs, type EvidenceLayout } from './flow/issue-record.ts';
import { readIssuerPublicKeyFile } from './flow/public-key-file.ts';
import { resolveIssuerKey } from './flow/issuer-key.ts';
import type { EvidenceArtifact } from './flow/presence.ts';

beginAcceptanceSuite('durability');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

const temporaryDirectories: string[] = [];
function freshDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'peac-durability-'));
  temporaryDirectories.push(dir);
  return dir;
}

/** A tiny, valid evidence layout: content does not matter for these boundary tests. */
function sampleLayout(): EvidenceLayout {
  const files = new Map<EvidenceArtifact, Uint8Array>();
  files.set('record.jws', new TextEncoder().encode('synthetic-record\n'));
  files.set('chain-observation.json', new TextEncoder().encode('{}\n'));
  return { jws: 'synthetic-record', files };
}

/** Every `.tmp-*` staging directory currently present directly under `parent`. */
function stagingEntriesIn(parent: string): string[] {
  if (!existsSync(parent)) return [];
  return readdirSync(parent).filter((name) => name.startsWith('.tmp-'));
}

recordExecution('DURABILITY-001');
{
  const dir = freshDir();
  const path = join(dir, 'a-file.txt');
  writeFileDurably(path, new TextEncoder().encode('hello'));
  check('a durably written file reads back with the exact bytes written', readFileSync(path, 'utf8') === 'hello');

  let threw = false;
  try {
    writeFileDurably(path, new TextEncoder().encode('overwrite attempt'));
  } catch (e) {
    threw = (e as NodeJS.ErrnoException).code === 'EEXIST';
  }
  check('writeFileDurably refuses to overwrite an existing file (EEXIST)', threw);
  check(
    'the original content is unchanged after the refused overwrite attempt',
    readFileSync(path, 'utf8') === 'hello',
  );
}

recordExecution('DURABILITY-002');
{
  const parent = freshDir();
  const finalDirectory = join(parent, 'evidence');
  await writeEvidenceTransactionally({
    finalDirectory,
    layout: sampleLayout(),
    finalize: async () => {},
  });
  check('the final directory exists after an ordinary publish', existsSync(finalDirectory));
  check(
    'every file in the layout is present with the correct content',
    readFileSync(join(finalDirectory, 'record.jws'), 'utf8') === 'synthetic-record\n' &&
      readFileSync(join(finalDirectory, 'chain-observation.json'), 'utf8') === '{}\n',
  );
  check('no staging directory is left behind after a successful publish', stagingEntriesIn(parent).length === 0);
}

{
  // The one-level-deep invariant `writeEvidenceTransactionally` relies on for complete
  // directory-fsync coverage is asserted at runtime, not only relied on as a type-level fact
  // about `EvidenceArtifact`. A path nested two directories deep is smuggled in via a cast here —
  // the type system already refuses it honestly, so this is the one place that matters is proven
  // to fail loudly rather than silently skip fsyncing an intermediate directory.
  const parent = freshDir();
  const finalDirectory = join(parent, 'evidence');
  const twoLevelLayout: EvidenceLayout = {
    jws: 'synthetic-record',
    files: new Map([['a/b/c.txt' as EvidenceArtifact, new TextEncoder().encode('x')]]),
  };
  let threw = false;
  let message = '';
  try {
    await writeEvidenceTransactionally({ finalDirectory, layout: twoLevelLayout, finalize: async () => {} });
  } catch (e) {
    threw = true;
    message = (e as Error).message;
  }
  check(
    'a two-directory-deep artifact path is refused loudly by the asserted invariant, not silently under-fsynced',
    threw && message.includes('nested more than one directory deep'),
    message,
  );
  check('nothing was published for the refused layout', !existsSync(finalDirectory));
}

recordExecution('DURABILITY-003');
{
  const parent = freshDir();
  const finalDirectory = join(parent, 'evidence');
  let threw = false;
  try {
    await writeEvidenceTransactionally({
      finalDirectory,
      layout: sampleLayout(),
      finalize: async () => {},
      __testOnlyFaultInjector: (point) => {
        if (point === 'before-rename') throw new Error('synthetic crash before rename');
      },
    });
  } catch {
    threw = true;
  }
  check('the injected fault before rename propagates', threw);
  check('the final directory does not exist', !existsSync(finalDirectory));
  const staged = stagingEntriesIn(parent);
  check('the staged directory is left in place, not deleted', staged.length === 1, JSON.stringify(staged));
  if (staged[0] !== undefined) {
    check(
      'the staged directory itself is fully written (durable before the fault)',
      readFileSync(join(parent, staged[0], 'record.jws'), 'utf8') === 'synthetic-record\n',
    );
  }
}

recordExecution('DURABILITY-004');
{
  const parent = freshDir();
  const finalDirectory = join(parent, 'evidence');
  let threw = false;
  try {
    await writeEvidenceTransactionally({
      finalDirectory,
      layout: sampleLayout(),
      finalize: async () => {},
      __testOnlyFaultInjector: (point) => {
        if (point === 'after-rename') throw new Error('synthetic crash after rename');
      },
    });
  } catch {
    threw = true;
  }
  check('the injected fault after rename propagates (the caller sees a failure)', threw);
  check(
    'the final directory nonetheless exists and is complete: the rename already durably happened',
    existsSync(finalDirectory) &&
      readFileSync(join(finalDirectory, 'record.jws'), 'utf8') === 'synthetic-record\n',
  );
  check('no staging directory is left behind', stagingEntriesIn(parent).length === 0);
}

recordExecution('DURABILITY-005');
{
  const parent = freshDir();
  const finalDirectory = join(parent, 'evidence');
  let threw = false;
  try {
    await writeEvidenceTransactionally({
      finalDirectory,
      layout: sampleLayout(),
      finalize: async () => {},
      __testOnlyFaultInjector: (point) => {
        if (point === 'after-parent-directory-fsync') throw new Error('synthetic crash at the last boundary');
      },
    });
  } catch {
    threw = true;
  }
  check('the injected fault at the last boundary propagates', threw);
  check(
    'the final directory is complete regardless: every earlier boundary already made it durable',
    existsSync(finalDirectory) &&
      readFileSync(join(finalDirectory, 'chain-observation.json'), 'utf8') === '{}\n',
  );
}

recordExecution('DURABILITY-006');
{
  const dir = freshDir();
  const issuerKey = await resolveIssuerKey('fixture');
  const publicKeyFile = join(dir, 'issuer.pub.json');
  const evidenceDirectory = join(dir, 'evidence'); // never created in this test

  const loaded = prepareRunOutputs({ evidenceDirectory, publicKeyFile, issuerKey });
  check(
    'prepareRunOutputs returns the key file read back correctly',
    loaded.kid === issuerKey.kid && loaded.issuer === issuerKey.iss,
  );

  const dir2 = freshDir();
  const publicKeyFile2 = join(dir2, 'issuer.pub.json');
  let threw = false;
  try {
    prepareRunOutputs({
      evidenceDirectory: join(dir2, 'evidence'),
      publicKeyFile: publicKeyFile2,
      issuerKey,
      __testOnlyFaultInjector: (point) => {
        if (point === 'after-key-file-fsync') throw new Error('synthetic crash after the key file fsync');
      },
    });
  } catch {
    threw = true;
  }
  check('the injected fault after the key-file fsync propagates', threw);
  check(
    'the key file is nonetheless durable and readable: its own fsync already completed',
    readIssuerPublicKeyFile(publicKeyFile2).kid === issuerKey.kid,
  );
}

recordExecution('DURABILITY-007');
{
  check(
    "isCrossDeviceError recognises Node's EXDEV error shape",
    isCrossDeviceError(Object.assign(new Error('cross-device link'), { code: 'EXDEV' })),
  );
  check(
    'isCrossDeviceError does not misclassify an unrelated error',
    !isCrossDeviceError(new Error('some other failure')) && !isCrossDeviceError(null) && !isCrossDeviceError('EXDEV'),
  );

  const parent = freshDir();
  const finalDirectory = join(parent, 'evidence');
  let message = '';
  try {
    await writeEvidenceTransactionally({
      finalDirectory,
      layout: sampleLayout(),
      finalize: async () => {},
      __testOnlyFaultInjector: (point) => {
        if (point === 'before-rename') {
          throw Object.assign(new Error('EXDEV: cross-device link not permitted'), { code: 'EXDEV' });
        }
      },
    });
  } catch (e) {
    message = (e as Error).message;
  }
  check(
    'a rename that would cross a filesystem boundary fails closed with a clear, named reason',
    message.includes('filesystem boundary') && message.includes('EXDEV'),
    message,
  );
  check('nothing was published: the final directory does not exist', !existsSync(finalDirectory));
  check(
    'the staged directory is left in place, never silently discarded or copied around the failure',
    stagingEntriesIn(parent).length === 1,
  );
}

for (const directory of temporaryDirectories) rmSync(directory, { recursive: true, force: true });

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
