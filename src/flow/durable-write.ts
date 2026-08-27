/**
 * Crash-durable writes on a local POSIX filesystem.
 *
 * WHAT "DURABLE" MEANS HERE. A write returning from `writeFileDurably` means the bytes have been
 * handed to the storage device via `fsync`, not merely to the kernel's page cache: a crash or power
 * loss immediately afterward does not lose them. A directory whose entries were changed — a file
 * created inside it, or a rename that moved a name into or out of it — is durable in the same sense
 * only once THAT directory has also been fsynced, because the file's own durability says nothing
 * about whether the directory entry pointing at it survives a crash.
 *
 * THE SUPPORTED CONTRACT, STATED TRUTHFULLY. This is a single local filesystem's crash-durability
 * story: one write, or one rename, made durable against the process or the machine dying, on the
 * filesystem the path already lives on. It is NOT a cross-host or shared-filesystem guarantee. NFS,
 * SMB and similar network filesystems can accept an `fsync` and still lose the write to a
 * server-side failure the client never observes, and this module has no way to detect that. A
 * `rename` that would cross filesystems (`EXDEV`) is refused rather than silently falling back to a
 * copy, because a copy is not the atomic, no-clobber publish this module exists to provide.
 *
 * WINDOWS. Opening a directory as a file descriptor to `fsync` it is a POSIX operation; Windows has
 * no equivalent reachable through Node's `fs` API (the open fails). `fsyncDirectory` treats that as
 * a no-op rather than a thrown error, which means the directory-entry half of the durability
 * contract above does NOT hold on Windows — only the per-file `fsync` in `writeFileDurably` does,
 * via `FlushFileBuffers`. That gap is stated here rather than left to be discovered.
 */
import { closeSync, fsyncSync, openSync, writeSync } from 'node:fs';

/**
 * Named points along a durable write this repository's tests can interrupt, deterministically,
 * without patching `node:fs` globally. Each name is a boundary this module's own doc comments
 * already claim durability at; a fault-injection test exists to prove the claim rather than to
 * exercise a code path nothing else asserts.
 */
export type FaultInjectionPoint =
  | 'after-file-fsync'
  | 'after-staging-directory-fsync'
  | 'before-rename'
  | 'after-rename'
  | 'after-parent-directory-fsync'
  | 'after-key-file-fsync';

/**
 * A caller supplies this to observe or interrupt a durable write at a named point. Never called in
 * an ordinary run: every production call site passes it through unset, and the functions in this
 * module default it to a no-op.
 */
export interface FaultInjectionHook {
  readonly __testOnlyFaultInjector?: (point: FaultInjectionPoint) => void;
}

/** Call the injector for one point, if a caller supplied one. Never throws on its own. */
export function injectFault(hook: FaultInjectionHook | undefined, point: FaultInjectionPoint): void {
  hook?.__testOnlyFaultInjector?.(point);
}

/**
 * Write bytes to a NEW file, durably: opened exclusively so an existing file at `path` is never
 * overwritten, written, and `fsync`ed before the descriptor closes.
 *
 * @throws an `EEXIST` error if `path` already exists — the same no-clobber behavior a caller
 *   already relies on from `{ flag: 'wx' }`, preserved here rather than loosened for durability.
 */
export function writeFileDurably(path: string, bytes: Uint8Array): void {
  const fd = openSync(path, 'wx');
  try {
    writeSync(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * `fsync` a directory's own entries, so a file just created inside it, or a rename that just
 * changed what name it holds, is durable — not only the file's own bytes.
 *
 * Never throws: a filesystem or platform that cannot open a directory this way (Windows, some
 * network filesystems) is treated as unable to provide this half of the contract, not as a failure
 * of the write that already completed and returned successfully.
 */
export function fsyncDirectory(path: string): void {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return;
  }
  try {
    fsyncSync(fd);
  } catch {
    // Same posture: a directory that cannot be fsynced this way does not undo the file write.
  } finally {
    closeSync(fd);
  }
}

/** Whether an error is Node's `EXDEV`: a rename that would cross a filesystem boundary. */
export function isCrossDeviceError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'EXDEV'
  );
}
