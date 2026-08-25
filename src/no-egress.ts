/**
 * Network-egress diagnostics for the offline path.
 *
 * DIAGNOSTICS ONLY. This replaces a few JavaScript entry points inside one process so that an
 * accidental outbound call during the fixture path is loud rather than silent. It is not a sandbox
 * and must never be described as one: a native addon, a child process, or any code that captured a
 * reference before this module loaded would bypass it entirely.
 *
 * The authoritative gate is the continuous-integration job that runs the same path in a container
 * with networking disabled. This exists so the same failure is caught early, on a developer
 * machine, with a readable message.
 *
 * Usage: `node --import ./src/no-egress.ts <entry>`, or import it first from a wrapper.
 */
import dns from 'node:dns';
import net from 'node:net';

class EgressAttemptError extends Error {
  constructor(api: string, target: string) {
    super(`offline path attempted network access via ${api}: ${target.slice(0, 120)}`);
    this.name = 'EgressAttemptError';
  }
}

/** Report and abort: a silent failure would let an unnoticed call pass as a clean run. */
function refuse(api: string, target: string): never {
  const error = new EgressAttemptError(api, target);
  console.error(error.message);
  throw error;
}

const originalFetch = globalThis.fetch;
if (typeof originalFetch === 'function') {
  globalThis.fetch = ((input: unknown, init?: unknown) => {
    void init;
    const target =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.href
          : ((input as { url?: string } | null)?.url ?? '<unknown>');
    refuse('fetch', target);
  }) as typeof globalThis.fetch;
}

const originalLookup = dns.lookup;
// @ts-expect-error the diagnostic replacement deliberately narrows the overloaded signature
dns.lookup = (hostname: string, ...rest: unknown[]) => {
  void rest;
  refuse('dns.lookup', hostname);
};
void originalLookup;

const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function connect(...args: unknown[]) {
  const first = args[0];
  const target =
    typeof first === 'number'
      ? `port ${first}`
      : typeof first === 'string'
        ? first
        : JSON.stringify(first ?? {});
  refuse('net.Socket.connect', target);
};
void originalConnect;

console.log('egress diagnostics active: fetch, dns.lookup and net.Socket.connect will refuse');
