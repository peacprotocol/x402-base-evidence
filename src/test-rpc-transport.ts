/**
 * The JSON-RPC transport boundary against a hostile endpoint.
 *
 * A local loopback HTTP server stands in for the endpoint and returns exactly the bytes each case
 * needs — oversized, lying about its own length, invalid UTF-8, ambiguous JSON, the wrong id or
 * protocol version, or both a result and an error at once — and every case asserts that
 * `baseSealedRpcSource`'s calls refuse it rather than processing it, through the public interface
 * this repository actually calls, never through an unexported internal.
 */
import { createServer, type Server } from 'node:http';
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { baseSealedRpcSource } from './flow/observe-transaction.ts';

beginAcceptanceSuite('rpc-transport');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

/** A raw response this server sends for every request, until the test closes it. */
interface RawResponse {
  readonly statusCode?: number;
  readonly headers?: Record<string, string>;
  readonly body: Buffer;
}

async function withServer(response: RawResponse, fn: (url: string) => Promise<void>): Promise<void> {
  const server: Server = createServer((_req, res) => {
    res.writeHead(response.statusCode ?? 200, response.headers ?? { 'content-type': 'application/json' });
    res.end(response.body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('no usable server address');
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const rejects = async (name: string, fn: () => Promise<unknown>): Promise<void> => {
  try {
    await fn();
    check(name, false, 'did NOT reject');
  } catch (e) {
    check(name, true, `rejected: ${(e as Error).message}`);
  }
};

const validEnvelope = (result: unknown): string => JSON.stringify({ jsonrpc: '2.0', id: 1, result });

console.log('\n  -- response size bounds --');

recordExecution('RPC-001');
await withServer(
  {
    body: Buffer.from(validEnvelope(`0x${'a'.repeat(6 * 1024 * 1024)}`)),
  },
  async (url) => {
    // The server sends a correct Content-Length for a body well over the bound; the case is that
    // a truthful but oversized declaration is rejected before the body is read at all.
    await rejects('oversized response with a correct Content-Length is rejected', () =>
      baseSealedRpcSource(url).sealedHeadBlockNumber(),
    );
  },
);

recordExecution('RPC-002');
await withServer(
  {
    headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' },
    body: Buffer.from(validEnvelope(`0x${'a'.repeat(6 * 1024 * 1024)}`)),
  },
  async (url) => {
    // No Content-Length at all (chunked transfer): the streaming reader's own running byte count
    // is what must catch this, since there is no header to reject on up front.
    await rejects('oversized response with no Content-Length is rejected while streaming', () =>
      baseSealedRpcSource(url).sealedHeadBlockNumber(),
    );
  },
);

recordExecution('RPC-003');
await withServer(
  {
    // Declares a small, harmless-looking size while actually sending an oversized body: an
    // early reject keyed only on a truthful Content-Length would miss this, so the streaming
    // reader's own running byte count — not the header — is what must catch it.
    headers: { 'content-type': 'application/json', 'content-length': '10' },
    body: Buffer.from(validEnvelope(`0x${'a'.repeat(6 * 1024 * 1024)}`)),
  },
  async (url) => {
    await rejects('a Content-Length that understates an oversized body is rejected', () =>
      baseSealedRpcSource(url).sealedHeadBlockNumber(),
    );
  },
);

console.log('\n  -- envelope admission --');

recordExecution('RPC-004');
await withServer({ body: Buffer.from([0xc3, 0x28, 0x7b, 0x7d]) }, async (url) => {
  await rejects('a response that is not valid UTF-8 is rejected', () =>
    baseSealedRpcSource(url).sealedHeadBlockNumber(),
  );
});

recordExecution('RPC-005');
await withServer(
  { body: Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x1","result":"0x2"}') },
  async (url) => {
    await rejects('a response with a duplicate JSON member is rejected', () =>
      baseSealedRpcSource(url).sealedHeadBlockNumber(),
    );
  },
);

recordExecution('RPC-006');
await withServer({ body: Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 2, result: '0x1' })) }, async (url) => {
  await rejects('a response whose id does not match the request is rejected', () =>
    baseSealedRpcSource(url).sealedHeadBlockNumber(),
  );
});

recordExecution('RPC-007');
await withServer({ body: Buffer.from(JSON.stringify({ jsonrpc: '1.0', id: 1, result: '0x1' })) }, async (url) => {
  await rejects('a response declaring the wrong jsonrpc version is rejected', () =>
    baseSealedRpcSource(url).sealedHeadBlockNumber(),
  );
});

recordExecution('RPC-008');
await withServer(
  {
    body: Buffer.from(
      JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x1', error: { code: -1, message: 'also an error' } }),
    ),
  },
  async (url) => {
    await rejects('a response carrying both result and error is rejected', () =>
      baseSealedRpcSource(url).sealedHeadBlockNumber(),
    );
  },
);

{
  const neitherBody = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: 1 }));
  await withServer({ body: neitherBody }, async (url) => {
    check(
      'a response carrying neither result nor error is also rejected',
      await baseSealedRpcSource(url)
        .sealedHeadBlockNumber()
        .then(() => false)
        .catch(() => true),
    );
  });
}

console.log('\n  -- receipt-shaped bounds and grammar --');

recordExecution('RPC-009');
{
  const hugeLogs = Array.from({ length: 20_000 }, () => ({
    address: `0x${'a'.repeat(40)}`,
    topics: [`0x${'1'.repeat(64)}`],
    data: '0x',
  }));
  const receiptBody = Buffer.from(
    validEnvelope({
      status: '0x1',
      blockNumber: '0x1',
      blockHash: `0x${'b'.repeat(64)}`,
      logs: hugeLogs,
    }),
  );
  await withServer({ body: receiptBody }, async (url) => {
    const receipt = await baseSealedRpcSource(url).transactionReceipt(`0x${'c'.repeat(64)}`);
    check(
      'a receipt claiming more logs than the bound is refused outright, not truncated',
      receipt === undefined,
      JSON.stringify(receipt, (_k, v) => typeof v === 'bigint' ? v.toString() : v),
    );
  });

  const manyTopicsBody = Buffer.from(
    validEnvelope({
      status: '0x1',
      blockNumber: '0x1',
      blockHash: `0x${'b'.repeat(64)}`,
      logs: [
        {
          address: `0x${'a'.repeat(40)}`,
          topics: Array.from({ length: 5 }, () => `0x${'1'.repeat(64)}`),
          data: '0x',
        },
      ],
    }),
  );
  await withServer({ body: manyTopicsBody }, async (url) => {
    const receipt = await baseSealedRpcSource(url).transactionReceipt(`0x${'c'.repeat(64)}`);
    check(
      'a log claiming more than four topics (no LOG5 exists) is skipped, not admitted',
      receipt !== undefined && receipt.logs.length === 0,
      JSON.stringify(receipt, (_k, v) => typeof v === 'bigint' ? v.toString() : v),
    );
  });
}

recordExecution('RPC-010');
{
  const malformedHashReceipt = Buffer.from(
    validEnvelope({
      status: '0x1',
      blockNumber: '0x1',
      blockHash: '0xnotahash',
      logs: [],
    }),
  );
  await withServer({ body: malformedHashReceipt }, async (url) => {
    const receipt = await baseSealedRpcSource(url).transactionReceipt(`0x${'c'.repeat(64)}`);
    check(
      'a malformed block hash on a receipt is refused, not passed through',
      receipt === undefined,
      JSON.stringify(receipt, (_k, v) => typeof v === 'bigint' ? v.toString() : v),
    );
  });

  const malformedAddressTx = Buffer.from(
    validEnvelope({ from: '0xnotanaddress', blockNumber: '0x1', blockHash: `0x${'b'.repeat(64)}` }),
  );
  await withServer({ body: malformedAddressTx }, async (url) => {
    const tx = await baseSealedRpcSource(url).transactionByHash(`0x${'c'.repeat(64)}`);
    check(
      'a malformed sender address on a transaction is refused, not passed through',
      tx === undefined,
      JSON.stringify(tx, (_k, v) => typeof v === 'bigint' ? v.toString() : v),
    );
  });

  const nonCanonicalQuantity = Buffer.from(validEnvelope('0x0123'));
  await withServer({ body: nonCanonicalQuantity }, async (url) => {
    await rejects('a non-canonical quantity (leading zero) is refused, not parsed leniently', () =>
      baseSealedRpcSource(url).sealedHeadBlockNumber(),
    );
  });
}

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
