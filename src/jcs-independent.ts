/**
 * A second, independently written RFC 8785 (JCS) implementation.
 *
 * TEST-ONLY. The protocol canonicalization helper is the production authority; this exists so golden
 * vectors are checked by two separately written implementations rather than by one function compared
 * against itself. It must never be used to produce signed material.
 *
 * Strictness matters here: RFC 8785 requires termination with an error on invalid Unicode. A lone
 * surrogate that is tolerated becomes U+FFFD when encoded to UTF-8, so two runtimes could canonicalize
 * "the same" string into different bytes while both appearing to succeed.
 */

export class JcsError extends Error {}

const ESCAPES: Record<string, string> = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
};

/** RFC 8785: invalid Unicode terminates with an error rather than being replaced. */
function assertWellFormed(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff)
        throw new JcsError(`lone high surrogate at index ${i}`);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new JcsError(`lone low surrogate at index ${i}`);
    }
  }
}

function serializeString(s: string): string {
  assertWellFormed(s);
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ESCAPES[ch]) out += ESCAPES[ch];
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return out + '"';
}

/**
 * RFC 8785 serialises numbers with ECMAScript Number::toString, so 1e21 becomes "1e+21".
 *
 * Integers beyond 2^53-1 are NOT rejected here: any precision loss already happened when the value
 * was parsed into a double, and refusing to canonicalize at this point would be non-conformant while
 * fixing nothing. Callers that need exact large integers must carry them as strings.
 */
function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) throw new JcsError(`non-finite number is not valid JSON: ${n}`);
  if (Object.is(n, -0)) return '0';
  return String(n);
}

/** RFC 8785 sorts member names by UTF-16 code unit, not by locale collation. */
function compareCodeUnits(a: string, b: string): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Only I-JSON values are canonicalizable; anything else is an error, never a silent omission. */
function assertJsonValue(v: unknown, seen: Set<object> = new Set()): void {
  if (v !== null && typeof v === 'object') {
    if (seen.has(v as object)) throw new JcsError('cyclic structure cannot be canonicalized');
  }
  const t = typeof v;
  if (v === null || t === 'boolean' || t === 'number' || t === 'string') return;
  if (Array.isArray(v)) return;
  if (t === 'object') {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null)
      throw new JcsError('only plain objects can be canonicalized');
    return;
  }
  throw new JcsError(`value of type ${t} cannot be canonicalized`);
}

export function canonicalizeIndependent(value: unknown, seen: Set<object> = new Set()): string {
  assertJsonValue(value, seen);
  if (value !== null && typeof value === 'object') seen = new Set([...seen, value as object]);
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return serializeNumber(value as number);
  if (t === 'string') return serializeString(value as string);
  if (Array.isArray(value)) {
    // A sparse array has holes that JSON.stringify renders as null, quietly changing the data.
    for (let i = 0; i < value.length; i++)
      if (!Object.prototype.hasOwnProperty.call(value, i)) throw new JcsError(`sparse array hole at index ${i}`);
    return `[${value.map((el) => {
      if (el === undefined) throw new JcsError('undefined is not a JSON value');
      return canonicalizeIndependent(el, seen);
    }).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  if (Object.getOwnPropertySymbols(obj).length > 0)
    throw new JcsError('symbol-keyed own properties cannot be canonicalized');
  const keys = Object.keys(obj);
  for (const k of keys) {
    // Dropping undefined members silently would let two different inputs canonicalize identically.
    if (obj[k] === undefined) throw new JcsError(`member "${k}" is undefined, which is not JSON`);
    assertWellFormed(k);
  }
  keys.sort(compareCodeUnits);
  return `{${keys.map((k) => `${serializeString(k)}:${canonicalizeIndependent(obj[k], seen)}`).join(',')}}`;
}

/** Canonical UTF-8 bytes, which are what actually get hashed. */
export function canonicalUtf8Bytes(value: unknown): Buffer {
  return Buffer.from(canonicalizeIndependent(value), 'utf8');
}
