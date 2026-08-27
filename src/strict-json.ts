/**
 * Bounded duplicate-member scanner for JSON text, extended to admit only I-JSON-valid string
 * content.
 *
 * WHY THIS EXISTS. RFC 8259 says object member names SHOULD be unique; it does not forbid
 * duplicates, and JSON.parse silently keeps the last occurrence. I-JSON (RFC 7493) does forbid
 * them, and JCS (RFC 8785) canonicalization is defined over I-JSON-compatible input. This example
 * canonicalizes decoded payment artifacts and binds the resulting bytes cryptographically, so an
 * object whose members are ambiguous must never reach canonicalization: two parsers could disagree
 * about which value the signed digest covers.
 *
 * RFC 7493 also restricts string content: a JSON string is not I-JSON if it contains an unpaired
 * UTF-16 surrogate code unit or a Unicode noncharacter, in a key or a value, at any depth. Neither
 * restriction is part of JSON's own grammar — `JSON.parse` accepts both — so a document that
 * passes ordinary JSON syntax can still carry either defect straight through canonicalization,
 * where a plain `TextEncoder` silently rewrites an unpaired surrogate into U+FFFD rather than
 * failing: two runtimes could then canonicalize what looks like "the same" string into different
 * bytes while both appear to succeed. This scanner is where that content is checked, before any
 * value it admits reaches canonicalization, a digest, or a signature — never after, and never by
 * repairing or replacing what it finds. A string failing this check is rejected outright.
 *
 * This is a PEAC binding-safety requirement. It is NOT an x402 conformance rule: x402 does not
 * declare duplicate members or these string-content restrictions invalid, and nothing here should
 * be read as an upstream validation result.
 *
 * The scanner tokenizes only. It decodes string escapes per RFC 8259 so that "a" and "a"
 * are recognised as the same member name, and it never parses values into JavaScript data;
 * JSON.parse remains the object producer.
 */

export const DUPLICATE_SCAN_LIMITS = {
  /**
   * Maximum number of nested `scanValue` calls the scanner will make along any single chain of
   * nesting before failing closed — stated and enforced identically everywhere it is checked
   * (`scanValue`, `scanObject` and `scanArray` all fail at the same `depth >= maxDepth`), so this
   * number is the true, exact bound rather than one function's approximation of it.
   */
  maxDepth: 32,
} as const;

export type DuplicateScanCode =
  /** Two members of the same object decoded to the same name. */
  | 'duplicate_member'
  /** Nesting exceeded the declared depth bound. */
  | 'depth_limit_exceeded'
  /** The scanner could not complete: input the tokenizer cannot describe. */
  | 'scan_incomplete'
  /**
   * A decoded string — an object member name or a string value, at any depth, arrays included —
   * carries an unpaired UTF-16 surrogate or a Unicode noncharacter. I-JSON (RFC 7493) forbids
   * both from appearing in string content; JSON's own grammar does not, so `JSON.parse` accepts
   * a string like this without complaint, and this scanner is where that gap is closed.
   */
  | 'invalid_ijson_string';

export type DuplicateScanResult =
  | { readonly status: 'accepted' }
  | {
      readonly status: 'rejected';
      readonly code: DuplicateScanCode;
      /** Member names and array indices leading to the failure, outermost first. */
      readonly path: readonly string[];
    };

class ScanFailure extends Error {
  readonly code: DuplicateScanCode;
  readonly path: readonly string[];

  constructor(code: DuplicateScanCode, path: readonly string[]) {
    super(code);
    this.code = code;
    this.path = path;
  }
}

const WHITESPACE = new Set([' ', '\t', '\n', '\r']);
/** Characters that may appear in a JSON number or in true/false/null. */
const BARE_VALUE = /[0-9eE+\-.a-z]/;

/** The BMP block RFC 7493 reserves as noncharacters: U+FDD0 through U+FDEF, inclusive. */
const NONCHARACTER_BMP_START = 0xfdd0;
const NONCHARACTER_BMP_END = 0xfdef;

/**
 * Whether a decoded JSON string is free of unpaired UTF-16 surrogates and Unicode noncharacters,
 * per RFC 7493's I-JSON string-content restrictions.
 *
 * Runs over the fully decoded string — after every `\u` escape has already become a UTF-16 code
 * unit and every literal character has already been copied through — so escaped and literal
 * occurrences of either defect are caught the same way, in one pass, regardless of which form
 * produced them.
 *
 * A high surrogate must be immediately followed by its low surrogate, and the two combine to one
 * code point before the noncharacter check runs, because "every plane-end noncharacter" is a
 * property of the code point (its low 16 bits are 0xFFFE or 0xFFFF), not of either UTF-16 half on
 * its own.
 */
function isValidIjsonString(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) return false;
      const codePoint = 0x10000 + (unit - 0xd800) * 0x400 + (next - 0xdc00);
      if ((codePoint & 0xffff) === 0xfffe || (codePoint & 0xffff) === 0xffff) return false;
      i++; // the low surrogate just consumed is part of this pair, not a unit of its own
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return false; // a low surrogate reached on its own
    if (unit >= NONCHARACTER_BMP_START && unit <= NONCHARACTER_BMP_END) return false;
    if (unit === 0xfffe || unit === 0xffff) return false;
  }
  return true;
}

class Scanner {
  private index = 0;
  private readonly path: string[] = [];
  private readonly text: string;

  constructor(text: string) {
    this.text = text;
  }

  run(): void {
    this.skipWhitespace();
    this.scanValue(0);
    this.skipWhitespace();
    if (this.index !== this.text.length) this.fail('scan_incomplete');
  }

  private fail(code: DuplicateScanCode): never {
    throw new ScanFailure(code, [...this.path]);
  }

  private skipWhitespace(): void {
    while (this.index < this.text.length && WHITESPACE.has(this.text[this.index]!)) this.index++;
  }

  private expect(ch: string): void {
    if (this.text[this.index] !== ch) this.fail('scan_incomplete');
    this.index++;
  }

  private scanValue(depth: number): void {
    // Same bound, same comparison, as `scanObject`/`scanArray` below: a value at `depth ===
    // maxDepth` is refused here regardless of whether it turns out to be a scalar or a container,
    // so the stated bound is the exact number of nested `scanValue` calls ever made along one
    // chain, not one function's looser approximation of another's.
    if (depth >= DUPLICATE_SCAN_LIMITS.maxDepth) this.fail('depth_limit_exceeded');
    const ch = this.text[this.index];
    if (ch === undefined) this.fail('scan_incomplete');
    if (ch === '{') return this.scanObject(depth);
    if (ch === '[') return this.scanArray(depth);
    if (ch === '"') {
      this.scanString();
      return;
    }
    // Numbers and the three literals are consumed as opaque token runs: their content cannot
    // introduce a member name, so tokenizing further would add risk without adding information.
    let consumed = 0;
    while (this.index < this.text.length && BARE_VALUE.test(this.text[this.index]!)) {
      this.index++;
      consumed++;
    }
    if (consumed === 0) this.fail('scan_incomplete');
  }

  private scanObject(depth: number): void {
    if (depth >= DUPLICATE_SCAN_LIMITS.maxDepth) this.fail('depth_limit_exceeded');
    this.expect('{');
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.text[this.index] === '}') {
      this.index++;
      return;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.index] !== '"') this.fail('scan_incomplete');
      const name = this.scanString();
      this.path.push(name);
      if (seen.has(name)) this.fail('duplicate_member');
      seen.add(name);
      this.skipWhitespace();
      this.expect(':');
      this.skipWhitespace();
      this.scanValue(depth + 1);
      this.path.pop();
      this.skipWhitespace();
      const next = this.text[this.index];
      if (next === ',') {
        this.index++;
        continue;
      }
      if (next === '}') {
        this.index++;
        return;
      }
      this.fail('scan_incomplete');
    }
  }

  private scanArray(depth: number): void {
    if (depth >= DUPLICATE_SCAN_LIMITS.maxDepth) this.fail('depth_limit_exceeded');
    this.expect('[');
    this.skipWhitespace();
    if (this.text[this.index] === ']') {
      this.index++;
      return;
    }
    for (let element = 0; ; element++) {
      this.skipWhitespace();
      this.path.push(String(element));
      this.scanValue(depth + 1);
      this.path.pop();
      this.skipWhitespace();
      const next = this.text[this.index];
      if (next === ',') {
        this.index++;
        continue;
      }
      if (next === ']') {
        this.index++;
        return;
      }
      this.fail('scan_incomplete');
    }
  }

  /**
   * Consume a JSON string and return its DECODED value.
   *
   * Escape decoding is the point: "a" and "a" are the same member name, so a scanner that
   * compared raw source spans would miss an escaped-key collision entirely. The same decoded
   * value is checked for I-JSON string-content validity before it is returned, so every caller —
   * a member name or a value, at any depth, inside an object or an array — gets that check for
   * free and cannot admit a string this scanner never looked at.
   */
  private scanString(): string {
    this.expect('"');
    let out = '';
    for (;;) {
      const ch = this.text[this.index];
      if (ch === undefined) this.fail('scan_incomplete');
      this.index++;
      if (ch === '"') {
        if (!isValidIjsonString(out)) this.fail('invalid_ijson_string');
        return out;
      }
      if (ch !== '\\') {
        // RFC 8259 forbids unescaped control characters inside a string.
        if (ch < ' ') this.fail('scan_incomplete');
        out += ch;
        continue;
      }
      const esc = this.text[this.index];
      if (esc === undefined) this.fail('scan_incomplete');
      this.index++;
      switch (esc) {
        case '"':
        case '\\':
        case '/':
          out += esc;
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'n':
          out += '\n';
          break;
        case 'r':
          out += '\r';
          break;
        case 't':
          out += '\t';
          break;
        case 'u': {
          const hex = this.text.slice(this.index, this.index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail('scan_incomplete');
          this.index += 4;
          // Surrogate halves are appended individually; a valid pair recombines into the same
          // code point JSON.parse would produce, so name comparison stays faithful.
          out += String.fromCharCode(parseInt(hex, 16));
          break;
        }
        default:
          this.fail('scan_incomplete');
      }
    }
  }
}

/**
 * Report whether JSON text is free of duplicate object members.
 *
 * Never throws for malformed input: a failure to complete is itself a result, and the caller
 * decides how to record it. Callers must treat anything other than `accepted` as a refusal to
 * canonicalize.
 */
export function scanForDuplicateMembers(text: string): DuplicateScanResult {
  try {
    new Scanner(text).run();
    return { status: 'accepted' };
  } catch (e) {
    if (e instanceof ScanFailure) return { status: 'rejected', code: e.code, path: e.path };
    return { status: 'rejected', code: 'scan_incomplete', path: [] };
  }
}

/**
 * Decode bytes as UTF-8, or refuse them.
 *
 * The default `TextDecoder` replaces malformed sequences with U+FFFD, which turns bytes that are
 * not text into text that nobody wrote. For a document whose canonical bytes are about to be
 * digested and compared against a signed claim, that substitution is a silent rewrite: the digest
 * would cover a document the file does not contain. So decoding is fatal, and a refusal is a result
 * the caller reports rather than an exception out of the middle of verification.
 *
 * @returns The decoded text, or `undefined` if the bytes are not valid UTF-8.
 */
export function decodeStrictUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

/** Why bytes were not admitted as a JSON document. */
export type StrictJsonRefusal =
  /** The bytes are not valid UTF-8, and replacing what is malformed would rewrite the document. */
  | 'invalid_utf8'
  /** Well-formed enough for the scanner, but not parseable JSON. */
  | 'not_json'
  | DuplicateScanCode;

export type StrictJsonRead =
  | { readonly status: 'parsed'; readonly value: unknown }
  | { readonly status: 'refused'; readonly refusal: StrictJsonRefusal };

/**
 * Admit bytes as a JSON document, in the order the admission rules require.
 *
 * Decode fatally, scan for ambiguous member names, and only then parse. The order is the point: by
 * the time a value exists, it cannot be a value two parsers would disagree about, and it cannot
 * have come from bytes that were repaired on the way in. Anything a caller then canonicalizes and
 * digests is therefore a document the file actually contains, exactly once.
 *
 * Every refusal is named. A caller reports which rule refused the document rather than collapsing
 * five distinct conditions into "not valid JSON".
 */
export function parseStrictJson(bytes: Uint8Array): StrictJsonRead {
  const text = decodeStrictUtf8(bytes);
  if (text === undefined) return { status: 'refused', refusal: 'invalid_utf8' };
  const scan = scanForDuplicateMembers(text);
  if (scan.status !== 'accepted') return { status: 'refused', refusal: scan.code };
  try {
    return { status: 'parsed', value: JSON.parse(text) };
  } catch {
    return { status: 'refused', refusal: 'not_json' };
  }
}
