/**
 * Bounded duplicate-member scanner for JSON text.
 *
 * WHY THIS EXISTS. RFC 8259 says object member names SHOULD be unique; it does not forbid
 * duplicates, and JSON.parse silently keeps the last occurrence. I-JSON (RFC 7493) does forbid
 * them, and JCS (RFC 8785) canonicalization is defined over I-JSON-compatible input. This example
 * canonicalizes decoded payment artifacts and binds the resulting bytes cryptographically, so an
 * object whose members are ambiguous must never reach canonicalization: two parsers could disagree
 * about which value the signed digest covers.
 *
 * This is a PEAC binding-safety requirement. It is NOT an x402 conformance rule: x402 does not
 * declare duplicate members invalid, and nothing here should be read as an upstream validation
 * result.
 *
 * The scanner tokenizes only. It decodes string escapes per RFC 8259 so that "a" and "a"
 * are recognised as the same member name, and it never parses values into JavaScript data;
 * JSON.parse remains the object producer.
 */

export const DUPLICATE_SCAN_LIMITS = {
  /** Maximum nesting depth the scanner will descend before failing closed. */
  maxDepth: 32,
} as const;

export type DuplicateScanCode =
  /** Two members of the same object decoded to the same name. */
  | 'duplicate_member'
  /** Nesting exceeded the declared depth bound. */
  | 'depth_limit_exceeded'
  /** The scanner could not complete: input the tokenizer cannot describe. */
  | 'scan_incomplete';

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
    if (depth > DUPLICATE_SCAN_LIMITS.maxDepth) this.fail('depth_limit_exceeded');
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
   * compared raw source spans would miss an escaped-key collision entirely.
   */
  private scanString(): string {
    this.expect('"');
    let out = '';
    for (;;) {
      const ch = this.text[this.index];
      if (ch === undefined) this.fail('scan_incomplete');
      this.index++;
      if (ch === '"') return out;
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
