/**
 * A bounded, terminal-safe rendering of an arbitrary value.
 *
 * Every string this repository's verifier or demos print that came out of an evidence directory —
 * an issuer, a `kid`, a claimed value, a path, a mismatch detail — is attacker-controlled: the
 * directory can be handed over by whoever produced it, and nothing about a failed check requires
 * its text to be printable, short, or free of terminal-control meaning. A control character passed
 * straight through would let that text do things ordinary printed text cannot: CR/LF can forge an
 * extra report line, ESC can start a terminal escape sequence (color, cursor movement, and on some
 * terminals far more), and a bidirectional-formatting override can visually reorder the characters
 * around it so a reader sees something other than what the bytes actually are.
 *
 * This function is the one place that risk is closed: every control character in the class below
 * is rendered as its own visible `\uXXXX` escape rather than passed through, and the result is
 * bounded to a maximum length AFTER escaping, so a string that only becomes long once every
 * character is spelled out cannot slip past a bound sized for the original text.
 *
 * The character class is written entirely with `\u` escapes, deliberately, rather than as literal
 * characters in this source file: a source file is exactly the kind of place a raw control or
 * bidi-override character should never appear, for the same reason this module exists.
 */

/**
 * C0 controls (U+0000-U+001F) and DEL (U+007F): CR, LF and ESC among them.
 * C1 controls (U+0080-U+009F): meaningful in several 8-bit terminal encodings.
 * Bidirectional formatting controls: ALM (U+061C), LRM/RLM (U+200E/U+200F), the explicit
 * embedding/override controls (U+202A-U+202E), and the isolate controls (U+2066-U+2069).
 */
const UNSAFE_FOR_TERMINAL =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

function escapeUnsafeChar(ch: string): string {
  return `\\u${ch.codePointAt(0)!.toString(16).padStart(4, '0')}`;
}

/** Escape every control character `UNSAFE_FOR_TERMINAL` names. Never removes or reorders anything else. */
export function escapeForTerminal(text: string): string {
  return text.replace(UNSAFE_FOR_TERMINAL, escapeUnsafeChar);
}

/**
 * Render a value for inclusion in report text: a string is escaped then bounded, an object is
 * named rather than serialised, and anything else is stringified then escaped and bounded.
 *
 * The bound applies to the ESCAPED length, not the original: a short string that is mostly control
 * characters can escape to something much longer, and the point of bounding is to cap what a
 * terminal actually renders, not what the source bytes measured before this function ran.
 */
export function terminalSafe(value: unknown, maxLength = 80): string {
  const raw =
    typeof value === 'string'
      ? value
      : typeof value === 'object' && value !== null
        ? 'a value that is not a string'
        : String(value);
  const escaped = escapeForTerminal(raw);
  return escaped.length <= maxLength ? escaped : `${escaped.slice(0, maxLength)}...`;
}
