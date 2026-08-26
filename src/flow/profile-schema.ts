/**
 * Validation of the two application-local binding documents against their committed schemas.
 *
 * WHAT THIS IS, AND WHAT IT IS NOT. The schemas under `schemas/` describe the two documents this
 * example invents: an example-local request binding and an example-local origin result binding.
 * They are experimental and non-normative. Validating against them establishes that a document has
 * the shape this example produces and nothing more. It is NOT PEAC conformance, NOT x402
 * conformance, and NOT a statement about any registry: neither profile is registered anywhere, and
 * a document that validates here has satisfied one repository's own closed schema.
 *
 * WHY THE VERIFIER RUNS THEM AT ALL. A digest proves that a document is the one the record bound.
 * It says nothing about whether that document is well formed, so a producer that emitted a request
 * binding with a missing component, an unknown member or a malformed digest string would hand over
 * evidence whose digests all recompute and whose contents nobody has actually read. The digest and
 * the shape answer different questions, and both are worth a named check.
 *
 * The schemas are read from the repository rather than restated here, so the documents the tests
 * validate and the documents the verifier validates are held to one definition. Compilation is
 * deferred to first use and then reused, because a run that verifies nothing should not pay for it.
 *
 * On the validator: `ajv` is a development dependency, and so is `tsx`, which is what runs this
 * file. Every entry point in this repository is a repository script executed from a working tree
 * where `pnpm install` has run; there is no published package here whose consumers could receive
 * one without the other.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const APP_ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

/** The example-local documents that have a committed schema. */
export type LocalProfileDocument = 'request-binding' | 'origin-result-binding';

const SCHEMA_FILE: Readonly<Record<LocalProfileDocument, string>> = {
  'request-binding': 'request-binding.v1.schema.json',
  'origin-result-binding': 'origin-result-binding.v1.schema.json',
};

export type LocalProfileResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      /** Bounded explanation. Never reproduces document content beyond a truncated member name. */
      readonly detail: string;
    };

/** One compiled validator per document, built on first use. */
type Validator = (value: unknown) => boolean;
interface ValidatorWithErrors extends Validator {
  errors?: ReadonlyArray<{
    readonly instancePath?: string;
    readonly keyword?: string;
    readonly message?: string;
    readonly params?: Record<string, unknown>;
  }> | null;
}

let compiled: Record<LocalProfileDocument, ValidatorWithErrors> | undefined;

function validators(): Record<LocalProfileDocument, ValidatorWithErrors> {
  if (compiled !== undefined) return compiled;
  // The CommonJS build exposes the class both as the module value and as `default`, and which one
  // arrives depends on the loader. Both are accepted rather than assuming one of them.
  const constructor = ((Ajv2020 as unknown as { default?: unknown }).default ??
    Ajv2020) as new (options: Record<string, unknown>) => {
    compile(schema: unknown): ValidatorWithErrors;
  };
  const ajv = new constructor({ strict: true, allErrors: false });
  const load = (document: LocalProfileDocument): ValidatorWithErrors =>
    ajv.compile(
      JSON.parse(readFileSync(join(APP_ROOT, 'schemas', SCHEMA_FILE[document]), 'utf8')) as unknown,
    );
  compiled = {
    'request-binding': load('request-binding'),
    'origin-result-binding': load('origin-result-binding'),
  };
  return compiled;
}

/**
 * A bounded, printable rendering of text taken from a document under validation.
 *
 * Member names inside an evidence directory are chosen by whoever produced it, and a validation
 * message carries them. Report text is written to a terminal, so anything that could carry control
 * characters or arbitrary length is reduced to printable ASCII and truncated.
 */
function bounded(text: string, limit: number): string {
  const printable = [...text].filter((c) => c >= ' ' && c <= '~').join('');
  return printable.length <= limit ? printable : `${printable.slice(0, limit)}...`;
}

/**
 * Validate one document against its committed example-local schema.
 *
 * @param document - Which local profile to hold it to.
 * @param value - The document, already admitted as JSON by the caller.
 * @returns Whether it satisfies the schema, and the first reason it did not.
 */
export function validateLocalProfile(
  document: LocalProfileDocument,
  value: unknown,
): LocalProfileResult {
  const validate = validators()[document];
  if (validate(value)) return { ok: true };

  const first = validate.errors?.[0];
  if (first === undefined) return { ok: false, detail: 'it does not satisfy the example-local schema' };

  const where = first.instancePath === undefined || first.instancePath.length === 0
    ? 'the document'
    : bounded(first.instancePath, 60);
  const what = bounded(first.message ?? 'does not satisfy the example-local schema', 80);
  // The offending member name is the actionable part of a closed-schema refusal, and it is the one
  // piece of document-controlled text worth repeating, bounded like everything else.
  const extra =
    first.keyword === 'additionalProperties' && typeof first.params?.['additionalProperty'] === 'string'
      ? `: ${bounded(first.params['additionalProperty'] as string, 40)}`
      : '';
  return { ok: false, detail: `${where} ${what}${extra}` };
}
