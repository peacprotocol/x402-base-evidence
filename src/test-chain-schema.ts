/**
 * The closed application/profile schema for the Base chain-observation document, against hostile
 * shapes it must refuse before any verifier logic reads a single field out of them.
 *
 * `schemas/base-chain-observation.v1.schema.json` is an application/profile schema for this
 * example's own document, not a PEAC normative schema; satisfying it is not PEAC conformance and
 * not x402 conformance.
 */
import { beginAcceptanceSuite, recordExecution } from './acceptance-ids.ts';
import { validateLocalProfile } from './flow/profile-schema.ts';

beginAcceptanceSuite('chain-schema');

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n          ${detail}`}`);
};

/** A minimal, otherwise-valid document, so each case tampers exactly one thing. */
function baseDocument(): Record<string, unknown> {
  return {
    profile: 'org.peacprotocol.examples.payment-evidence/base-chain-observation/1',
    scheme: 'exact',
    payment_expectation: {
      source: 'native_x402_artifact',
      network: 'eip155:84532',
      asset: `0x${'a'.repeat(40)}`,
      amount_base_units: '250000',
      asset_decimals: 6,
      recipient: `0x${'b'.repeat(40)}`,
    },
    chain_observation: {
      source: { kind: 'facilitator', reference: 'synthetic' },
      settlement_outcome: 'succeeded',
      observed_at_unix_seconds: 1_785_000_000,
    },
    comparison: {
      network: 'match',
      asset: 'not_evaluated',
      recipient: 'not_evaluated',
      amount: 'not_evaluated',
      authorization: 'not_evaluated',
      transfer_event: 'not_evaluated',
    },
    terminal_state: 'response_write_attempted',
    observed_at_unix_seconds: 1_785_000_000,
  };
}

const accepted = (doc: unknown): boolean => validateLocalProfile('base-chain-observation', doc).ok;

check('the minimal well-formed document is accepted', accepted(baseDocument()));

recordExecution('CHAIN-SCHEMA-001');
{
  const withUnknownTopLevel = { ...baseDocument(), unexpectedField: 'anything' };
  check('an unknown top-level member is refused', !accepted(withUnknownTopLevel));

  const doc = baseDocument();
  (doc['payment_expectation'] as Record<string, unknown>)['unexpectedField'] = 'anything';
  check('an unknown nested member is refused', !accepted(doc));
}

recordExecution('CHAIN-SCHEMA-002');
{
  const wrongTerminalState = { ...baseDocument(), terminal_state: 'not_a_real_state' };
  check('an invalid terminal_state enum value is refused', !accepted(wrongTerminalState));

  const doc = baseDocument();
  (doc['chain_observation'] as Record<string, unknown>)['settlement_outcome'] = 'maybe';
  check('an invalid settlement_outcome enum value is refused', !accepted(doc));

  const doc2 = baseDocument();
  (doc2['comparison'] as Record<string, unknown>)['network'] = 'sort_of';
  check('an invalid comparison verdict enum value is refused', !accepted(doc2));
}

recordExecution('CHAIN-SCHEMA-003');
{
  const negative = { ...baseDocument(), observed_at_unix_seconds: -1 };
  check('a negative top-level timestamp is refused', !accepted(negative));

  const farFuture = { ...baseDocument(), observed_at_unix_seconds: 99_999_999_999 };
  check('a timestamp far beyond the declared bound is refused', !accepted(farFuture));

  const nonInteger = { ...baseDocument(), observed_at_unix_seconds: 1785000000.5 };
  check('a non-integer timestamp is refused', !accepted(nonInteger));
}

recordExecution('CHAIN-SCHEMA-004');
{
  const doc = baseDocument();
  (doc['payment_expectation'] as Record<string, unknown>)['asset_decimals'] = 256;
  check('an asset_decimals value beyond the uint8 bound is refused', !accepted(doc));

  const doc2 = baseDocument();
  (doc2['payment_expectation'] as Record<string, unknown>)['asset_decimals'] = -1;
  check('a negative asset_decimals value is refused', !accepted(doc2));
}

recordExecution('CHAIN-SCHEMA-005');
{
  const doc = baseDocument();
  doc['rpc_observation'] = {
    source: { kind: 'rpc', reference: 'synthetic' },
    transaction_hash: `0x${'c'.repeat(64)}`,
    observation_state: 'found',
    observation_level: 'l1_batch_inclusion', // invalid: only l2_block_inclusion is ever declared
    observed_at_unix_seconds: 1_785_000_000,
    statement: 'synthetic',
  };
  check('an invalid observation_level value is refused', !accepted(doc));

  const doc2 = baseDocument();
  doc2['rpc_observation'] = {
    source: { kind: 'facilitator', reference: 'synthetic' }, // wrong: rpc_observation.source.kind must be 'rpc'
    transaction_hash: `0x${'c'.repeat(64)}`,
    observation_state: 'found',
    observed_at_unix_seconds: 1_785_000_000,
    statement: 'synthetic',
  };
  check('an rpc_observation whose source.kind is not "rpc" is refused', !accepted(doc2));
}

// Grammar spot-checks beyond the five named cases above: exact CAIP-2 and hex forms.
{
  const doc = baseDocument();
  (doc['payment_expectation'] as Record<string, unknown>)['network'] = 'eip155:084532';
  check('a non-canonical CAIP-2 network (leading zero chain id) is refused', !accepted(doc));
}
{
  const doc = baseDocument();
  (doc['payment_expectation'] as Record<string, unknown>)['asset'] = 'not-an-address';
  check('a malformed asset address is refused', !accepted(doc));
}

console.log(`\n${failures ? 'FAILED' : 'PASSED'}: ${failures} failure(s)\n`);
if (failures) process.exit(1);
