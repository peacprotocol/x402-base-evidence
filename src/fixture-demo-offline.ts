/**
 * The fixture walkthrough with egress diagnostics installed first.
 *
 * Module evaluation follows import order, so the diagnostics are in place before any fixture code
 * runs. See no-egress.ts: this is an early warning, not the authoritative offline gate.
 */
import './no-egress.ts';
import './fixture-demo.ts';
