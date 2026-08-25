/**
 * HTTP request components, following RFC 9421 derived-component semantics.
 *
 * Components are taken from the message as the origin observed it. They are never reconstructed by
 * re-parsing a single absolute URL string, because doing so invites rebuilding trusted context from
 * attacker-controlled Host or X-Forwarded-* values, and because URL parsers normalise: they collapse
 * dot segments, rewrite percent-encoding and reorder queries, any of which changes the operation the
 * evidence describes.
 *
 * Per RFC 9421:
 *   @method     preserved exactly; HTTP methods are case-sensitive
 *   @scheme     lowercased
 *   @authority  host lowercased, default port for the scheme omitted
 *   @path       percent-encoded octets preserved verbatim
 *   @query      includes the leading "?"; a request with no query yields "?"
 */

import { isIP } from 'node:net';

/**
 * Only `direct-origin` is implemented: scheme and authority come from the adapter's own trust
 * decision, never from a client-supplied header. A trusted-proxy profile (explicit trusted-hop
 * policy, `Forwarded`/`X-Forwarded-*` precedence, spoofing rejection) is a real feature this
 * reference does not implement, so it is not named here. Advertising an enum value with no
 * behavior behind it would let a caller select a mode that does not exist.
 */
export type ProxyTrustProfile = 'direct-origin';

export interface HttpRequestComponentsV1 {
  '@method': string;
  '@scheme': 'http' | 'https';
  '@authority': string;
  '@path': string;
  '@query': string;
  capturePoint: 'origin_request_after_http_parsing';
  proxyTrustProfile: ProxyTrustProfile;
}

export class ComponentError extends Error {}

const MAX_TARGET_BYTES = 8192;
const METHOD_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const REG_NAME = /^[A-Za-z0-9\-._~!$&'()*+,;=%]+$/;
const PCT_OK = /^(?:[^%]|%[0-9A-Fa-f]{2})*$/;

/**
 * Validate an authority and return its canonical form.
 *
 * Canonical form, per RFC 9421 Section 2.2.3, which defers to RFC 9110 Section 4.2.3: the host is
 * lowercased and the default port for the scheme is omitted. Port normalization additionally
 * follows RFC 3986 Section 3.2.3 -- "URI producers and normalizers should omit the port component
 * and its ':' delimiter if port is empty or if its value would be the same as that of the scheme's
 * default" -- so an explicit but EMPTY port is equivalent to no port at all.
 *
 * The two host branches used to disagree about that last rule: a reg-name authority ending in ':'
 * was rejected as a dangling separator, while a bracketed IPv6 literal ending in ':' had the empty
 * port quietly dropped. The same input shape cannot be both malformed and canonical, so the port is
 * now decided once, below, for both branches. Default-port detection is likewise NUMERIC rather than
 * a raw-string comparison: "0443" is port 443 written with a leading zero, and comparing the raw
 * text against "443" retained it as though it were a distinct non-default port.
 *
 * Used by BOTH the capture path, which adopts the returned canonical form, and the
 * constructed-object assertion, which compares against it and rejects anything not already
 * canonical rather than rewriting a caller's evidence.
 */
function canonicalAuthority(scheme: 'http' | 'https', rawAuthority: string): string {
  // Types do not survive into JavaScript callers, so a non-string reaching `.length` or
  // `.toLowerCase()` below would surface as a TypeError. The API contract is ComponentError.
  if (typeof rawAuthority !== 'string') throw new ComponentError('authority must be a string');
  if (rawAuthority.length === 0) throw new ComponentError('empty authority');
  if (rawAuthority.includes('@')) throw new ComponentError('credentials in authority are rejected');

  let host: string;
  let port = '';

  if (rawAuthority.startsWith('[')) {
    const close = rawAuthority.indexOf(']');
    if (close === -1) throw new ComponentError('malformed bracketed IPv6 authority');
    host = rawAuthority.slice(0, close + 1);
    const rest = rawAuthority.slice(close + 1);
    if (rest.length > 0) {
      if (!rest.startsWith(':')) throw new ComponentError('malformed authority after IPv6 literal');
      port = rest.slice(1);
    }
    const inner = host.slice(1, -1);
    // IPvFuture ("v" HEXDIG "." ...) is not supported by this profile and is rejected explicitly
    // rather than being silently accepted by a permissive character class.
    if (/^[vV][0-9A-Fa-f]+\./.test(inner)) throw new ComponentError('IPvFuture authority is not supported');
    if (inner.length === 0 || isIP(inner) !== 6) throw new ComponentError('malformed IPv6 literal');
  } else {
    // An unbracketed IPv6 literal is ambiguous with host:port and must not be guessed at.
    if ((rawAuthority.match(/:/g) ?? []).length > 1)
      throw new ComponentError('unbracketed IPv6 literal or malformed authority');
    const colon = rawAuthority.lastIndexOf(':');
    if (colon === -1) {
      host = rawAuthority;
    } else {
      host = rawAuthority.slice(0, colon);
      // An empty port is NOT rejected here: it is normalized away below, exactly as the bracketed
      // IPv6 branch above already did, and as RFC 3986 Section 3.2.3 directs.
      port = rawAuthority.slice(colon + 1);
    }
    if (host.length === 0) throw new ComponentError('empty host');
    if (!REG_NAME.test(host)) throw new ComponentError(`invalid host syntax: ${host.slice(0, 40)}`);
    if (!PCT_OK.test(host)) throw new ComponentError('malformed percent-encoding in host');
    // A bare IPv4-looking host must actually be a valid IPv4 address.
    if (/^[0-9.]+$/.test(host) && isIP(host) !== 4) throw new ComponentError('malformed IPv4 literal');
  }

  // One port decision for both host branches. An empty port normalizes to absent; a present port is
  // validated, then reduced to its canonical decimal form so that leading zeros cannot disguise a
  // default port as a distinct one.
  let normalizedPort = '';
  if (port.length > 0) {
    if (!/^[0-9]+$/.test(port)) throw new ComponentError(`invalid port: ${port.slice(0, 12)}`);
    const n = Number(port);
    if (n < 1 || n > 65535) throw new ComponentError(`port out of range: ${port}`);
    normalizedPort = String(n);
  }

  const lowered = host.toLowerCase();
  const isDefault =
    (scheme === 'https' && normalizedPort === '443') || (scheme === 'http' && normalizedPort === '80');
  return normalizedPort !== '' && !isDefault ? `${lowered}:${normalizedPort}` : lowered;
}

const CONTROL_OR_SPACE = /[\x00-\x20\x7f]/;
const NON_ASCII = /[^\x00-\x7f]/;

/**
 * The single source of truth for what a valid `HttpRequestComponentsV1` is.
 *
 * Both entry points run this: `captureRequestComponents` asserts it over the object it just built,
 * and `buildRequestBinding` asserts it over an object a caller constructed elsewhere. Keeping two
 * validation stacks meant the builder accepted authorities, targets and encodings that capture
 * rejected, so evidence could be produced through the weaker door.
 *
 * TypeScript types do not survive into JavaScript callers, so a structurally-typed object can reach
 * a builder with an empty authority or a non-path path. Everything is re-checked here.
 *
 * This asserts; it never normalises. Rewriting caller-supplied components behind their back would
 * change the operation the evidence describes, so an object that is not ALREADY canonical (a
 * non-lowercase host, an explicit default port) is rejected rather than corrected.
 */
export function assertCanonicalComponents(c: HttpRequestComponentsV1): void {
  if (!c || typeof c !== 'object') throw new ComponentError('components missing');

  if (typeof c['@method'] !== 'string' || !METHOD_TOKEN.test(c['@method']))
    throw new ComponentError(`invalid method token: ${String(c['@method']).slice(0, 40)}`);

  const scheme = c['@scheme'];
  if (scheme !== 'http' && scheme !== 'https')
    throw new ComponentError(`non-HTTP scheme rejected: ${String(scheme).slice(0, 20)}`);

  if (typeof c['@authority'] !== 'string') throw new ComponentError('invalid authority');
  // canonicalAuthority performs every syntax check (credentials, IPv4/IPv6 literals, port syntax and
  // range) and returns the canonical form; equality is what additionally forbids a non-canonical but
  // syntactically valid authority such as "Example.COM" or "example.com:443" under https.
  const canonical = canonicalAuthority(scheme, c['@authority']);
  if (c['@authority'] !== canonical)
    throw new ComponentError(
      `authority is not in canonical form: ${c['@authority'].slice(0, 60)} (canonical: ${canonical.slice(0, 60)})`,
    );

  const path = c['@path'];
  if (typeof path !== 'string' || path.length === 0)
    throw new ComponentError('invalid path');
  if (!path.startsWith('/'))
    throw new ComponentError('request target must be origin-form and begin with "/"');

  const query = c['@query'];
  // RFC 9421: @query carries its leading "?", and is "?" when no query is present.
  if (typeof query !== 'string' || !query.startsWith('?'))
    throw new ComponentError('invalid query: @query must begin with "?"');

  for (const [label, value] of [['path', path], ['query', query]] as const) {
    if (CONTROL_OR_SPACE.test(value))
      throw new ComponentError('request target contains control or space characters');
    if (NON_ASCII.test(value))
      throw new ComponentError('request target must be ASCII; percent-encode non-ASCII octets');
    if (value.includes('#'))
      throw new ComponentError('fragment rejected: never sent to the origin');
    if (!PCT_OK.test(value))
      throw new ComponentError(`malformed percent-encoding in ${label}`);
  }

  // Bound the reconstructed request target, matching what the capture path bounds on its raw input.
  // A bare "?" is the no-query marker and was not part of the target on the wire.
  const target = query === '?' ? path : `${path}${query}`;
  if (Buffer.byteLength(target, 'utf8') > MAX_TARGET_BYTES)
    throw new ComponentError(`request target exceeds ${MAX_TARGET_BYTES} bytes`);

  if (c.capturePoint !== 'origin_request_after_http_parsing')
    throw new ComponentError('invalid capturePoint');
  if (c.proxyTrustProfile !== 'direct-origin')
    throw new ComponentError('invalid proxyTrustProfile');
}

/**
 * Build components from message parts an adapter supplies.
 *
 * `rawPathAndQuery` is the origin-form request target exactly as received. `scheme` and `authority`
 * come from the adapter's trust decision, not from a header the client controls.
 */
export function captureRequestComponents(input: {
  method: string;
  scheme: string;
  authority: string;
  rawPathAndQuery: string;
  proxyTrustProfile: ProxyTrustProfile;
}): HttpRequestComponentsV1 {
  const { method, rawPathAndQuery } = input;

  if (typeof method !== 'string' || !METHOD_TOKEN.test(method))
    throw new ComponentError(`invalid method token: ${String(method).slice(0, 40)}`);

  // Plain-JavaScript callers reach this function with no type checking at all. Each field is
  // therefore proven to be a string before any string method runs on it, so a caller's mistake is
  // reported as this module's own ComponentError rather than leaking a TypeError from
  // `.toLowerCase()` or `.length` as though it were part of the API contract.
  if (typeof input.scheme !== 'string')
    throw new ComponentError('scheme must be a string');
  const scheme = input.scheme.toLowerCase();
  if (scheme !== 'http' && scheme !== 'https')
    throw new ComponentError(`non-HTTP scheme rejected: ${scheme.slice(0, 20)}`);

  if (typeof input.authority !== 'string')
    throw new ComponentError('authority must be a string');

  if (typeof rawPathAndQuery !== 'string' || rawPathAndQuery.length === 0)
    throw new ComponentError('empty request target');
  if (Buffer.byteLength(rawPathAndQuery, 'utf8') > MAX_TARGET_BYTES)
    throw new ComponentError(`request target exceeds ${MAX_TARGET_BYTES} bytes`);
  if (/[\x00-\x20\x7f]/.test(rawPathAndQuery))
    throw new ComponentError('request target contains control or space characters');
  // Non-ASCII octets must be percent-encoded before they reach the binding, so the digest does not
  // depend on how an intermediary chose to represent them.
  if (/[^\x00-\x7f]/.test(rawPathAndQuery))
    throw new ComponentError('request target must be ASCII; percent-encode non-ASCII octets');
  if (rawPathAndQuery.includes('#'))
    throw new ComponentError('fragment rejected: never sent to the origin');
  if (!rawPathAndQuery.startsWith('/'))
    throw new ComponentError('request target must be origin-form and begin with "/"');

  const q = rawPathAndQuery.indexOf('?');
  const path = q === -1 ? rawPathAndQuery : rawPathAndQuery.slice(0, q);
  // RFC 9421: @query carries its leading "?", and is "?" when no query is present.
  const query = q === -1 ? '?' : rawPathAndQuery.slice(q);

  if (!PCT_OK.test(path)) throw new ComponentError('malformed percent-encoding in path');
  if (!PCT_OK.test(query)) throw new ComponentError('malformed percent-encoding in query');

  const components: HttpRequestComponentsV1 = {
    '@method': method,                                   // case preserved: methods are case-sensitive
    '@scheme': scheme,
    '@authority': canonicalAuthority(scheme, input.authority),
    '@path': path,                                       // percent-encoding and dot segments preserved
    '@query': query,
    capturePoint: 'origin_request_after_http_parsing',
    proxyTrustProfile: input.proxyTrustProfile,
  };
  // Assert the constructed object through the same invariants the binding builder applies, so the
  // two entry points can never drift apart. Capture emits canonical output, so this always holds for
  // input capture accepted; it fails only if the construction above ever stops being canonical.
  assertCanonicalComponents(components);
  return components;
}

/**
 * TEST UTILITY ONLY. Splits an absolute URI without normalising it.
 *
 * Production adapters must call captureRequestComponents with the framework's own message parts and
 * an explicitly resolved trust profile. An absolute URI reassembled by an application has already
 * lost the distinction between what the client sent and what an intermediary supplied.
 */
export function componentsFromAbsoluteUri(input: {
  method: string;
  absoluteUri: string;
  proxyTrustProfile?: ProxyTrustProfile;
}): HttpRequestComponentsV1 {
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(input.absoluteUri);
  if (!m) throw new ComponentError('target must be absolute with an explicit scheme');
  const afterScheme = input.absoluteUri.slice(m[0].length);
  // The authority ends at the FIRST of '/', '?' or '#'. Splitting on '/' alone absorbed the query
  // into the authority for inputs like https://example.com?x=1, silently losing it.
  const end = afterScheme.search(/[/?#]/);
  const authority = end === -1 ? afterScheme : afterScheme.slice(0, end);
  const remainder = end === -1 ? '' : afterScheme.slice(end);
  const rawPathAndQuery = remainder === '' ? '/' : remainder.startsWith('/') ? remainder : `/${remainder}`;
  return captureRequestComponents({
    method: input.method,
    scheme: m[1]!,
    authority,
    rawPathAndQuery,
    proxyTrustProfile: input.proxyTrustProfile ?? 'direct-origin',
  });
}
