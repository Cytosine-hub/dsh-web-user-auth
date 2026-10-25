/**
 * Signed cookie helpers, independent of the DSH browser-session cookie.
 *
 * The DSH Connection cookie identifies "the owner of this Harness". This
 * plugin adds a second, signed cookie that identifies the Web user; both are
 * required for a browser request, and the plugin maps the second cookie to a
 * non-owner Peer.
 */
import crypto from 'node:crypto'

const BASE64URL = /^[A-Za-z0-9_-]*$/u

function encode(value) {
  return Buffer.from(value).toString('base64url')
}

function decode(value) {
  if (!BASE64URL.test(value) || value.length % 4 === 1) return undefined
  try {
    return Buffer.from(value, 'base64url')
  } catch {
    return undefined
  }
}

function signature(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest()
}

/** Read one cookie without attempting to parse unrelated attributes. */
export function readCookie(header, name) {
  if (typeof header !== 'string') return undefined
  for (const segment of header.split(';')) {
    const index = segment.indexOf('=')
    if (index === -1) continue
    if (segment.slice(0, index).trim() !== name) continue
    return segment.slice(index + 1).trim()
  }
  return undefined
}

/** Every cookie value whose name starts with `prefix`. */
export function cookiesWithPrefix(header, prefix) {
  const found = []
  if (typeof header !== 'string') return found
  for (const segment of header.split(';')) {
    const index = segment.indexOf('=')
    if (index === -1) continue
    const name = segment.slice(0, index).trim()
    if (!name.startsWith(prefix)) continue
    found.push({ name, value: segment.slice(index + 1).trim() })
  }
  return found
}

/** Serialize one signed user-session cookie. */
export function signSession(payload, secret) {
  const body = encode(JSON.stringify(payload))
  return `v1.${body}.${signature(secret, body).toString('base64url')}`
}

/** Verify and decode a signed user-session cookie. */
export function verifySession(token, secret) {
  if (typeof token !== 'string') return undefined
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return undefined
  const [version, body, encodedSignature] = parts
  const actual = decode(encodedSignature)
  if (actual === undefined) return undefined
  const expected = signature(secret, body)
  if (actual.byteLength !== expected.byteLength || !crypto.timingSafeEqual(actual, expected)) return undefined
  const bytes = decode(body)
  if (bytes === undefined) return undefined
  let payload
  try {
    payload = JSON.parse(bytes.toString('utf8'))
  } catch {
    return undefined
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return undefined
  if (payload.v !== 1 || typeof payload.id !== 'string' || payload.id === '') return undefined
  if (typeof payload.name !== 'string') return undefined
  if (payload.provider !== 'local' && payload.provider !== 'http' && payload.provider !== 'header' && payload.provider !== 'token') return undefined
  if(payload.provider==='token'&&(typeof payload.tokenSessionId!=='string'||!payload.tokenSessionId))return undefined
  if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) return undefined
  if (payload.exp <= Date.now()) return undefined
  return payload
}

/** One `Set-Cookie` value for the user session. */
export function sessionCookie(name, value, { maxAgeSeconds, secure }) {
  const attributes = [
    `${name}=${value}`,
    `Max-Age=${String(maxAgeSeconds)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ]
  if (secure) attributes.push('Secure')
  return attributes.join('; ')
}

/** One `Set-Cookie` value that clears a cookie. */
export function clearCookie(name, { secure } = {}) {
  const attributes = [`${name}=`, 'Max-Age=0', 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT']
  if (secure) attributes.push('Secure')
  return attributes.join('; ')
}

/** Canonical authority string used by DSH's built-in browser cookie. */
function requestAuthority(headers, secure) {
  const host = typeof headers?.host === 'string' ? headers.host : undefined
  if (host === undefined) return undefined
  try {
    const url = new URL(`${secure ? 'https:' : 'http:'}//${host}`)
    return secure ? url.origin : url.host
  } catch {
    return undefined
  }
}

/** Name of DSH's built-in browser-session cookie for this request. */
export function builtInCookieName(headers, secure) {
  const authority = requestAuthority(headers, secure)
  if (authority === undefined) return undefined
  return `dsh-auth-${crypto.createHash('sha256').update(authority).digest('base64url')}`
}

/**
 * Inspect the built-in cookie. This deliberately does not verify its signature:
 * it only decides whether a token exchange is likely needed. The real check
 * remains DSH's own `authorizeIndex` / `admit` implementation.
 */
export function builtInCookieState(headers, secure) {
  const name = builtInCookieName(headers, secure)
  if (name === undefined) return { name: undefined, present: false, usable: false }
  const value = readCookie(headers?.cookie, name)
  if (value === undefined) return { name, present: false, usable: false }
  const parts = value.split('.')
  if (parts.length !== 3 || (parts[0] !== 'v1' && parts[0] !== 'v2')) return { name, present: true, usable: false }
  const bytes = decode(parts[1])
  if (bytes === undefined) return { name, present: true, usable: false }
  let payload
  try {
    payload = JSON.parse(bytes.toString('utf8'))
  } catch {
    return { name, present: true, usable: false }
  }
  const expiresAt = payload?.expiresAt ?? payload?.exp
  const usable = payload !== null && typeof payload === 'object' && Number.isSafeInteger(expiresAt) && expiresAt > Date.now()
  return { name, present: true, usable }
}
