/**
 * Path helpers for the Web user-authentication plugin.
 *
 * Everything that decides whether a user may touch a path goes through
 * `contains()`. It is deliberately lexical and strict: a sibling with the same
 * prefix (for example `alice-work` next to `alice`) is not contained.
 */
import fs from 'node:fs'
import path from 'node:path'

/** Resolve a configured directory without touching the filesystem. */
export function resolveBase(value) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error('web-user-auth: a directory path must be a non-empty string')
  return path.resolve(value)
}

/** Whether `target` is `root` or a descendant of it. */
export function contains(root, target) {
  if (typeof root !== 'string' || typeof target !== 'string') return false
  const relative = path.relative(path.resolve(root), path.resolve(target))
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
}

/** Resolve a symlink when it exists; otherwise return the normalized path. */
export function canonicalPath(value) {
  const absolute = path.resolve(value)
  try {
    return fs.realpathSync.native(absolute)
  } catch {
    return absolute
  }
}

/** Resolve `value` against `base` unless it is already absolute. */
export function resolveAgainst(base, value) {
  return path.isAbsolute(value) ? path.resolve(value) : path.resolve(base, value)
}

/**
 * Validate a user supplied relative name for a directory below the workspace.
 * The check is intentionally conservative: one ordinary path segment only.
 */
export function directoryName(value) {
  if (typeof value !== 'string') throw new Error('directory name must be a string')
  const name = value.trim()
  if (name === '' || name === '.' || name === '..') throw new Error('directory name must not be empty or relative')
  if (name.length > 128) throw new Error('directory name is too long')
  if (/[/\\\0]/u.test(name)) throw new Error('directory name must not contain a path separator')
  return name
}

/** Reversible, filesystem-safe directory name for one user id. */
export function userDirectoryName(userId) {
  return `u-${Buffer.from(userId, 'utf8').toString('base64url')}`
}

/** Decode a directory name produced by {@link userDirectoryName}. */
export function userDirectoryId(name) {
  if (typeof name !== 'string' || !name.startsWith('u-')) return undefined
  try {
    const decoded = Buffer.from(name.slice(2), 'base64url').toString('utf8')
    return decoded === '' ? undefined : decoded
  } catch {
    return undefined
  }
}

/** Create a directory and return its canonical absolute path. */
export function ensureDirectory(value) {
  const absolute = path.resolve(value)
  fs.mkdirSync(absolute, { recursive: true, mode: 0o700 })
  return canonicalPath(absolute)
}

/**
 * The user a stored Session belongs to, inferred from the first segment of its
 * cwd below the deployment's user root. This makes ownership survive restarts
 * without adding fields to the Session header.
 */
export function userFromCwd(root, cwd) {
  if (typeof cwd !== 'string' || !contains(root, cwd)) return undefined
  const relative = path.relative(path.resolve(root), path.resolve(cwd))
  if (relative === '') return undefined
  const [first] = relative.split(path.sep)
  return userDirectoryId(first)
}
