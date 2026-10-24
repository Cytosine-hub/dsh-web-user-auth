/**
 * Local users, password verification, and the small durable state this plugin
 * owns. Passwords can live in the plugin config (as scrypt hashes or plain
 * text) or in a JSON users file created by the first-run setup page.
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const SCRYPT_N = 16384
const SCRYPT_R = 8
const SCRYPT_P = 1
const KEY_BYTES = 64

function sameSecret(actual, expected) {
  const a = Buffer.from(actual, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  return a.byteLength === b.byteLength && crypto.timingSafeEqual(a, b)
}

/** Hash a password as a self-describing scrypt string. */
export function hashPassword(password) {
  const salt = crypto.randomBytes(16)
  const key = crypto.scryptSync(password, salt, KEY_BYTES, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 64 * 1024 * 1024 })
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64url')}$${key.toString('base64url')}`
}

/** Verify a scrypt hash produced by {@link hashPassword}. */
function verifyScryptHash(password, stored) {
  const parts = stored.split('$')
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false
  const n = Number(parts[1])
  const r = Number(parts[2])
  const p = Number(parts[3])
  if (![n, r, p].every(Number.isSafeInteger) || n <= 0 || r <= 0 || p <= 0) return false
  let salt
  let expected
  try {
    salt = Buffer.from(parts[4], 'base64url')
    expected = Buffer.from(parts[5], 'base64url')
  } catch {
    return false
  }
  if (salt.byteLength === 0 || expected.byteLength === 0) return false
  let actual
  try {
    actual = crypto.scryptSync(password, salt, expected.byteLength, { N: n, r, p, maxmem: 64 * 1024 * 1024 })
  } catch {
    return false
  }
  return actual.byteLength === expected.byteLength && crypto.timingSafeEqual(actual, expected)
}

/** Verify either a scrypt hash or a configured plaintext password. */
export function verifyPassword(password, user) {
  if (typeof password !== 'string' || typeof user !== 'object' || user === null) return false
  if (typeof user.passwordHash === 'string' && user.passwordHash !== '') return verifyScryptHash(password, user.passwordHash)
  if (typeof user.password === 'string') return sameSecret(password, user.password)
  return false
}

function normalizeUser(value, source) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error(`web-user-auth: ${source} contains a non-object user`)
  const id = typeof value.id === 'string' ? value.id.trim() : ''
  if (id === '') throw new Error(`web-user-auth: ${source} contains a user without an id`)
  if (/[/\\\0]/u.test(id)) throw new Error(`web-user-auth: user id ${JSON.stringify(id)} contains a path separator`)
  const name = typeof value.name === 'string' && value.name.trim() !== '' ? value.name.trim() : id
  return {
    ...value,
    id,
    name,
  }
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (error) {
    if (error?.code === 'ENOENT') return undefined
    throw new Error(`web-user-auth: cannot read ${file}: ${error instanceof Error ? error.message : String(error)}`)
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
  fs.renameSync(temporary, file)
}

/** Durable local user directory plus the configured users. */
export class UserStore {
  /** @param {{users?: unknown[], usersFile: string}} options */
  constructor(options) {
    this.usersFile = options.usersFile
    this.configured = []
    this.fileUsers = []
    this.byId = new Map()
    if (options.users !== undefined) {
      if (!Array.isArray(options.users)) throw new Error('web-user-auth: local.users must be an array')
      this.configured = options.users.map((user) => normalizeUser(user, 'local.users'))
    }
    this.load()
  }

  load() {
    const document = readJson(this.usersFile)
    if (document === undefined) {
      this.fileUsers = []
    } else if (Array.isArray(document)) {
      this.fileUsers = document.map((user) => normalizeUser(user, this.usersFile))
    } else if (document !== null && typeof document === 'object' && Array.isArray(document.users)) {
      this.fileUsers = document.users.map((user) => normalizeUser(user, this.usersFile))
    } else {
      throw new Error(`web-user-auth: ${this.usersFile} must be a user array or {"users": [...]}`)
    }
    this.byId.clear()
    for (const user of this.fileUsers) this.byId.set(user.id, user)
    for (const user of this.configured) this.byId.set(user.id, { ...this.byId.get(user.id), ...user })
  }

  has(id) {
    return this.byId.has(id)
  }

  get(id) {
    return this.byId.get(id)
  }

  list() {
    return Array.from(this.byId.values())
  }

  /** Whether the deployment still needs its first user. */
  needsSetup() {
    return this.byId.size === 0
  }

  verify(id, password) {
    const user = this.byId.get(id)
    return user !== undefined && verifyPassword(password, user)
  }

  /**
   * Create a local user. Configured users are immutable here; file users can be
   * added, which is what the first-run setup page does.
   */
  add({ id, name, password }) {
    const normalizedId = String(id ?? '').trim()
    if (normalizedId === '') throw new Error('user id is required')
    if (/[/\\\0]/u.test(normalizedId)) throw new Error('user id must not contain a path separator')
    if (this.byId.has(normalizedId)) throw new Error(`user ${JSON.stringify(normalizedId)} already exists`)
    if (typeof password !== 'string' || password.length < 8) throw new Error('password must be at least 8 characters')
    const user = {
      id: normalizedId,
      name: typeof name === 'string' && name.trim() !== '' ? name.trim() : normalizedId,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
    }
    this.fileUsers.push(user)
    this.byId.set(user.id, user)
    this.persist()
    return user
  }

  resetPassword(id, password) {
    if (this.configured.some(user => user.id === id)) throw new Error('此账号由静态配置管理，请在原配置中修改密码')
    const user = this.fileUsers.find(user => user.id === id)
    if (user === undefined) throw new Error('普通用户不存在')
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) throw new Error('密码长度需要为 12 到 1024 个字符')
    user.passwordHash = hashPassword(password)
    delete user.password
    user.passwordChangedAt = Date.now()
    this.persist()
    this.load()
    return this.get(id)
  }

  persist() {
    writeJson(this.usersFile, { users: this.fileUsers })
  }
}

/** Read or create the HMAC secret used for user cookies. */
export function loadOrCreateSecret(file) {
  try {
    const value = fs.readFileSync(file, 'utf8').trim()
    if (value !== '') return Buffer.from(value, 'base64url')
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
  const secret = crypto.randomBytes(32)
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  fs.writeFileSync(file, `${secret.toString('base64url')}\n`, { mode: 0o600 })
  return secret
}

/** Read or create the first-run setup token. */
export function loadOrCreateSetupToken(file) {
  try {
    const value = fs.readFileSync(file, 'utf8').trim()
    if (value !== '') return value
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
  const token = crypto.randomBytes(24).toString('base64url')
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  fs.writeFileSync(file, `${token}\n`, { mode: 0o600 })
  return token
}
