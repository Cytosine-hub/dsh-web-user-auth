/**
 * Web user authentication, per-user Session isolation, and per-user workspace
 * confinement for DeepSeek Harness.
 *
 * The plugin sits on top of DSH's own browser authentication:
 *
 * 1. DSH still performs its launch-token / signed-cookie handshake.
 * 2. This plugin adds a second signed cookie naming a Web user, and patches
 *    `ctx.connection.admit()` so every browser request speaks for a non-owner
 *    `harness-user` Peer.
 * 3. A Remote-access policy grants each user only Sessions and Workspaces whose
 *    immutable `cwd` lives under that user's assigned directory.
 * 4. Session creation is normalized to the user's directory, and the DSH
 *    sandbox uses the Session cwd as its `workspace-write` root.
 */
import { installAdmin } from './admin.js'
import { patchServiceMethod } from './service-patch.js'
import { createNativeHandoff } from './handoff.js'
import { normalizeTokenConfig, TokenSessions } from './token-auth.js'
import { tokenBrowserScript, tokenLoginMarkup } from './token-browser.js'
import { installManagement } from './management.js'
import { ADMIN_USER_ID, administratorIdentity } from './identity.js'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import {
  builtInCookieState,
  clearCookie,
  cookiesWithPrefix,
  readCookie,
  sessionCookie,
  signSession,
  verifySession,
} from './cookies.js'
import {
  canonicalPath,
  contains,
  directoryName,
  ensureDirectory,
  resolveAgainst,
  userDirectoryName,
  userFromCwd,
} from './paths.js'
import { UserStore, loadOrCreateSecret, loadOrCreateSetupToken } from './users.js'
import { createUserAccessPolicy } from './policy.js'
import { installPluginManagementGuards } from './plugin-management.js'
import { mergeSavedSettings, persistedSettings } from './provider-settings.js'
import { renderLoginPage, renderMessagePage, renderSetupPage, serverLocale } from './login-page.js'

const DAY_MS = 86_400_000
const MAX_FORM_BYTES = 64 * 1024
const MAX_JSON_BYTES = 64 * 1024

function homeDirectory() {
  return process.env.DSH_HOME ?? path.join(os.homedir(), '.deepseek-harness')
}

/** Apply defaults and validate the user-supplied plugin config. */
export function normalizeConfig(raw) {
  const input = raw !== null && typeof raw === 'object' ? raw : {}
  const home = homeDirectory()
  const stateDir = path.resolve(typeof input.stateDir === 'string' && input.stateDir !== '' ? input.stateDir : path.join(home, 'web-user-auth'))
  const workspaceRoot = path.resolve(typeof input.workspaceRoot === 'string' && input.workspaceRoot !== '' ? input.workspaceRoot : path.join(home, 'web-users'))
  const provider = input.provider ?? 'local'
  if (provider !== 'local' && provider !== 'http' && provider !== 'header' && provider !== 'token') {
    throw new Error('web-user-auth: provider must be "local", "http", "header", or "token"')
  }
  const local = input.local !== null && typeof input.local === 'object' ? input.local : {}
  const http = input.http !== null && typeof input.http === 'object' ? input.http : {}
  const header = input.header !== null && typeof input.header === 'object' ? input.header : {}
  const setup = input.setup !== null && typeof input.setup === 'object' ? input.setup : {}
  if (http.method === 'GET') throw new Error('web-user-auth: login requires POST; GET is not supported')
  if (provider === 'http' && (typeof http.loginUrl !== 'string' || http.loginUrl === '')) {
    throw new Error('web-user-auth: http provider requires http.loginUrl')
  }
  const usersFile = path.resolve(typeof local.usersFile === 'string' && local.usersFile !== '' ? local.usersFile : path.join(stateDir, 'users.json'))
  const maxAgeDays = Number.isSafeInteger(input.cookieMaxAgeDays) && input.cookieMaxAgeDays > 0 ? input.cookieMaxAgeDays : 7
  return {
    enabled: input.enabled === true,
    provider,
    token:normalizeTokenConfig(input.token??{},provider==='token'),
    workspaceRoot,
    adminWorkspaceRoot:path.resolve(typeof input.adminWorkspaceRoot==='string'&&input.adminWorkspaceRoot!==''?input.adminWorkspaceRoot:workspaceRoot),
    workspaceRootHistory:Array.isArray(input.workspaceRootHistory)?[...new Set(input.workspaceRootHistory.filter(value=>typeof value==='string'&&path.isAbsolute(value)).map(value=>path.resolve(value)))]:[],
    stateDir,
    usersFile,
    cookieName: typeof input.cookieName === 'string' && /^[A-Za-z0-9_-]+$/u.test(input.cookieName) ? input.cookieName : 'dsh-user-auth',
    cookieMaxAgeDays: maxAgeDays,
    secureCookies: input.secureCookies === true || input.secureCookies === false ? input.secureCookies : 'auto',
    allowOwnerLoopback: input.allowOwnerLoopback !== false,
    allowApiTokens: input.allowApiTokens === true,
    setup: {
      enabled: setup.enabled !== false,
      tokenFile: path.resolve(typeof setup.tokenFile === 'string' && setup.tokenFile !== '' ? setup.tokenFile : path.join(stateDir, 'setup-token')),
    },
    local: {
      users: Array.isArray(local.users) ? local.users : [],
      usersFile,
    },
    http: {
      loginUrl: typeof http.loginUrl === 'string' ? http.loginUrl : '',
      userInfoUrl: typeof http.userInfoUrl === 'string' ? http.userInfoUrl : '',
      method: http.method === 'GET' ? 'GET' : 'POST',
      requestFormat: http.requestFormat === 'form' ? 'form' : 'json',
      timeoutMs: Number.isSafeInteger(http.timeoutMs) && http.timeoutMs > 0 ? http.timeoutMs : 10_000,
      tokenField: typeof http.tokenField === 'string' ? http.tokenField : 'access_token',
      userField: typeof http.userField === 'string' ? http.userField : 'user',
      idField: typeof http.idField === 'string' ? http.idField : 'id',
      nameField: typeof http.nameField === 'string' ? http.nameField : 'name',
      headers: http.headers !== null && typeof http.headers === 'object' && !Array.isArray(http.headers) ? http.headers : {},
      userInfoHeaders: http.userInfoHeaders !== null && typeof http.userInfoHeaders === 'object' && !Array.isArray(http.userInfoHeaders) ? http.userInfoHeaders : {},
      tokenHeader: typeof http.tokenHeader === 'string' ? http.tokenHeader : 'authorization',
      tokenPrefix: typeof http.tokenPrefix === 'string' ? http.tokenPrefix : 'Bearer ',
    },
    header: {
      userHeader: typeof header.userHeader === 'string' && header.userHeader !== '' ? header.userHeader.toLowerCase() : 'x-auth-request-user',
      nameHeader: typeof header.nameHeader === 'string' && header.nameHeader !== '' ? header.nameHeader.toLowerCase() : 'x-auth-request-name',
      secretHeader: typeof header.secretHeader === 'string' && header.secretHeader !== '' ? header.secretHeader.toLowerCase() : 'x-dsh-auth-secret',
      sharedSecret: typeof header.sharedSecret === 'string' ? header.sharedSecret : '',
    },
  }
}

function isLoopbackHostname(hostname) {
  if (hostname === 'localhost' || hostname === '[::1]' || hostname === '::1') return true
  const mapped = hostname.startsWith('::ffff:') ? hostname.slice(7) : hostname
  const parts = mapped.split('.')
  return parts.length === 4 && parts[0] === '127' && parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255)
}

function isLoopbackRequest(request) {
  const host = typeof request?.headers?.host === 'string' ? request.headers.host : ''
  let hostLoopback = false
  try {
    hostLoopback = isLoopbackHostname(new URL(`http://${host}`).hostname)
  } catch {
    hostLoopback = false
  }
  const address = request?.socket?.remoteAddress
  const remoteLoopback = address === undefined || address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
  return hostLoopback && remoteLoopback
}

function headerValue(headers, name) {
  const value = headers?.[name.toLowerCase()]
  if (typeof value === 'string') return value
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0]
  return undefined
}

function sameSecret(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string' || expected === '') return false
  const a = Buffer.from(actual)
  const b = Buffer.from(expected)
  return a.byteLength === b.byteLength && crypto.timingSafeEqual(a, b)
}

function splitField(value, field) {
  if (typeof field !== 'string' || field === '') return undefined
  let current = value
  for (const part of field.split('.')) {
    if (current === null || typeof current !== 'object' || !(part in current)) return undefined
    current = current[part]
  }
  return current
}

function pickField(body, field, fallback) {
  const value = splitField(body, field)
  if (typeof value === 'string' && value !== '') return value
  const fallbackValue = splitField(body, fallback)
  return typeof fallbackValue === 'string' && fallbackValue !== '' ? fallbackValue : undefined
}

function readCookieValue(header, name) {
  return readCookie(header, name)
}

async function readBody(request, limit) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.byteLength
    if (size > limit) throw new Error('request body is too large')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function send(res, status, headers, body = '') {
  res.writeHead(status, { 'cache-control': 'no-store', ...headers })
  res.end(body)
}

function sendHtml(res, status, html) {
  send(res, status, { 'content-type': 'text/html; charset=utf-8', 'referrer-policy': 'no-referrer' }, html)
}

function sendJson(res, status, value) {
  send(res, status, { 'content-type': 'application/json; charset=utf-8' }, JSON.stringify(value))
}

function redirect(res, location) {
  res.writeHead(303, {
    location,
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
  })
  res.end()
}

class WebUserAuthRuntime {
  constructor(ctx, config, isAdmin) {
    this.isAdmin = isAdmin
    this.ctx = ctx
    this.ownerPeer = ctx.connection.browserPeer
    this.config = config
    this.log = ctx.logger
    this.secret = undefined
    this.setupToken = undefined
    this.store = undefined
    this.root = undefined
    this.policy = undefined
    this.policyDispose = undefined
    this.peers = new Map()
    this.ensuring = new Map()
    this.ensured = new Map()
    this.syncEnsured = new Map()
    this.workspaceIds = new Map()
    this.disposed = false
    this.passwordCsrf=crypto.randomBytes(32)
    this.passwordAttempts=new Map()
    this.patchDisposers = []
    this.routeDisposers = []
  }

  async start() {
    fs.mkdirSync(this.config.stateDir, { recursive: true, mode: 0o700 })
    this.secret = loadOrCreateSecret(path.join(this.config.stateDir, 'secret'))
    this.root = ensureDirectory(this.config.workspaceRoot)
    this.adminRoot = ensureDirectory(this.config.adminWorkspaceRoot)
    this.userRoots = [...new Set([this.root,...this.config.workspaceRootHistory.map(canonicalPath)])]
    this.ownershipRoots = [...new Set([...this.userRoots,this.adminRoot])].sort((a,b)=>b.length-a.length)
    this.store = new UserStore({ users: this.config.local.users, usersFile: this.config.usersFile })
    if(this.config.provider==='token')this.tokenSessions=new TokenSessions(this.config.token,{onRevoke:id=>this.disposePeer(id)})
    if (this.config.setup.enabled) this.setupToken = loadOrCreateSetupToken(this.config.setup.tokenFile)

    const created = this.ctx.effect(() => {
      this.policy = createUserAccessPolicy({
        ctx: this.ctx,
        workspaceRoot: this.root,
        workspaceOf: (userId) => this.workspacePathOf(userId),
        userForPath: (cwd) => this.userForCwd(cwd),
        isAdministrator: id=>Boolean(this.tokenSessions?.administrator(id)),
        scheduleCatalogReady: () => this.scheduleCatalogGuarded === true,
        ownsPath: (userId, target) => this.pathAllowed(userId === ADMIN_USER_ID ? administratorIdentity() : {id:userId}, target),
      })
      const ordinary = this.ctx.remoteAccess.registerPolicy('harness-user', this.policy.policy)
      const administrator = this.ctx.remoteAccess.registerPolicy('harness-admin', this.policy.policy)
      this.policyDispose = () => { administrator(); ordinary() }
      return () => {
        try {
          this.policyDispose?.()
        } finally {
          this.policyDispose = undefined
        }
      }
    }, 'web-user-auth: Remote access policy')
    void created

    this.installPatches()
    this.registerRoutes()
    // The shipped index carries the owner baseline. Override it with a neutral
    // non-owner baseline; the Client follows `remoteAccess/follow` immediately
    // and replaces the grants with this user's own Sessions and Workspaces.
    this.patchDisposers.push(this.ctx.on('webserver/index-inject', (table) => {
      table.push({
        kind: 'global',
        name: '__DSH_REMOTE_ACCESS__',
        value: { type: 'baseline', owner: false, grants: [] },
      })
    }))
    this.patchDisposers.push(this.ctx.on('session/created', (session) => {
      this.rememberSessionHeader(session)
    }))
    this.patchDisposers.push(this.ctx.on('session/disposed', (session) => {
      this.policy?.forgetSession(session.id)
    }))
    this.ctx.effect(() => () => this.dispose(), 'web-user-auth: runtime teardown')

    await this.scanPersistedSessions()
    this.log?.info?.(`web-user-auth: enabled (${this.config.provider} provider, workspace root ${this.root})`)
  }

  dispose() {
    if (this.disposed) return
    this.disposed = true
    this.tokenSessions?.dispose()
    for (const dispose of this.patchDisposers.splice(0).reverse()) {
      try {
        dispose()
      } catch {
        // Best effort during teardown.
      }
    }
    for (const dispose of this.routeDisposers.splice(0).reverse()) {
      try {
        dispose()
      } catch {
        // Best effort during teardown.
      }
    }
    for (const peer of this.peers.values()) {
      void peer.dispose()
    }
    this.peers.clear()
    this.policyDispose?.()
    this.policyDispose = undefined
  }

  // ---------------------------------------------------------------------------
  // Identity and workspace ownership
  // ---------------------------------------------------------------------------

  workspacePathOf(userId) {
    const candidate = path.join(userId===ADMIN_USER_ID?this.adminRoot:this.root, userDirectoryName(userId))
    return fs.existsSync(candidate) ? canonicalPath(candidate) : candidate
  }

  userForCwd(cwd) {
    const target=canonicalPath(cwd)
    for(const root of this.ownershipRoots){
      if(contains(root,target))return userFromCwd(root,target)
    }
    return ADMIN_USER_ID
  }

  ephemeralUser(id, name = id, provider = 'header') {
    return { id, name, provider }
  }

  userFromPrincipal(principal) {
    if (principal?.kind === 'harness-admin') return principal.userId===ADMIN_USER_ID?administratorIdentity():this.tokenSessions?.administrator(principal.userId)
    if (principal === null || typeof principal !== 'object' || principal.kind !== 'harness-user' || typeof principal.userId !== 'string' || principal.userId===ADMIN_USER_ID) return undefined
    return this.store.get(principal.userId) ?? this.ephemeralUser(principal.userId)
  }

  sessionOwner(sessionId) {
    const header = this.ctx.sessions.get(sessionId)?.header
    if (header !== undefined) return this.userForCwd(header.cwd)
    for (const userId of this.workspaceIds.keys()) {
      if (this.policy?.sessionsOf(userId).includes(sessionId) === true) return userId
    }
    return undefined
  }

  ownsSession(userId, sessionId) {
    if (typeof sessionId !== 'string') return false
    return this.policy?.sessionsOf(userId).includes(sessionId) === true
  }

  rememberSessionHeader(session) {
    const header = session?.header
    if (header === undefined) return
    if (this.policy?.rememberSession(header.id, header.cwd) === true) {
      // Session ownership must not overwrite the user's registered Workspace ID.
    }
  }

  async scanPersistedSessions() {
    const seen = new Set()
    for (const session of this.ctx.sessions.list()) {
      seen.add(session.id)
      this.rememberSessionHeader(session)
    }
    try {
      const snapshots = await this.ctx.sessionPersistence.list()
      for (const snapshot of snapshots) {
        if (seen.has(snapshot.header.id)) continue
        this.rememberSessionHeader({ header: snapshot.header })
      }
    } catch (error) {
      this.log?.warn?.(`web-user-auth: could not scan persisted Sessions: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  async ensureUser(identity) {
    const id = identity?.id
    if (typeof id !== 'string' || id.trim() === '') throw new Error('web-user-auth: user identity has no id')
    if (id === ADMIN_USER_ID && identity.administrator !== true) throw new Error('web-user-auth: reserved administrator identity')
    if (/[/\\\0]/u.test(id) || id.length > 256) throw new Error('web-user-auth: invalid user id')
    const cached = this.ensured.get(id)
    if (cached !== undefined && fs.existsSync(cached.workspacePath)) return cached
    const existing = this.ensuring.get(id)
    if (existing !== undefined) return existing
    const pending = this.ensureUserNow(id, identity.name ?? id)
    this.ensuring.set(id, pending)
    try {
      const ensured = await pending
      this.ensured.set(id, ensured)
      return ensured
    } finally {
      this.ensuring.delete(id)
    }
  }

  async ensureUserNow(id, name) {
    const directory = this.workspacePathOf(id)
    const canonical = ensureDirectory(directory)
    if (!contains(id===ADMIN_USER_ID?this.adminRoot:this.root, canonical)) throw new Error('web-user-auth: user workspace resolved outside the configured root')
    let workspaceId
    try {
      const workspace = await this.ctx.workspaceRegistry.create(canonical, name)
      workspaceId = workspace.id
    } catch (error) {
      this.log?.warn?.(`web-user-auth: could not register workspace ${canonical}: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (workspaceId !== undefined) this.workspaceIds.set(id, workspaceId)
    try {
      this.ctx.remoteAccess.invalidate({ kind: id === ADMIN_USER_ID ? 'harness-admin' : 'harness-user', userId: id })
    } catch {
      // Best effort.
    }
    return { id, name, provider: 'header', workspacePath: canonical, workspaceId }
  }

  ensureUserSync(identity) {
    if(identity.id===ADMIN_USER_ID&&identity.administrator!==true)throw new Error('web-user-auth: reserved administrator identity')
    let canonical = this.syncEnsured.get(identity.id)
    if (canonical === undefined || !fs.existsSync(canonical)) {
      canonical = ensureDirectory(this.workspacePathOf(identity.id))
      if (!contains(identity.id===ADMIN_USER_ID?this.adminRoot:this.root, canonical)) throw new Error('web-user-auth: user workspace resolved outside the configured root')
      this.syncEnsured.set(identity.id, canonical)
    }
    void this.ensureUser(identity).catch((error) => {
      this.log?.warn?.(`web-user-auth: workspace registration failed: ${error instanceof Error ? error.message : String(error)}`)
    })
    return { ...identity, workspacePath: canonical, workspaceId: this.workspaceIds.get(identity.id) }
  }

  identify(request) {
    if (!this.config.enabled) return undefined
    const token = readCookieValue(request?.headers?.cookie, this.config.cookieName)
    const payload = token === undefined ? undefined : verifySession(token, this.secret)
    if (payload !== undefined) {
      if (payload.provider === 'local' && !this.store.has(payload.id)) return undefined
      if (payload.provider !== this.config.provider) return undefined
      if(payload.provider==='token'){
        const record=this.tokenSessions?.get(payload.tokenSessionId)
        if(!record||record.identity.id!==payload.id)return undefined
        return this.ensureUserSync(record.identity)
      }
      const known = this.store.get(payload.id)
      if (payload.provider === 'local' && typeof known?.passwordChangedAt === 'number' && payload.iat <= known.passwordChangedAt) return undefined
      return this.ensureUserSync({
        id: payload.id,
        name: known?.name ?? payload.name,
        provider: payload.provider,
      })
    }
    if (this.config.provider !== 'header') return undefined
    const header = this.config.header
    const id = headerValue(request?.headers, header.userHeader)?.trim()
    if (id === undefined || id === '' || id===ADMIN_USER_ID) return undefined
    if (header.sharedSecret !== '' && !sameSecret(headerValue(request?.headers, header.secretHeader), header.sharedSecret)) return undefined
    if (/[/\\\0]/u.test(id) || id.length > 256) return undefined
    const name = headerValue(request?.headers, header.nameHeader)?.trim() || id
    return this.ensureUserSync(this.ephemeralUser(id, name, 'header'))
  }

  peerForUser(user) {
    if (this.disposed) throw new Error('web-user-auth: runtime is disposed')
    let peer = this.peers.get(user.id)
    const kind=user.administrator===true?'harness-admin':'harness-user'
    if(peer!==undefined&&!peer.signal.aborted&&peer.principal.kind!==kind){this.disposePeer(user.id);peer=undefined}
    if (peer !== undefined && !peer.signal.aborted) return peer
    peer = this.ctx.connection.createPeer({
      principal: { kind: user.administrator === true ? 'harness-admin' : 'harness-user', userId: user.id },
      interactions: 'answer',
    })
    this.peers.set(user.id, peer)
    return peer
  }

  peerForRequest(user, request) {
    const peer = this.peerForUser(user)
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    // Harness captures its exact-route Fetch handler before Auth starts. Select
    // the peer at admission instead of wrapping that already-captured handler.
    // Only these native file routes receive owner authority, after ownership
    // checks. RPC and WebSocket requests retain the user's scoped peer.
    if (request.method === 'POST' && url.pathname === '/api/session/uploadFileBinary') {
      const sessionId = url.searchParams.get('sessionId')
      if (sessionId !== null && this.ownsSession(user.id, sessionId)) return this.ownerPeer
    }
    if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/api/file') {
      const target = url.searchParams.get('path')
      if (target !== null && this.pathAllowed(user, target)) return this.ownerPeer
    }
    return peer
  }

  disposePeer(userId) {
    const peer = this.peers.get(userId)
    if (peer === undefined) return
    this.peers.delete(userId)
    void peer.dispose()
  }

  // ---------------------------------------------------------------------------
  // Authentication providers
  // ---------------------------------------------------------------------------

  async authenticate(username, password, request) {
    if (this.config.provider === 'local') {
      if (!this.store.verify(username, password)) return undefined
      const user = this.store.get(username)
      return this.ephemeralUser(user.id, user.name, 'local')
    }
    if (this.config.provider === 'http') return this.authenticateHttp(username, password)
    return undefined
  }

  async authenticateHttp(username, password) {
    const http = this.config.http
    const form = http.requestFormat === 'form'
    const headers = { 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json', accept: 'application/json', ...http.headers }
    let response
    try {
      response = await fetch(http.loginUrl, {
        method: http.method,
        headers,
        body: http.method === 'GET' ? undefined : form ? new URLSearchParams({ username, password }).toString() : JSON.stringify({ username, password }),
        signal: AbortSignal.timeout(http.timeoutMs),
      })
    } catch (error) {
      throw new Error(`authentication endpoint is unavailable: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (!response.ok) return undefined
    const text = await response.text()
    let body
    try {
      body = text === '' ? {} : JSON.parse(text)
    } catch {
      throw new Error('authentication endpoint returned non-JSON content')
    }
    const token = pickField(body, http.tokenField, 'token')
    let userBody = body
    if (http.userInfoUrl !== '' && token !== undefined) {
      const userHeaders = { accept: 'application/json', ...http.userInfoHeaders }
      userHeaders[http.tokenHeader] = `${http.tokenPrefix}${token}`
      let userResponse
      try {
        userResponse = await fetch(http.userInfoUrl, { method: 'GET', headers: userHeaders, signal: AbortSignal.timeout(http.timeoutMs) })
      } catch (error) {
        throw new Error(`user-info endpoint is unavailable: ${error instanceof Error ? error.message : String(error)}`)
      }
      if (!userResponse.ok) throw new Error(`user-info endpoint returned HTTP ${String(userResponse.status)}`)
      const userText = await userResponse.text()
      try {
        userBody = JSON.parse(userText)
      } catch {
        throw new Error('user-info endpoint returned non-JSON content')
      }
    }
    const nestedUser = splitField(userBody, http.userField)
    if (nestedUser !== null && typeof nestedUser === 'object' && !Array.isArray(nestedUser)) userBody = nestedUser
    const id = pickField(userBody, http.idField, 'sub') ?? pickField(userBody, 'id', 'email') ?? username
    if (typeof id !== 'string' || id.trim() === '' || id===ADMIN_USER_ID) return undefined
    const name = pickField(userBody, http.nameField, 'preferred_username') ?? id
    return this.ephemeralUser(id, name, 'http')
  }

  // ---------------------------------------------------------------------------
  // HTTP routes
  // ---------------------------------------------------------------------------

  registerRoutes() {
    const ctx = this.ctx
    const routes = [
      { kind: 'exact', path: '/api/auth/token', handler:(req,res)=>this.handleToken(req,res) },
      { kind: 'exact', path: '/auth-token-client.js', handler:(req,res)=>{if(req.method!=='GET'){send(res,405,{allow:'GET'});return}send(res,200,{'content-type':'text/javascript; charset=utf-8'},tokenBrowserScript)} },
      { kind: 'exact', path: '/logout', handler: (req, res) => this.handleLogout(req, res) },
      { kind: 'exact', path: '/setup', handler: (req, res) => this.handleSetup(req, res) },
      { kind: 'exact', path: '/api/auth/password', handler: (req,res)=>this.handlePassword(req,res) },
      { kind: 'exact', path: '/api/auth/me', handler: (req, res) => this.handleMe(req, res) },
      { kind: 'exact', path: '/api/auth/new-directory', handler: (req, res) => this.handleNewDirectory(req, res) },
    ]
    for (const route of routes) {
      this.routeDisposers.push(ctx.webServer.register({...route,handler:(req,res)=>{this.clearInvalidTokenCookie(req,res);return route.handler(req,res)}}))
    }
  }

  listenerSecure() {
    return this.ctx.webServer.protocol === 'https:'
  }

  requestSecure(request) {
    if (this.config.secureCookies === true) return true
    if (this.config.secureCookies === false) return false
    const forwarded = headerValue(request?.headers, 'x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase()
    return forwarded === 'https' || this.listenerSecure()
  }

  loginRedirect(request, res, error) {
    const query = new URLSearchParams()
    if (error !== undefined) query.set('error', error)
    const suffix = query.size === 0 ? '' : `?${query.toString()}`
    redirect(res, `./login${suffix}`)
  }

  async handleLogin(request, res) {
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    if (request.method === 'GET' || request.method === 'HEAD') {
      const existing = this.identify(request)
      if (existing !== undefined) {
        redirect(res, './')
        return
      }
      const locale = serverLocale(headerValue(request.headers, 'accept-language'))
      sendHtml(res, 200, renderLoginPage({
        locale,
        provider: this.config.provider,
        error: url.searchParams.get('error') ?? undefined,
        needsSetup: this.store.needsSetup(),
        setupAvailable: this.config.setup.enabled,
      }))
      return
    }
    if (request.method !== 'POST') {
      send(res, 405, { allow: 'GET, HEAD, POST' })
      return
    }
    let body
    try {
      body = new URLSearchParams(await readBody(request, MAX_FORM_BYTES))
    } catch {
      this.loginRedirect(request, res, 'missing')
      return
    }
    const username = body.get('username') ?? ''
    const password = body.get('password') ?? ''
    if (username === '' || password === '') {
      this.loginRedirect(request, res, 'missing')
      return
    }
    let identity
    try {
      identity = await this.authenticate(username, password, request)
    } catch (error) {
      this.log?.warn?.(`web-user-auth: login failed: ${error instanceof Error ? error.message : String(error)}`)
      this.loginRedirect(request, res, 'error')
      return
    }
    if (identity === undefined) {
      this.loginRedirect(request, res, 'invalid')
      return
    }
    const user = await this.ensureUser(identity)
    this.setUserCookie(request, res, { ...identity, workspacePath: user.workspacePath })
    redirect(res, './')
  }

  setUserCookie(request, res, user) {
    const issuedAt = Date.now()
    const expiresAt = Math.floor(Math.min(issuedAt + this.config.cookieMaxAgeDays * DAY_MS,typeof user.expiresAt==='number'?user.expiresAt:Infinity))
    const token = signSession({
      v: 1,
      id: user.id,
      name: user.name,
      provider: user.provider,
      ...(user.tokenSessionId?{tokenSessionId:user.tokenSessionId}:{}),
      iat: issuedAt,
      exp: expiresAt,
    }, this.secret)
    res.setHeader('set-cookie', [sessionCookie(this.config.cookieName, token, {
      maxAgeSeconds: Math.max(0,Math.floor((expiresAt-issuedAt)/1000)),
      secure: this.requestSecure(request),
    }), clearCookie('dsh-admin-auth', { secure: this.requestSecure(request) })])
  }

  handleLogout(request, res) {
    const user = this.identify(request)
    if (user !== undefined) this.disposePeer(user.id)
    const cookies = [clearCookie(this.config.cookieName, { secure: this.requestSecure(request) })]
    for (const cookie of cookiesWithPrefix(request.headers.cookie, 'dsh-auth-')) {
      cookies.push(clearCookie(cookie.name, { secure: this.listenerSecure() }))
    }
    res.writeHead(303, {
      location: './login',
      'cache-control': 'no-store',
      'set-cookie': cookies,
    })
    res.end()
  }

  setupAllowed(request, token) {
    if (!this.config.setup.enabled || !this.store.needsSetup()) return false
    if (isLoopbackRequest(request)) return true
    return typeof token === 'string' && token !== '' && sameSecret(token, this.setupToken)
  }

  async handleSetup(request, res) {
    const url = new URL(request.url ?? '/', 'http://dsh.invalid')
    if (request.method === 'GET' || request.method === 'HEAD') {
      if (!this.store.needsSetup() || !this.config.setup.enabled) {
        this.loginRedirect(request, res, 'exists')
        return
      }
      const token = url.searchParams.get('token') ?? ''
      const allowed = this.setupAllowed(request, token)
      if (!allowed && !isLoopbackRequest(request)) {
        sendHtml(res, 403, renderMessagePage({
          locale: serverLocale(headerValue(request.headers, 'accept-language')),
          title: 'Setup unavailable',
          message: 'Open this page from the Harness host, or append the setup token from the plugin state directory.',
        }))
        return
      }
      const needsToken = !isLoopbackRequest(request)
      sendHtml(res, 200, renderSetupPage({
        locale: serverLocale(headerValue(request.headers, 'accept-language')),
        needsToken,
        token: needsToken ? token : undefined,
      }))
      return
    }
    if (request.method !== 'POST') {
      send(res, 405, { allow: 'GET, HEAD, POST' })
      return
    }
    let body
    try {
      body = new URLSearchParams(await readBody(request, MAX_FORM_BYTES))
    } catch {
      this.setupError(request, res, 'failed')
      return
    }
    const token = body.get('token') ?? ''
    if (!this.setupAllowed(request, token) && !isLoopbackRequest(request)) {
      this.setupError(request, res, 'failed')
      return
    }
    if (!this.store.needsSetup()) {
      this.setupError(request, res, 'exists')
      return
    }
    const username = (body.get('username') ?? '').trim()
    const name = (body.get('name') ?? '').trim()
    const password = body.get('password') ?? ''
    const confirm = body.get('confirm') ?? ''
    if (username === '' || password.length < 8) {
      this.setupError(request, res, password.length < 8 ? 'short' : 'failed')
      return
    }
    if (password !== confirm) {
      this.setupError(request, res, 'mismatch')
      return
    }
    try {
      const user = this.store.add({ id: username, name: name === '' ? username : name, password })
      const identity = this.ephemeralUser(user.id, user.name, 'local')
      const ensured = await this.ensureUser(identity)
      this.setUserCookie(request, res, { ...identity, workspacePath: ensured.workspacePath })
      redirect(res, './')
    } catch (error) {
      this.log?.warn?.(`web-user-auth: setup failed: ${error instanceof Error ? error.message : String(error)}`)
      this.setupError(request, res, 'failed')
    }
  }

  setupError(request, res, error) {
    const locale = serverLocale(headerValue(request.headers, 'accept-language'))
    sendHtml(res, 400, renderSetupPage({
      locale,
      error,
      needsToken: !isLoopbackRequest(request),
      token: '',
    }))
  }

  clearInvalidTokenCookie(request,res){
    if(this.config.provider!=='token')return
    if(readCookieValue(request?.headers?.cookie,this.config.cookieName)&&!this.identify(request)){
      res.setHeader('set-cookie',[clearCookie(this.config.cookieName,{secure:this.requestSecure(request)})])
    }
  }

  tokenClientConfig(request){
    if(!this.config.enabled||this.config.provider!=='token')return undefined
    if(request?.headers?.host!==new URL(this.config.token.siteOrigin).host)return undefined
    const {siteOrigin,storage,storageKey,storageField}=this.config.token
    return {siteOrigin,storage,storageKey,storageField,role:this.identify(request)?.administrator===true?'admin':'user'}
  }

  async handleToken(request,res){
    if(request.method!=='POST'){send(res,405,{allow:'POST'});return}
    const client=this.tokenClientConfig(request)
    if(!client){sendJson(res,403,{error:'Token 认证未启用，或访问站点不同源'});return}
    let origin;try{origin=new URL(request.headers.origin).origin}catch{}
    if(origin!==client.siteOrigin||request.headers['sec-fetch-site']&&request.headers['sec-fetch-site']!=='same-origin'){
      sendJson(res,403,{error:'Token 认证仅允许同源请求'});return
    }
    if(this.isAdmin(request)){sendJson(res,200,{administrator:true});return}
    let body;try{body=JSON.parse(await readBody(request,32768))}catch{sendJson(res,400,{error:'Token 请求格式不正确'});return}
    const cookie=verifySession(readCookieValue(request.headers.cookie,this.config.cookieName),this.secret)
    try{
      const {record,changed}=await this.tokenSessions.exchange(body.token,cookie?.provider==='token'?cookie.tokenSessionId:undefined)
      await this.ensureUser(record.identity)
      if(!this.tokenSessions.get(record.sid)||record.expiresAt<=Date.now()+1000){this.tokenSessions.revoke(record.sid);const error=new Error('Token 已过期或剩余有效期不足，请在业务系统重新登录');error.status=401;throw error}
      this.setUserCookie(request,res,{...record.identity,tokenSessionId:record.sid,expiresAt:record.expiresAt})
      sendJson(res,200,{id:record.identity.id,name:record.identity.name,changed})
    }catch(error){
      res.setHeader('set-cookie',[clearCookie(this.config.cookieName,{secure:this.requestSecure(request)})])
      sendJson(res,error.status===401?401:503,{error:error.status?error.message:'Token 校验暂不可用，未授予访问权限'})
    }
  }

  async handlePassword(request,res){
    const user=this.identify(request)
    if(this.isAdmin(request)||!user||user.provider!=='local'||this.config.provider!=='local'){
      sendJson(res,403,{error:'仅本地普通用户可修改自己的密码'});return
    }
    if(this.config.local.users.some(item=>item.id===user.id)){
      sendJson(res,403,{error:'此账号由静态配置管理，请联系管理员修改密码'});return
    }
    const csrf=crypto.createHmac('sha256',this.passwordCsrf).update(user.id).digest('hex')
    if(request.method==='GET'){sendJson(res,200,{csrf});return}
    if(request.method!=='POST'){send(res,405,{allow:'GET, POST'});return}
    let origin;try{origin=new URL(request.headers.origin).host}catch{}
    if(origin!==request.headers.host){sendJson(res,403,{error:'来源校验失败'});return}
    let form;try{form=new URLSearchParams(await readBody(request,8192))}catch{sendJson(res,413,{error:'提交内容过长'});return}
    if(form.get('csrf')!==csrf){sendJson(res,403,{error:'页面已过期，请刷新重试'});return}
    const attempts=(this.passwordAttempts.get(user.id)??[]).filter(time=>time>Date.now()-60000)
    if(attempts.length>=5){sendJson(res,429,{error:'尝试过于频繁，请一分钟后再试'});return}
    attempts.push(Date.now());this.passwordAttempts.set(user.id,attempts)
    if(!this.store.verify(user.id,form.get('currentPassword')??'')){sendJson(res,400,{error:'当前密码不正确'});return}
    const password=form.get('newPassword')??''
    if(password!==form.get('confirmPassword')){sendJson(res,400,{error:'两次输入的新密码不一致'});return}
    try{this.store.resetPassword(user.id,password)}catch(error){sendJson(res,400,{error:error.message});return}
    this.disposePeer(user.id)
    res.setHeader('set-cookie',[clearCookie(this.config.cookieName,{secure:this.requestSecure(request)})])
    sendJson(res,200,{message:'密码已修改，请重新登录。其他设备上的旧登录也已失效。'})
  }

  async handleMe(request, res) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      send(res, 405, { allow: 'GET, HEAD' })
      return
    }
    const user = this.identify(request)
    if (user === undefined) {
      sendJson(res, 401, { error: 'unauthenticated' })
      return
    }
    const ensured = await this.ensureUser(user)
    sendJson(res, 200, {
      id: user.id,
      name: user.name,
      provider: user.provider,
      workspace: ensured.workspacePath,
      workspaceId: ensured.workspaceId ?? null,
    })
  }

  async handleNewDirectory(request, res) {
    if (request.method !== 'POST') {
      send(res, 405, { allow: 'POST' })
      return
    }
    const user = this.identify(request)
    if (user === undefined) {
      sendJson(res, 401, { error: 'unauthenticated' })
      return
    }
    const ensured = await this.ensureUser(user)
    let body
    try {
      body = JSON.parse(await readBody(request, MAX_JSON_BYTES))
    } catch {
      sendJson(res, 400, { error: 'invalid-json' })
      return
    }
    let name
    try {
      name = directoryName(body?.name)
    } catch (error) {
      sendJson(res, 400, { error: 'invalid-name', message: error instanceof Error ? error.message : String(error) })
      return
    }
    const target = path.join(ensured.workspacePath, name)
    if (!contains(ensured.workspacePath, target)) {
      sendJson(res, 400, { error: 'outside-workspace' })
      return
    }
    try {
      fs.mkdirSync(target, { recursive: false, mode: 0o700 })
    } catch (error) {
      if (error?.code === 'EEXIST') {
        sendJson(res, 409, { error: 'exists' })
        return
      }
      sendJson(res, 400, { error: 'mkdir-failed', message: error instanceof Error ? error.message : String(error) })
      return
    }
    sendJson(res, 201, { name, path: target })
  }

  // ---------------------------------------------------------------------------
  // DSH patches
  // ---------------------------------------------------------------------------

  patchMethod(target, name, create) {
    this.patchDisposers.push(patchServiceMethod(target,name,original=>{
      const implementation=create(original)
      return function(...args){
        try{return implementation.apply(this,args)}catch(error){
          console.error('web-user-auth: request failure in '+name,error.stack)
          throw error
        }
      }
    }))
  }

  installPatches() {
    const connection = this.ctx.connection
    const runtime = this
    installPluginManagementGuards(this)

    this.patchMethod(connection, 'admit', (original) => function admit(request) {
      try {
        const user = runtime.isAdmin(request)
          ? runtime.ensureUserSync(administratorIdentity())
          : runtime.identify(request)
        if (user !== undefined) return { peer: runtime.peerForRequest(user, request) }
      } catch (error) {
        runtime.log?.warn?.(`web-user-auth: admission failed: ${error instanceof Error ? error.message : String(error)}`)
        return { rejection: 401 }
      }
      const admission = original.call(this, request)
      if (admission === null || typeof admission !== 'object' || !('peer' in admission)) return admission
      if (admission.peer.principal.kind !== 'owner') return admission
      if (runtime.config.allowOwnerLoopback && isLoopbackRequest(request)) return admission
      if (runtime.config.allowApiTokens && runtime.hasApiCookie(request)) return admission
      return { rejection: 401 }
    })

    this.patchMethod(connection, 'authorizeIndex', (original) => function authorizeIndex(request, response) {
      runtime.clearInvalidTokenCookie(request,response)
      if (runtime.isAdmin(request)) return true
      // A signed Web-user cookie is sufficient: the plugin's `admit` patch and
      // its exact Fetch routes use that cookie directly, so user pages never
      // travel through DSH's owner launch token.
      if (runtime.identify(request) !== undefined) return true
      const url = new URL(request.url ?? '/', 'http://dsh.invalid')
      if (url.searchParams.has('token')) return original.call(this, request, response)
      if (runtime.config.allowOwnerLoopback && isLoopbackRequest(request)) {
        const state = builtInCookieState(request.headers, runtime.listenerSecure())
        if (state.usable) return original.call(this, request, response)
      }
      redirect(response, './login')
      return false
    })

    const sessions = this.ctx.sessionController
    this.patchMethod(sessions, 'create', (original) => async function create(request) {
      const principal = this.ctx?.invocation?.peer?.principal
      const user = runtime.userFromPrincipal(principal)
      if (user === undefined) return original.apply(this, arguments)
      const ensured = await runtime.ensureUser(user)
      let cwd = ensured.workspacePath
      let workspaceId = ensured.workspaceId
      if (typeof request?.cwd === 'string' && request.cwd !== '') {
        const requested = canonicalPath(request.cwd)
        if (runtime.pathAllowed(user, requested)) {
          cwd = requested
          if (requested !== ensured.workspacePath) workspaceId = undefined
        }
      } else if (typeof request?.workspaceId === 'string') {
        try {
          const workspace = runtime.ctx.workspaceRegistry.get(request.workspaceId)
          if (workspace === undefined || !runtime.pathAllowed(user, workspace.path)) throw new Error('web-user-auth: workspace is outside the user workspace')
          cwd = workspace.path
          workspaceId = workspace.id
        } catch (error) {
          throw new Error('web-user-auth: selected workspace is unavailable or not owned by this user', { cause: error })
        }
      }
      const location = workspaceId === undefined ? { cwd, workspaceId: undefined } : { cwd: undefined, workspaceId }
      const result = await original.call(this, { ...request, ...location })
      runtime.policy?.rememberSession(result.sessionId, cwd)
      return result
    })

    this.patchMethod(sessions, 'list', (original) => async function list(request, signal) {
      const result = await original.call(this, request, signal)
      const principal = this.ctx?.invocation?.peer?.principal
      const user = runtime.userFromPrincipal(principal)
      if (user === undefined || !Array.isArray(result?.items)) return result
      return { ...result, items: result.items.filter((item) => runtime.ownsSession(user.id, item.sessionId)) }
    })

    this.patchMethod(sessions, 'search', (original) => async function search(request, signal) {
      const result = await original.call(this, request, signal)
      const principal = this.ctx?.invocation?.peer?.principal
      const user = runtime.userFromPrincipal(principal)
      if (user === undefined || !Array.isArray(result?.items)) return result
      return { ...result, items: result.items.filter((item) => runtime.ownsSession(user.id, item.sessionId)) }
    })

    this.patchMethod(sessions, 'openWorkspacePath', (original) => async function openWorkspacePath(request, signal) {
      const user = runtime.userFromPrincipal(this.ctx?.invocation?.peer?.principal)
      if (user !== undefined && typeof request?.path === 'string' && !runtime.pathAllowed(user, request.path)) {
        throw new Error('web-user-auth: path is outside the user workspace')
      }
      return original.call(this, request, signal)
    })

    this.patchMethod(sessions, 'workspacePathApplications', (original) => async function workspacePathApplications(request, signal) {
      const user = runtime.userFromPrincipal(this.ctx?.invocation?.peer?.principal)
      if (user !== undefined && typeof request?.path === 'string' && !runtime.pathAllowed(user, request.path)) {
        throw new Error('web-user-auth: path is outside the user workspace')
      }
      return original.call(this, request, signal)
    })

    const directoryPicker = this.ctx.directoryPickerController
    this.patchMethod(directoryPicker, 'pick', (original) => async function pick(signal) {
      const user = runtime.userFromPrincipal(this.ctx?.invocation?.peer?.principal)
      if (user === undefined) return original.call(this, signal)
      const ensured = await runtime.ensureUser(user)
      return ensured.workspacePath
    })

    this.patchMethod(directoryPicker, 'list', (original) => async function list(target, signal) {
      const user = runtime.userFromPrincipal(this.ctx?.invocation?.peer?.principal)
      if (user === undefined) return original.call(this, target, signal)
      const ensured = await runtime.ensureUser(user)
      const scoped = target === undefined || target === '' ? ensured.workspacePath : runtime.resolveAllowed(user, target)
      return original.call(this, scoped, signal)
    })

    this.patchMethod(directoryPicker, 'createDirectory', (original) => async function createDirectory(target, name) {
      const user = runtime.userFromPrincipal(this.ctx?.invocation?.peer?.principal)
      if (user === undefined) return original.call(this, target, name)
      const ensured = await runtime.ensureUser(user)
      const parent = target === undefined || target === '' ? ensured.workspacePath : runtime.resolveAllowed(user, target)
      const directory = directoryName(name)
      const final = path.join(parent, directory)
      if (!runtime.pathAllowed(user, final)) throw new Error('web-user-auth: path is outside the user workspace')
      return original.call(this, parent, directory)
    })

    const workspaceController = this.ctx.get?.('workspaceController')
    if (workspaceController !== undefined) {
      this.patchMethod(workspaceController, 'create', (original) => async function create(request) {
        const user = runtime.userFromPrincipal(this.ctx?.invocation?.peer?.principal)
        if (user !== undefined && typeof request?.path === 'string' && !runtime.pathAllowed(user, request.path)) {
          throw new Error('web-user-auth: workspace path is outside the user workspace')
        }
        return original.call(this, request)
      })
    }

    // Optional services may appear or reload after Auth. Keep their guards in
    // the service's dependency fiber and remove them when that fiber stops.
    const scopedService = (name, install) => {
      if (typeof this.ctx.inject === 'function') {
        const fiber = this.ctx.inject([name], scope => {
          scope.effect(() => {
            const service = scope.get(name)
            const disposers = []
            const cleanup = install(service, (method, create) => {
              disposers.push(patchServiceMethod(service, method, create))
            })
            return () => {
              cleanup?.()
              for (const dispose of disposers.reverse()) dispose()
            }
          })
        })
        this.patchDisposers.push(() => fiber.dispose())
      } else {
        const service = this.ctx.get?.(name)
        if (service !== undefined) {
          const cleanup = install(service, (method, create) => this.patchMethod(service, method, create))
          if (cleanup) this.patchDisposers.push(cleanup)
        }
      }
    }

    scopedService('schedule', (schedule, patch) => {
      if (typeof schedule.catalog !== 'function') return
      patch('catalog', original => async function catalog(...args) {
        const result = await original.apply(this, args)
        const principal = this.ctx?.invocation?.peer?.principal
        const user = runtime.userFromPrincipal(principal)
        if (user === undefined && ['harness-user', 'harness-admin'].includes(principal?.kind)) throw new Error('web-user-auth: authenticated user is unavailable')
        return user === undefined ? result : result.filter(task => runtime.ownsSession(user.id, task.sessionId))
      })
      const ready = value => {
        this.scheduleCatalogGuarded = value
        try { this.ctx.remoteAccess.invalidate() } catch { /* The Host may be shutting down. */ }
      }
      ready(true)
      return () => ready(false)
    })

    scopedService('workspaceFiles', (workspaceFiles, patch) => {
      const guard = (invocation, scope, target, options) => {
        const principal = invocation?.peer?.principal
        const user = runtime.userFromPrincipal(principal)
        if (user === undefined && ['harness-user', 'harness-admin'].includes(principal?.kind)) throw new Error('web-user-auth: authenticated user is unavailable')
        if (user === undefined) return
        if (scope === null || typeof scope !== 'object' || typeof scope.sessionId !== 'string' || !runtime.ownsSession(user.id, scope.sessionId)) {
          throw new Error('web-user-auth: session is not owned by the current user')
        }
        const allowed = value => {
          if (!runtime.pathAllowed(user, value)) throw new Error('web-user-auth: path is outside the user workspace')
          return value
        }
        // Match Harness: paths are relative to the Session header, and byte
        // reads with baseFile are relative to that file's canonical directory.
        let base = scope.workspaceRoot
        if (typeof options?.baseFile === 'string') {
          const baseFile = allowed(resolveAgainst(base, options.baseFile))
          base = path.dirname(canonicalPath(baseFile))
          target = target.replace(/\\/g, '/')
        }
        if (typeof target === 'string') allowed(resolveAgainst(base, target))
      }
      for (const method of ['read', 'readBytes', 'stat', 'list']) {
        patch(method, (original) => async function scoped(scope, target, ...rest) {
          guard(this.ctx?.invocation, scope, target, method === 'readBytes' ? rest[0] : undefined)
          return original.call(this, scope, target, ...rest)
        })
      }
      patch('changes', (original) => function changes(scope, target, ...rest) {
        guard(this.ctx?.invocation, scope, target)
        return original.call(this, scope, target, ...rest)
      })
    })
  }

  hasApiCookie(request) {
    const state = builtInCookieState(request.headers, this.listenerSecure())
    if (!state.present || state.name === undefined) return false
    const value = readCookie(request.headers.cookie, state.name)
    return typeof value === 'string' && value.startsWith('v2.')
  }

  pathAllowed(user, target) {
    try {
      const root = this.workspacePathOf(user.id)
      const candidate = canonicalPath(resolveAgainst(root, target))
      if (user.id !== ADMIN_USER_ID) return this.userRoots.some(base=>contains(path.join(base,userDirectoryName(user.id)),candidate))
      if (this.userForCwd(candidate) !== ADMIN_USER_ID) return false
      if (contains(root, candidate)) return true
      if (contains(canonicalPath(homeDirectory()), candidate)) return false
      return this.ctx.workspaceRegistry.list().some(workspace => this.userForCwd(workspace.path) === ADMIN_USER_ID && contains(canonicalPath(workspace.path), candidate))
    } catch {
      return false
    }
  }

  resolveAllowed(user, target) {
    const root = this.workspacePathOf(user.id)
    const resolved = resolveAgainst(root, target)
    if (!this.pathAllowed(user, resolved)) throw new Error('web-user-auth: path is outside the user workspace')
    return resolved
  }
}

/**
 * Plugin entry point.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {unknown} rawConfig
 */
export async function apply(ctx, rawConfig) {
  const settingsFile = path.join(homeDirectory(), 'web-admin', 'auth-settings.json')
  let saved = {}
  try { saved = JSON.parse(fs.readFileSync(settingsFile, 'utf8')) } catch (error) { if (error.code !== 'ENOENT') throw error }
  let config = normalizeConfig(mergeSavedSettings(rawConfig, saved))
  let runtime
  const handoff=createNativeHandoff(ctx)
  const isAdmin = installAdmin(ctx, homeDirectory(), () => config.enabled, {
    identifyUser: request => runtime?.identify(request),
    clearTokenCookie: (request,res)=>runtime?.clearInvalidTokenCookie(request,res),
    tokenClientConfig: request=>runtime?.tokenClientConfig(request),
    tokenLoginMarkup: request=>{const config=runtime?.tokenClientConfig(request);return config?tokenLoginMarkup(config):''},
    onPasswordChanged: () => runtime?.disposePeer(ADMIN_USER_ID),
    canChangePassword: id => config.provider==='local'&&!config.local.users.some(user=>user.id===id),
    adminPeer: () => runtime?.peerForUser(runtime.ensureUserSync(administratorIdentity())),
    loginUser: async (username, password, request, res) => {
      if (!runtime) return false
      const identity = await runtime.authenticate(username, password, request)
      if (!identity) return false
      await runtime.ensureUser(identity)
      runtime.setUserCookie(request, res, identity)
      redirect(res, './')
      return true
    },
  })
  async function activate(next) {
    runtime?.dispose()
    runtime = undefined
    config = next
    runtime = new WebUserAuthRuntime(ctx, config, isAdmin)
    runtime.handoffAuthorized=handoff.authorized
    try { await runtime.start() } catch (error) { console.error("web-user-auth: activation failed", error.stack); throw error }
  }
  await activate(config)
  installManagement(ctx, {
    isAdmin: request=>isAdmin(request)||runtime?.identify(request)?.administrator===true,
    handoff,
    getConfig: () => config,
    reloadUsers: (userId) => {
      runtime?.store.load()
      if (userId !== undefined) runtime?.disposePeer(userId)
    },
    update: async (patch) => {
      const previous = config
      const next = normalizeConfig({ ...config, ...patch })
      try {
        await activate(next)
        const temporary = settingsFile + '.tmp'
        fs.writeFileSync(temporary, JSON.stringify(persistedSettings(next)) + '\n', { mode: 0o600 })
        fs.renameSync(temporary, settingsFile)
      } catch (error) {
        await activate(previous)
        throw error
      }
    },
  })
}
