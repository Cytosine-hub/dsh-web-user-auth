import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { signSession } from '../lib/cookies.js'
import { ADMIN_USER_ID } from '../lib/identity.js'
import { userDirectoryName } from '../lib/paths.js'
import { apply } from '../lib/plugin.js'

async function fixture(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-file-routes-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const root = path.join(home, 'workspaces')
  const directories = Object.fromEntries(['alice', 'bob', ADMIN_USER_ID].map(id => {
    const directory = path.join(root, userDirectoryName(id))
    fs.mkdirSync(directory, { recursive: true })
    return [id, directory]
  }))
  const routes = new Map()
  const disposers = []
  const dispose = () => { for (const cleanup of disposers.splice(0).reverse()) cleanup() }
  let uploaded = 0
  const connection = {
    browserPeer: { principal: { kind: 'owner' } },
    admit() { return { rejection: 401 } },
    authorizeIndex() { return false },
    createPeer({ principal }) {
      return { principal, signal: { aborted: false }, dispose() { this.signal.aborted = true } }
    },
    // Match Harness: the /api carrier captures this handler before Auth starts.
    createSharedFetchHandler() {
      return {
        requestBodyMode: ({ url }) => url.pathname === '/api/session/uploadFileBinary' ? 'streaming' : 'buffered',
        async fetch(request, peer) {
          if (peer.principal.kind !== 'owner') return new Response('forbidden', { status: 403 })
          if (new URL(request.url).pathname === '/api/session/uploadFileBinary') {
            uploaded++
            return Response.json({ bytes: (await request.arrayBuffer()).byteLength })
          }
          return new Response(request.method === 'HEAD' ? null : 'owned file')
        },
      }
    },
  }
  const captured = connection.createSharedFetchHandler('/api')
  const ctx = {
    logger: { info() {}, warn() {} },
    on() { return () => {} },
    effect(fn) { const dispose = fn(); if (typeof dispose === 'function') disposers.push(dispose) },
    get() {},
    connection,
    webServer: { protocol: 'http:', register(row) { routes.set(row.path, row.handler); return () => {} } },
    remoteAccess: { registerPolicy() { return () => {} }, invalidate() {} },
    sessions: { list: () => Object.entries(directories).map(([id, cwd]) => ({ header: { id: 'session-' + id, cwd } })) },
    sessionPersistence: { list: async () => [] },
    sessionController: {},
    directoryPickerController: {},
    workspaceRegistry: { list: () => [], create: async directory => ({ id: directory }) },
    typert: { local: { list: () => [] } },
  }
  t.after(() => {
    dispose()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    fs.rmSync(home, { recursive: true, force: true })
  })
  await apply(ctx, {
    enabled: true,
    workspaceRoot: root,
    allowOwnerLoopback: false,
    local: { users: [{ id: 'alice', name: 'Alice', password: 'fixture-password' }] },
  })
  const secret = Buffer.from(fs.readFileSync(path.join(home, 'web-user-auth/secret'), 'utf8').trim(), 'base64url')
  const cookie = (expiresAt = Date.now() + 60_000) => 'dsh-user-auth=' + signSession({
    v: 1, id: 'alice', name: 'Alice', provider: 'local', iat: Date.now(), exp: expiresAt,
  }, secret)
  const request = (url, method = 'POST', auth = cookie()) => ({
    url, method, headers: { host: 'example.test', cookie: auth }, socket: { remoteAddress: '203.0.113.1' },
  })
  async function dispatch(req, body) {
    const admission = connection.admit(req)
    if ('rejection' in admission) return new Response(null, { status: admission.rejection })
    return captured.fetch(new Request(new URL(req.url, 'http://example.test'), {
      method: req.method,
      ...(body === undefined ? {} : { body }),
    }), admission.peer)
  }
  async function adminCookie() {
    const password = fs.readFileSync(path.join(home, 'web-admin/initial-password.txt'), 'utf8').trim()
    const login = Object.assign((async function* () {
      yield Buffer.from(new URLSearchParams({ username: 'admin', password }).toString())
    })(), { method: 'POST', headers: { host: 'example.test', origin: 'http://example.test' } })
    const res = {
      headers: {},
      setHeader(name, value) { this.headers[name] = value },
      writeHead(status, headers) { this.status = status; Object.assign(this.headers, headers) },
      end() {},
    }
    await routes.get('/admin')(login, res)
    assert.equal(res.status, 303)
    return res.headers['set-cookie'][0].split(';')[0]
  }
  return { connection, captured, directories, cookie, request, dispatch, adminCookie, dispose, uploaded: () => uploaded }
}

test('TC-AUTH-FILE-001 captured native handler accepts owned streaming uploads after Auth starts', async t => {
  const f = await fixture(t)
  for (const name of ['sample.txt', '网关搭建测试环境.doc']) {
    const url = '/api/session/uploadFileBinary?' + new URLSearchParams({ sessionId: 'session-alice', name })
    assert.equal(f.captured.requestBodyMode({ url: new URL(url, 'http://example.test') }), 'streaming')
    for (const bytes of [32, 1024 * 1024]) {
      const response = await f.dispatch(f.request(url), Buffer.alloc(bytes, 65))
      assert.equal(response.status, 200)
      assert.deepEqual(await response.json(), { bytes })
    }
  }
})

test('TC-AUTH-FILE-002 uploads reject anonymous, expired, tampered, foreign and missing identities', async t => {
  const f = await fixture(t)
  const own = '/api/session/uploadFileBinary?sessionId=session-alice'
  for (const auth of ['', f.cookie(Date.now() - 1000), f.cookie() + 'tampered']) {
    assert.equal((await f.dispatch(f.request(own, 'POST', auth), 'test')).status, 401)
  }
  for (const suffix of ['', '?sessionId=', '?sessionId=unknown', '?sessionId=session-bob']) {
    assert.equal((await f.dispatch(f.request('/api/session/uploadFileBinary' + suffix), 'test')).status, 403)
  }
  assert.equal(f.uploaded(), 0)
})

test('TC-AUTH-FILE-003 RPC, WebSocket and nonmatching file requests keep non-owner user peers', async t => {
  const f = await fixture(t)
  const baseline = f.connection.admit(f.request('/api/session/list')).peer
  for (const [url, method] of [
    ['/api/remote.mux', 'GET'],
    ['/api/settings/update?path=/api/file', 'POST'],
    ['/api/session/uploadFileBinary/extra?sessionId=session-alice', 'POST'],
    ['/api/session/uploadFileBinary?sessionId=session-alice', 'GET'],
    ['/api/file?path=' + encodeURIComponent(f.directories.alice), 'POST'],
    ['/api/file/extra?path=' + encodeURIComponent(f.directories.alice), 'GET'],
  ]) {
    assert.equal(f.connection.admit(f.request(url, method)).peer, baseline)
  }
  assert.equal(baseline.principal.kind, 'harness-user')
  assert.equal(f.connection.browserPeer.principal.kind, 'owner')
})

test('TC-AUTH-FILE-004 administrator uploads remain scoped to administrator-owned sessions', async t => {
  const f = await fixture(t)
  const auth = await f.adminCookie()
  assert.equal(f.connection.admit(f.request('/api/settings/describe', 'POST', auth)).peer.principal.kind, 'harness-admin')
  const own = '/api/session/uploadFileBinary?sessionId=session-' + ADMIN_USER_ID
  assert.equal((await f.dispatch(f.request(own, 'POST', auth), 'admin file')).status, 200)
  const foreign = '/api/session/uploadFileBinary?sessionId=session-alice'
  assert.equal((await f.dispatch(f.request(foreign, 'POST', auth), 'test')).status, 403)
})

test('TC-AUTH-FILE-005 GET and HEAD files allow own paths and reject foreign or symlink escapes', async t => {
  const f = await fixture(t)
  const link = path.join(f.directories.alice, 'foreign-link')
  fs.symlinkSync(f.directories.bob, link)
  for (const method of ['GET', 'HEAD']) {
    const own = '/api/file?' + new URLSearchParams({ path: path.join(f.directories.alice, 'report.doc') })
    assert.equal((await f.dispatch(f.request(own, method))).status, 200)
    for (const target of [f.directories.bob, '/etc/passwd', link, f.directories.alice + '/../' + userDirectoryName('bob')]) {
      const url = '/api/file?' + new URLSearchParams({ path: target })
      assert.equal((await f.dispatch(f.request(url, method))).status, 403)
    }
    assert.equal((await f.dispatch(f.request('/api/file', method))).status, 403)
  }
})

test('TC-AUTH-FILE-006 teardown restores native admission without mutating shared peers', async t => {
  const f = await fixture(t)
  const request = f.request('/api/session/uploadFileBinary?sessionId=session-alice')
  const ordinary = f.connection.admit(f.request('/api/session/list')).peer
  assert.equal((await f.dispatch(request, 'test')).status, 200)
  assert.equal(ordinary.principal.kind, 'harness-user')
  f.dispose()
  assert.equal(f.connection.admit(request).rejection, 401)
  assert.equal(ordinary.signal.aborted, true)
  assert.equal(f.connection.browserPeer.principal.kind, 'owner')
})
