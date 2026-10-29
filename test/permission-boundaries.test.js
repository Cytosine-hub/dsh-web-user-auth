import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { apply } from '../lib/plugin.js'
import { ADMIN_USER_ID } from '../lib/identity.js'
import { userDirectoryName } from '../lib/paths.js'

async function fixture(t, { deferred = false } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-permissions-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const root = path.join(home, 'users')
  const directories = Object.fromEntries(['alice', 'bob', ADMIN_USER_ID].map(id => {
    const directory = path.join(root, userDirectoryName(id))
    fs.mkdirSync(directory, { recursive: true })
    return [id, directory]
  }))
  const nested = path.join(directories.alice, 'nested')
  fs.mkdirSync(nested)
  fs.writeFileSync(path.join(directories.alice, 'own.txt'), 'alice-owned')
  fs.writeFileSync(path.join(directories.bob, 'base.txt'), 'bob-base')
  fs.writeFileSync(path.join(directories.bob, 'secret.txt'), 'bob-private')
  fs.symlinkSync(directories.bob, path.join(nested, 'escape'), 'dir')
  const headers = [
    { id: 'alice-root', cwd: directories.alice },
    { id: 'alice-nested', cwd: nested },
    { id: 'bob-root', cwd: directories.bob },
    { id: 'admin-root', cwd: directories[ADMIN_USER_ID] },
  ]
  const tasks = headers.map(header => ({ id: 'task-' + header.id, sessionId: header.id }))
  const disposers = []
  const nativePath = (scope, target) => path.resolve(scope.workspaceRoot, target)
  const files = {
    async read(scope, target) { return fs.readFileSync(nativePath(scope, target), 'utf8') },
    async readBytes(scope, target, options = {}) {
      const base = options.baseFile === undefined ? scope.workspaceRoot
        : path.dirname(fs.realpathSync(nativePath(scope, options.baseFile)))
      return fs.readFileSync(path.resolve(base, target.replace(/\\/g, '/')))
    },
    async stat(scope, target) { return fs.statSync(nativePath(scope, target)) },
    async list(scope, target) { return fs.readdirSync(nativePath(scope, target)) },
    async *changes(scope, target) { yield { path: fs.realpathSync(nativePath(scope, target)) } },
  }
  const schedule = { async catalog() { return tasks } }
  const policies = new Map()
  const ctx = {
    invocation: { peer: { principal: { kind: 'harness-user', userId: 'alice' } } },
    logger: { info() {}, warn() {} },
    on() { return () => {} },
    effect(fn) { const dispose = fn(); if (typeof dispose === 'function') disposers.push(dispose) },
    get(key) { return key === 'workspaceFiles' ? files : key === 'schedule' ? schedule : undefined },
    connection: { browserPeer: { principal: { kind: 'owner' } }, admit() { return { rejection: 401 } }, authorizeIndex() { return false } },
    webServer: { protocol: 'http:', register() { return () => {} } },
    remoteAccess: { registerPolicy(kind, policy) { policies.set(kind, policy); return () => {} }, invalidate() {} },
    sessions: { list: () => headers.map(header => ({ header })) },
    sessionPersistence: { list: async () => [] },
    sessionController: {}, directoryPickerController: {},
    workspaceRegistry: { list: () => [] },
    typert: { local: { list: () => [{ namespace: 'schedule', method: 'catalog' }] } },
  }
  files.ctx = ctx
  schedule.ctx = ctx
  t.after(() => {
    for (const dispose of disposers.reverse()) dispose()
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
    fs.rmSync(home, { recursive: true, force: true })
  })
  const optional = new Map()
  if (deferred) ctx.inject = ([name], callback) => {
    let cleanups = []
    const lifecycle = {
      load() {
        callback({ ...ctx, effect(fn) { cleanups.push(fn()) } })
      },
      dispose() { for (const cleanup of cleanups.splice(0).reverse()) cleanup?.() },
    }
    optional.set(name, lifecycle)
    return lifecycle
  }
  await apply(ctx, { enabled: true, workspaceRoot: root, setup: { enabled: false } })
  return { ctx, files, schedule, policies, directories, optional,
    scope: { sessionId: 'alice-root', workspaceRoot: directories.alice },
    nestedScope: { sessionId: 'alice-nested', workspaceRoot: nested } }
}

test('TC-AUTH-PERM-001 relative file paths use the session cwd and deny foreign symlink targets', async t => {
  const f = await fixture(t)
  for (const method of ['read', 'readBytes', 'stat']) {
    await assert.rejects(f.files[method](f.nestedScope, 'escape/secret.txt'), /outside the user workspace/)
  }
  assert.throws(() => f.files.changes(f.nestedScope, 'escape/secret.txt'), /outside the user workspace/)
  assert.equal(await f.files.read(f.nestedScope, '../own.txt'), 'alice-owned')
  assert.equal(await f.files.read(f.scope, 'own.txt'), 'alice-owned')
})

test('TC-AUTH-PERM-002 byte reads validate the base file and the resolved target', async t => {
  const f = await fixture(t)
  await assert.rejects(f.files.readBytes(f.scope, 'secret.txt', {
    baseFile: path.join(f.directories.bob, 'base.txt'),
  }), /outside the user workspace/)
  await assert.rejects(f.files.readBytes(f.nestedScope, 'secret.txt', {
    baseFile: 'escape/base.txt',
  }), /outside the user workspace/)
  await assert.rejects(f.files.readBytes(f.scope, '../' + userDirectoryName('bob') + '/secret.txt', {
    baseFile: 'own.txt',
  }), /outside the user workspace/)
  assert.equal((await f.files.readBytes(f.nestedScope, 'own.txt', {
    baseFile: '../own.txt',
  })).toString(), 'alice-owned')
  await assert.rejects(f.files.readBytes(f.scope, '../own.txt', {
    baseFile: 'own.txt',
  }), /outside the user workspace/)
})

test('TC-AUTH-PERM-003 reminder catalog is globally callable but contains only owned sessions', async t => {
  const f = await fixture(t)
  const alice = { kind: 'harness-user', userId: 'alice' }
  const global = f.policies.get('harness-user').bindings(alice).find(binding => binding.resource.kind === 'global')
  assert.ok(global.role.actions.includes('schedule/catalog'))
  assert.deepEqual((await f.schedule.catalog()).map(task => task.sessionId), ['alice-root', 'alice-nested'])
  f.ctx.invocation.peer.principal = { kind: 'harness-user', userId: 'bob' }
  assert.deepEqual((await f.schedule.catalog()).map(task => task.sessionId), ['bob-root'])
  f.ctx.invocation.peer.principal = { kind: 'harness-admin', userId: ADMIN_USER_ID }
  assert.deepEqual((await f.schedule.catalog()).map(task => task.sessionId), ['admin-root'])
  f.ctx.invocation.peer.principal = { kind: 'owner' }
  assert.equal((await f.schedule.catalog()).length, 4)
})


test('TC-AUTH-PERM-004 optional service guards survive reload and deny an unguarded catalog', async t => {
  const f = await fixture(t, { deferred: true })
  const principal = f.ctx.invocation.peer.principal
  const decision = () => f.policies.get('harness-user').bindings(principal)
    .find(binding => binding.resource.kind === 'global').condition({ action: 'schedule/catalog' }).kind
  assert.equal(decision(), 'deny')
  const nativeRead = f.files.read
  for (let generation = 0; generation < 2; generation++) {
    f.optional.get('schedule').load()
    f.optional.get('workspaceFiles').load()
    assert.equal(decision(), 'allow')
    assert.deepEqual((await f.schedule.catalog()).map(task => task.sessionId), ['alice-root', 'alice-nested'])
    await assert.rejects(f.files.read(f.nestedScope, 'escape/secret.txt'), /outside the user workspace/)
    f.optional.get('schedule').dispose()
    f.optional.get('workspaceFiles').dispose()
    assert.equal(decision(), 'deny')
    assert.equal(f.files.read, nativeRead)
  }
})

test('TC-AUTH-PERM-005 an expired administrator cannot fall back to unscoped service access', async t => {
  const f = await fixture(t)
  f.ctx.invocation.peer.principal = { kind: 'harness-admin', userId: 'expired-token-admin' }
  await assert.rejects(f.schedule.catalog(), /authenticated user is unavailable/)
  await assert.rejects(f.files.read(f.scope, path.join(f.directories.bob, 'secret.txt')), /authenticated user is unavailable/)
})
