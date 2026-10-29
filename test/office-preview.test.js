import assert from 'node:assert/strict'
import test from 'node:test'
import { createUserAccessPolicy } from '../lib/policy.js'

test('TC-AUTH-OFFICE-001 preview generation is global, rendering remains session scoped', () => {
  const { policy, rememberSession } = createUserAccessPolicy({
    ctx: {
      typert: { local: { list: () => [
        { namespace: 'officeToPdf', method: 'generation' },
        { namespace: 'officeToPdf', method: 'render' },
      ] } },
      workspaceRegistry: { list: () => [] },
      remoteAccess: { invalidate() {} },
    },
    workspaceRoot: '/users',
    workspaceOf: id => '/users/' + id,
    userForPath: cwd => cwd === '/users/alice' ? 'alice' : undefined,
    isAdministrator: id => id === 'sysadmin',
  })
  rememberSession('alice-session', '/users/alice')
  for (const principal of [
    { kind: 'harness-user', userId: 'alice' },
    { kind: 'harness-admin', userId: 'sysadmin' },
  ]) {
    const bindings = policy.bindings(principal)
    const global = bindings.find(binding => binding.resource.kind === 'global')
    assert.ok(global.role.actions.includes('officeToPdf/generation'))
    assert.ok(!global.role.actions.includes('officeToPdf/render'))
    const sessions = bindings.filter(binding => binding.resource.kind === 'session')
    assert.deepEqual(sessions.map(binding => binding.resource.id), principal.userId === 'alice' ? ['alice-session'] : [])
    for (const session of sessions) assert.ok(session.role.actions.includes('officeToPdf/render'))
  }
  assert.deepEqual(policy.bindings({ kind: 'anonymous' }), [])
})
