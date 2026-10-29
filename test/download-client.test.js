import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'
import test from 'node:test'

test('TC-AUTH-FILE-010 authenticated delivery cards offer a browser download independently of desktop availability', async () => {
  const source = fs.readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8')
  for (const role of ['user', 'admin', 'anonymous']) {
    let plugin
    const slots = new Map()
    const window = {
      location: { href: 'https://example.test/assistant/' },
      __ModuleLoader__: { load({ factory }) { plugin = factory(() => ({
        createElement: (type, props, ...children) => ({ type, props, children }),
      })) } },
    }
    vm.runInNewContext(source, {
      window, URL, URLSearchParams,
      fetch: async () => ({ status: 200, ok: true, json: async () => ({ role, provider: 'token' }) }),
    })
    await plugin.apply({
      effect: fn => fn(),
      locale: { register() {}, bind: () => key => key },
      layout: {},
      slots: { inject: (_name, fn) => fn(), register: (descriptor, view) => {
        if (descriptor.name === 'deliverables.file.actions') assert.equal(descriptor.id, 'web-user-auth-download')
        slots.set(descriptor.name, view)
      } },
    })
    const view = slots.get('deliverables.file.actions')
    if (role === 'anonymous') { assert.equal(view, undefined); continue }
    assert.equal(typeof view, 'function')
    const link = view({ actionUrl: 'api/present.open?sessionId=own&seq=12&index=1', available: false })
    assert.equal(link.type, 'a')
    const target = new URL(link.props.href)
    assert.equal(target.pathname, '/assistant/api/auth/download')
    assert.equal(target.searchParams.get('sessionId'), 'own')
    assert.equal(target.searchParams.get('seq'), '12')
    assert.equal(target.searchParams.get('index'), '1')
    assert.equal(link.props.download, '')
  }
})
