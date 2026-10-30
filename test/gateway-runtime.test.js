import assert from 'node:assert/strict'
import { test as nodeTest } from 'node:test'
import {installInteractions} from '../lib/interactions.js'
import {patchServiceMethod} from '../lib/service-patch.js'
import { pathToFileURL } from 'node:url'

// Run against the installed Gateway, before and after the build-time compatibility fix.
const target = process.env.DSH_GATEWAY_ENTRY
const { TypertGatewayService } = target ? await import(pathToFileURL(target)) : {}
const test=(name,fn)=>nodeTest(name,{skip:!target},fn)
function fixture(kind = 'harness-user', userId = 'alice', event = 'approval/request') {
  const gateway = Object.create(TypertGatewayService.prototype)
  let allowed = true
  Object.defineProperty(gateway, 'ctx', { value: { remoteAccess: { decide: ({ principal, resources, action }) => ({
    kind: allowed && principal.userId === 'alice' && resources.length === 1 && resources[0].kind === 'session' && resources[0].id === 'session-a' && action === 'session/control' ? 'allow' : 'deny',
  }) } } })
  gateway.remoteEventClients = new Map()
  gateway.pendingRemoteEvents = new Map()
  gateway.remoteEvents = { lifetime: new AbortController(), host: {} }
  const peer = { principal: { kind, userId }, interactions: 'answer', signal: new AbortController().signal }
  const pending = { id: 'event-a', source: { event, context: { subject: { session: { id: 'session-a' } } } }, frame: { type: 'waterfall', event, eventId: 'event-a' }, deliveries: new Set() }
  gateway.pendingRemoteEvents.set(pending.id, pending)
  const disposers=[]
  const cleanup=installInteractions({ctx:gateway.ctx,userFromPrincipal:p=>({id:p.userId}),ownsSession:(id,sessionId)=>id==='alice'&&sessionId==='session-a'},gateway,(name,create)=>disposers.push(patchServiceMethod(gateway,name,create)))
  const stream = gateway.openRemoteEvents({ args: {} }, new AbortController().signal, peer)
  return { gateway, peer, pending, stream, cleanup:()=>{cleanup();for(const dispose of disposers.reverse())dispose()}, revoke: () => { allowed = false } }
}
async function opened(f) {
  const ready = await f.stream.next()
  return f.gateway.remoteEventClients.get(ready.value.clientId)
}

test('TC-DSH-APPROVAL-001 本人会话审批可投递并通过原生回答入口处理', async () => {
  const f = fixture()
  const client = await opened(f)
  try {
    assert.equal(client.deliveries.has('event-a'), true)
    let settled
    f.gateway.settleRemoteEvent = (_, outcome) => { settled = outcome }
    const response = await f.gateway.dispatchRpc('$events/result', { args: { clientId: client.id, eventId: 'event-a', outcome: { kind: 'result', value: true } } }, undefined, f.peer)
    assert.equal(response.ok, true)
    assert.deepEqual(settled, { kind: 'result', value: true })
  } finally { await f.stream.return() }
})

test('TC-DSH-APPROVAL-002 普通用户及管理员均不得接收他人审批', async () => {
  for (const kind of ['harness-user', 'harness-admin']) {
    const f = fixture(kind, 'bob')
    const client = await opened(f)
    try { assert.equal(client.deliveries.size, 0) } finally { await f.stream.return() }
  }
})

test('TC-DSH-APPROVAL-003 审批回答时重新校验归属且拒绝其他 Peer', async () => {
  const f = fixture()
  const client = await opened(f)
  try {
    let settled = false
    f.gateway.settleRemoteEvent = () => { settled = true }
    const payload = { args: { clientId: client.id, eventId: 'event-a', outcome: { kind: 'result', value: true } } }
    const foreign = await f.gateway.dispatchRpc('$events/result', payload, undefined, { ...f.peer })
    assert.equal(foreign.ok, false)
    f.revoke()
    const revoked = await f.gateway.dispatchRpc('$events/result', payload, undefined, f.peer)
    assert.equal(revoked.ok, false)
    assert.equal(settled, false)
  } finally { await f.stream.return() }
})

test('TC-DSH-APPROVAL-004 可回答审批的用户仍不能接收他人普通通知', async () => {
  const f = fixture('harness-user', 'bob')
  const client = await opened(f)
  try {
    const frames = []
    client.queue.push = frame => frames.push(frame)
    f.gateway.broadcastRemoteEvent({ event: 'api-session/status', args: [], resources: { session: () => 'session-a' } })
    assert.deepEqual(frames, [])
  } finally { await f.stream.return() }
})

test('TC-DSH-APPROVAL-005 未知交互与缺失会话归属默认拒绝', async () => {
  for (const change of [p => { p.source.event = 'unknown/request' }, p => { delete p.source.context.subject.session }]) {
    const f = fixture()
    change(f.pending)
    const client = await opened(f)
    try { assert.equal(client.deliveries.size, 0) } finally { await f.stream.return() }
  }
})

test('TC-DSH-APPROVAL-006 新产生的审批同样按会话过滤，拒绝后保留原生处理', async () => {
  const f = fixture()
  f.gateway.pendingRemoteEvents.clear()
  const client = await opened(f)
  try {
    assert.equal(client.deliveries.size, 0)
    f.gateway.pendingRemoteEvents.set(f.pending.id, f.pending)
    f.gateway.deliverRemoteEvent(f.pending, client)
    assert.equal(client.deliveries.has(f.pending.id), true)
    let rejected
    f.gateway.settleRemoteEvent = (_, outcome) => { rejected = outcome.value }
    const response = await f.gateway.dispatchRpc('$events/result', { args: { clientId: client.id, eventId: f.pending.id, outcome: { kind: 'result', value: false } } }, undefined, f.peer)
    assert.equal(response.ok, true)
    assert.equal(rejected, false)
  } finally { await f.stream.return() }
})

test('TC-DSH-APPROVAL-007 owner 既有交互保留，未知身份默认拒绝', async () => {
  for (const kind of ['owner', 'unknown']) {
    const f = fixture(kind)
    f.pending.source.event = 'other/request'
    const client = await opened(f)
    try { assert.equal(client.deliveries.has(f.pending.id), kind === 'owner') } finally { await f.stream.return() }
  }
})


test('TC-DSH-QUESTION-001 本人提问投递并保留原生回答结构', async () => {
  for (const kind of ['harness-user', 'harness-admin']) {
    const f = fixture(kind, 'alice', 'user-questions/request')
    const client = await opened(f)
    try {
      assert.equal(client.deliveries.has('event-a'), true)
      let settled
      f.gateway.settleRemoteEvent = (_, outcome) => { settled = outcome }
      const outcome = { kind: 'result', value: [{ id: 'product', answer: 'TongWeb' }] }
      const response = await f.gateway.dispatchRpc('$events/result', { args: { clientId: client.id, eventId: 'event-a', outcome } }, undefined, f.peer)
      assert.equal(response.ok, true)
      assert.deepEqual(settled, outcome)
    } finally { await f.stream.return() }
  }
})

test('TC-DSH-QUESTION-002 他人会话提问对普通用户及管理员不可见', async () => {
  for (const kind of ['harness-user', 'harness-admin']) {
    const f = fixture(kind, 'bob', 'user-questions/request')
    const client = await opened(f)
    try { assert.equal(client.deliveries.size, 0) } finally { await f.stream.return() }
  }
})

test('TC-DSH-QUESTION-003 提问回答拒绝跨 Peer 和已撤销权限', async () => {
  const f = fixture('harness-user', 'alice', 'user-questions/request')
  const client = await opened(f)
  try {
    assert.equal(client.deliveries.has('event-a'), true)
    let settled = false
    f.gateway.settleRemoteEvent = () => { settled = true }
    const payload = { args: { clientId: client.id, eventId: 'event-a', outcome: { kind: 'result', value: [] } } }
    assert.equal((await f.gateway.dispatchRpc('$events/result', payload, undefined, { ...f.peer })).ok, false)
    f.revoke()
    assert.equal((await f.gateway.dispatchRpc('$events/result', payload, undefined, f.peer)).ok, false)
    assert.equal(settled, false)
  } finally { await f.stream.return() }
})

test('TC-DSH-QUESTION-004 连接后新提问可投递，缺少服务端会话归属仍拒绝', async () => {
  const f = fixture('harness-user', 'alice', 'user-questions/request')
  f.gateway.pendingRemoteEvents.clear()
  const client = await opened(f)
  try {
    delete f.pending.source.context.subject.session
    f.gateway.deliverRemoteEvent(f.pending, client)
    assert.equal(client.deliveries.size, 0)
    f.pending.source.context.subject.session = { id: 'session-a' }
    f.gateway.deliverRemoteEvent(f.pending, client)
    assert.equal(client.deliveries.has('event-a'), true)
  } finally { await f.stream.return() }
})

test('TC-DSH-QUESTION-005 刷新重连重新投递，旧连接不能回答', async () => {
  const f = fixture('harness-user', 'alice', 'user-questions/request')
  const old = await opened(f)
  assert.equal(old.deliveries.size, 1)
  await f.stream.return()
  assert.equal(f.gateway.pendingRemoteEvents.has(f.pending.id), true)
  const stream = f.gateway.openRemoteEvents({ args: {} }, new AbortController().signal, f.peer)
  const ready = await stream.next(), client = f.gateway.remoteEventClients.get(ready.value.clientId)
  try {
    assert.notEqual(client.id, old.id)
    assert.equal(client.deliveries.has(f.pending.id), true)
    const args = { clientId: old.id, eventId: f.pending.id, outcome: { kind: 'result', value: [] } }
    assert.equal((await f.gateway.dispatchRpc('$events/result', { args }, undefined, f.peer)).ok, false)
  } finally { await stream.return() }
})

test('TC-DSH-QUESTION-006 原生取消及完成清理所有面板并忽略重复回答', async () => {
  for (const outcome of [{ kind: 'result', value: [] }, { kind: 'rejected', error: { name: 'AbortError', message: 'User cancelled' } }]) {
    const f = fixture('harness-user', 'alice', 'user-questions/request')
    const client = await opened(f), frames = []
    let resolved, rejected, released = 0
    Object.assign(f.pending, { releaseSignal: () => released++, releaseContext: () => released++ })
    Object.assign(f.pending.source, { resolve: value => { resolved = value }, reject: error => { rejected = error } })
    const otherStream = f.gateway.openRemoteEvents({ args: {} }, new AbortController().signal, f.peer)
    const ready = await otherStream.next(), other = f.gateway.remoteEventClients.get(ready.value.clientId)
    other.queue.push = frame => frames.push(frame)
    try {
      const args = { clientId: client.id, eventId: f.pending.id, outcome }
      assert.equal((await f.gateway.dispatchRpc('$events/result', { args }, undefined, f.peer)).ok, true)
      assert.equal(f.gateway.pendingRemoteEvents.size, 0)
      assert.equal(client.deliveries.size, 0)
      assert.equal(released, 2)
      assert.deepEqual(frames, [{ type: 'cancel', eventId: f.pending.id }])
      if (outcome.kind === 'result') assert.deepEqual(resolved, outcome)
      else assert.equal(rejected.name, 'AbortError')
      await f.gateway.dispatchRpc('$events/result', { args }, undefined, f.peer)
      assert.equal(released, 2)
    } finally { await otherStream.return(); await f.stream.return() }
  }
})

test('TC-DSH-QUESTION-007 停止任务的原生 AbortSignal 撤回提问且不可重连复活', async () => {
  const f = fixture('harness-user', 'alice', 'user-questions/request')
  f.gateway.pendingRemoteEvents.clear()
  const client = await opened(f), frames = [], abort = new AbortController()
  const agent = { session: { id: 'session-a' } }
  let rejected, released = 0
  client.queue.push = frame => frames.push(frame)
  const source = { event: 'user-questions/request', request: { agent, signal: abort.signal, questions: [{ id: 'q', question: 'Choose?' }] }, context: { agentId: 'session-a', subject: agent, value: { effect: () => () => released++ } }, resolve: () => assert.fail('Stopped question resolved'), reject: error => { rejected = error } }
  try {
    f.gateway.startRemoteEvent(source)
    assert.equal(client.deliveries.size, 1)
    const id = frames[0].eventId
    abort.abort(new Error('Session stopped'))
    assert.equal(rejected.message, 'Session stopped')
    assert.equal(released, 1)
    assert.equal(client.deliveries.size, 0)
    assert.equal(f.gateway.pendingRemoteEvents.size, 0)
    assert.deepEqual(frames.at(-1), { type: 'cancel', eventId: id })
    f.gateway.deliverRemoteEvent = () => assert.fail('Cancelled event redelivered')
    const stream = f.gateway.openRemoteEvents({ args: {} }, new AbortController().signal, f.peer)
    await stream.next(); await stream.return()
  } finally { await f.stream.return() }
})

test('TC-DSH-QUESTION-008 已断开的 Peer 或客户端不可收到提问', async () => {
  for (const target of ['peer', 'client']) {
    const f = fixture('harness-user', 'alice', 'user-questions/request')
    f.gateway.pendingRemoteEvents.clear()
    const client = await opened(f), abort = new AbortController()
    if (target === 'peer') f.peer.signal = abort.signal
    else client.signal = abort.signal
    abort.abort()
    try { f.gateway.deliverRemoteEvent(f.pending, client); assert.equal(client.deliveries.size, 0) } finally { await f.stream.return() }
  }
})


test('TC-DSH-INTERACTION-001 原生已连接检测识别隔离用户且不跳过通知权限',async()=>{
  const f=fixture()
  assert.equal(f.gateway.hasLiveClient(),false)
  const client=await opened(f)
  try{
    assert.equal(f.gateway.hasLiveClient(),true)
    assert.equal(client.answers,false)
    const frames=[];client.queue.push=frame=>frames.push(frame)
    f.revoke()
    f.gateway.broadcastRemoteEvent({event:'api-session/status',args:[],resources:{session:()=> 'session-other'}})
    assert.deepEqual(frames,[])
  }finally{await f.stream.return();f.cleanup()}
})

test('TC-DSH-INTERACTION-002 非法回答不结算，已过期身份及交互能力撤销均拒绝',async()=>{
  for(const kind of ['harness-user','harness-admin']){
    const f=fixture(kind),client=await opened(f)
    try{
      let settled=false;f.gateway.settleRemoteEvent=()=>{settled=true}
      const args={clientId:client.id,eventId:f.pending.id,outcome:{kind:'result',value:[]}}
      for(const malformed of [{args:{...args,sessionId:'session-other'}},{args:{...args,outcome:{kind:'result',value:()=>{}}}},{args:{...args,outcome:{kind:'rejected',error:{name:'Error',message:1}}}}])assert.equal((await f.gateway.dispatchRpc('$events/result',malformed,undefined,f.peer)).ok,false)
      f.peer.interactions='observe'
      assert.equal((await f.gateway.dispatchRpc('$events/result',{args},undefined,f.peer)).ok,false)
      assert.equal(settled,false)
    }finally{await f.stream.return();f.cleanup()}
  }
})

test('TC-DSH-INTERACTION-003 插件卸载清理流并恢复宿主方法',async()=>{
  const f=fixture(),client=await opened(f)
  const prototype=Object.getPrototypeOf(f.gateway)
  assert.notEqual(f.gateway.dispatchRpc,prototype.dispatchRpc)
  f.cleanup()
  assert.equal(f.gateway.remoteEventClients.size,0)
  assert.equal(f.gateway.dispatchRpc,prototype.dispatchRpc)
  assert.equal(client.deliveries.size,0)
  await f.stream.return()
})


test('TC-DSH-INTERACTION-004 不支持的网关接口不能部分安装适配',()=>{
  let patched=false
  assert.throws(()=>installInteractions({}, {remoteEventClients:new Map(),pendingRemoteEvents:new Map()},()=>{patched=true}),/unsupported/)
  assert.equal(patched,false)
})
