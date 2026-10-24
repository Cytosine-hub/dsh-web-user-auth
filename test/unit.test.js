import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { builtInCookieName, readCookie, signSession, verifySession } from '../lib/cookies.js'
import { contains, userDirectoryId, userDirectoryName, userFromCwd } from '../lib/paths.js'
import { UserStore, hashPassword, verifyPassword } from '../lib/users.js'
import { escapeHtml, serverLocale } from '../lib/login-page.js'

test('contains refuses prefix siblings and accepts descendants', () => {
  assert.equal(contains('/srv/users/alice', '/srv/users/alice'), true)
  assert.equal(contains('/srv/users/alice', '/srv/users/alice/projects/a.ts'), true)
  assert.equal(contains('/srv/users/alice', '/srv/users/alice-work'), false)
  assert.equal(contains('/srv/users/alice', '/srv/users/bob'), false)
  assert.equal(contains('/srv/users/alice', '/srv/users/alice/../bob'), false)
})

test('user directory names round-trip arbitrary user ids', () => {
  for (const id of ['alice', 'alice@example.com', '用户-42', 'a/b']) {
    assert.equal(userDirectoryId(userDirectoryName(id)), id)
  }
  assert.equal(userFromCwd('/srv/users', '/srv/users/u-YWxpY2U/project'), 'alice')
  assert.equal(userFromCwd('/srv/users', '/srv/users'), undefined)
  assert.equal(userFromCwd('/srv/users', '/srv/other/u-YWxpY2U'), undefined)
})

test('signed user cookies verify, expire, and reject tampering', () => {
  const secret = crypto.randomBytes(32)
  const now = Date.now()
  const token = signSession({ v: 1, id: 'alice', name: 'Alice', provider: 'local', iat: now, exp: now + 60_000 }, secret)
  assert.equal(verifySession(token, secret)?.id, 'alice')
  assert.equal(verifySession(`${token}x`, secret), undefined)
  assert.equal(verifySession(token, crypto.randomBytes(32)), undefined)
  const expired = signSession({ v: 1, id: 'alice', name: 'Alice', provider: 'local', iat: now - 120_000, exp: now - 60_000 }, secret)
  assert.equal(verifySession(expired, secret), undefined)
  assert.equal(readCookie(`a=1; ${'dsh-user-auth'}=${token}; b=2`, 'dsh-user-auth'), token)
})

test('built-in cookie name uses the listener authority and protocol', () => {
  const http = builtInCookieName({ host: 'example.test:3080' }, false)
  const https = builtInCookieName({ host: 'example.test:3080' }, true)
  assert.match(http, /^dsh-auth-[A-Za-z0-9_-]+$/u)
  assert.match(https, /^dsh-auth-[A-Za-z0-9_-]+$/u)
  assert.notEqual(http, https)
  assert.equal(builtInCookieName({}, false), undefined)
})

test('scrypt hashes verify and reject wrong passwords', () => {
  const hash = hashPassword('correct horse battery staple')
  assert.match(hash, /^scrypt\$/u)
  assert.equal(verifyPassword('correct horse battery staple', { passwordHash: hash }), true)
  assert.equal(verifyPassword('wrong password', { passwordHash: hash }), false)
  assert.equal(verifyPassword('plain', { password: 'plain' }), true)
})

test('user store merges config and file users with config precedence', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-web-auth-'))
  const file = path.join(dir, 'users.json')
  fs.writeFileSync(file, JSON.stringify({ users: [{ id: 'alice', name: 'File Alice', password: 'file-password' }] }))
  const store = new UserStore({
    usersFile: file,
    users: [{ id: 'alice', name: 'Config Alice', passwordHash: hashPassword('config-password') }],
  })
  assert.equal(store.get('alice').name, 'Config Alice')
  assert.equal(store.verify('alice', 'config-password'), true)
  assert.equal(store.verify('alice', 'file-password'), false)
  store.add({ id: 'bob', name: 'Bob', password: 'bob-password-1' })
  const reloaded = new UserStore({ usersFile: file, users: [] })
  assert.equal(reloaded.verify('bob', 'bob-password-1'), true)
  fs.rmSync(dir, { recursive: true, force: true })
})

test('server pages escape untrusted values and choose Chinese', () => {
  assert.equal(escapeHtml('<script>&"'), '&lt;script&gt;&amp;&quot;')
  assert.equal(serverLocale('en-US,en;q=0.9'), 'en')
  assert.equal(serverLocale('zh-CN,zh;q=0.9'), 'zh')
})

test('admin login is independent, signed, persistent and grants owner only after login', async () => {
  const { installAdmin } = await import('../lib/admin.js')
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-admin-test-'))
  function context() {
    const routes = new Map()
    return { routes, effect() {}, webServer:{ protocol:'http:',register(r){ routes.set(r.path,r.handler) } }, connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false}} }
  }
  const ctx = context(); installAdmin(ctx,home)
  const anonymousResponse={writeHead(status,headers){this.status=status;this.headers=headers},end(){}}
  assert.equal(ctx.connection.authorizeIndex({url:"/",headers:{host:"example.test"}},anonymousResponse),false)
  assert.equal(anonymousResponse.status,303)
  assert.equal(anonymousResponse.headers.location,"./login")
  const password=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
  assert.equal(ctx.connection.admit({headers:{}}).rejection,401)
  const req = Object.assign((async function*(){yield Buffer.from(new URLSearchParams({username:'admin',password}).toString())})(), {method:'POST',headers:{host:'example.test',origin:'http://example.test'}})
  const res={headers:{},setHeader(k,v){this.headers[k]=v},writeHead(s,h){this.status=s;Object.assign(this.headers,h)},end(){}}
  await ctx.routes.get('/admin')(req,res)
  assert.equal(res.status,303)
  assert.equal(res.headers['referrer-policy'],'same-origin')
  const invalidOriginReq=Object.assign((async function*(){})(),{method:'POST',headers:{host:'example.test',origin:'null'}})
  const invalidOriginRes={setHeader(){},writeHead(s){this.status=s},end(){}}
  await ctx.routes.get('/admin')(invalidOriginReq,invalidOriginRes)
  assert.equal(invalidOriginRes.status,403)
  const cookie=res.headers['set-cookie'][0].split(';')[0]
  assert.equal(ctx.connection.admit({headers:{cookie}}).peer.principal.kind,'owner')
  const restarted=context(); installAdmin(restarted,home)
  assert.equal(restarted.connection.admit({headers:{cookie}}).peer.principal.kind,'owner')
  assert.equal(restarted.connection.admit({headers:{cookie:cookie+'x'}}).rejection,401)
  fs.rmSync(home,{recursive:true,force:true})
})

test('ordinary users have native plugin management without auth settings or unrelated global authority', async () => {
  const { createUserAccessPolicy }=await import('../lib/policy.js')
  const {policy}=createUserAccessPolicy({ctx:{typert:{local:{list:()=>[]}},workspaceRegistry:{list:()=>[]}},workspaceRoot:'/users',workspaceOf:id=>'/users/'+id,userForPath:()=>undefined})
  const a=policy.bindings({kind:'harness-user',userId:'alice'})[0]
  policy.bindings({kind:'harness-user',userId:'bob'})
  assert.equal(a.condition({action:'directoryPicker/list',args:{path:'/users/alice/project'}}).kind,'allow')
  assert.equal(a.condition({action:'directoryPicker/list',args:{path:'/users/bob'}}).kind,'deny')
  assert.ok(a.role.actions.includes('pluginInventory/list'))
  assert.ok(a.role.actions.includes('pluginManager/installBundle'))
  assert.ok(a.role.actions.includes('pluginManager/setPluginEnabled'))
  assert.equal(a.role.actions.some(action=>/dynamicCordis|configForms|credentials/.test(action)),false)
  assert.equal(a.role.actions.includes('pluginManager/setVersionExemption'),false)
})

test('enabled user authentication preserves independent administrator admission', async () => {
  const { apply } = await import('../lib/plugin.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-enabled-auth-'))
  const old=process.env.DSH_HOME;process.env.DSH_HOME=home
  const routes=new Map();const disposers=[]
  const ctx={logger:{info(){}},on(){},effect(fn){const d=fn();if(typeof d==='function')disposers.push(d)},
    webServer:{protocol:'http:',register(route){routes.set(route.path,route.handler);return ()=>{}}},
    connection:{createPeer:({principal})=>({principal,signal:{aborted:false},dispose(){}}),browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false}},
    remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},
    sessions:{list:()=>[]},sessionPersistence:{list:async()=>[]},sessionController:{},directoryPickerController:{},
    workspaceRegistry:{list:()=>[]},typert:{local:{list:()=>[]}},get(){return undefined}}
  try {
    await apply(ctx,{enabled:true})
    const password=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
    const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams({username:'admin',password}).toString())})(),{method:'POST',headers:{host:'example.test'}})
    const res={headers:{},setHeader(k,v){this.headers[k]=v},writeHead(s,h){this.status=s;Object.assign(this.headers,h)},end(){}}
    await routes.get('/admin')(req,res)
    const cookie=res.headers['set-cookie'][0].split(';')[0]
    const request={headers:{cookie,host:'example.test'},url:'/',socket:{remoteAddress:'203.0.113.1'}}
    assert.equal(ctx.connection.admit(request).peer.principal.kind,'harness-admin')
    assert.equal(ctx.connection.authorizeIndex(request,{}),true)
    assert.equal(ctx.connection.admit({headers:{host:'example.test'},socket:{remoteAddress:'203.0.113.1'}}).rejection,401)
  } finally {
    for(const dispose of disposers.reverse())dispose()
    if(old===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=old
    fs.rmSync(home,{recursive:true,force:true})
  }
})

test('unified login remains available when ordinary user authentication is disabled', async () => {
  const { apply }=await import('../lib/plugin.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-disabled-login-'));const previous=process.env.DSH_HOME;process.env.DSH_HOME=home
  const routes=new Map()
  const ctx={on(){return ()=>{}},sessions:{list:()=>[]},sessionPersistence:{list:async()=>[]},sessionController:{},directoryPickerController:{},workspaceRegistry:{list:()=>[]},remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},typert:{local:{list:()=>[]}},get(){},effect(){},logger:{info(){}},webServer:{protocol:'http:',register(r){routes.set(r.path,r.handler)}},connection:{admit(){return {rejection:401}},authorizeIndex(){return false}}}
  const response=()=>({status:200,headers:{},setHeader(k,v){this.headers[k]=v},writeHead(s,h){this.status=s;Object.assign(this.headers,h)},end(body){this.body=body}})
  try {
    await apply(ctx,{enabled:false})
    const login=response();await routes.get('/login')({method:'GET',headers:{}},login)
    assert.equal(login.status,200);assert.match(login.body,/普通用户认证尚未开启/);assert.match(login.body,/管理员和普通用户使用同一入口/)
    const req=Object.assign((async function*(){yield Buffer.from('username=alice&password=invalid')})(),{method:'POST',headers:{host:'test.local'}})
    const post=response();await routes.get('/login')(req,post);assert.equal(post.status,401)
    const admin=response();await routes.get('/admin')({method:'GET',headers:{}},admin)
    assert.equal(admin.status,303);assert.equal(admin.headers.location,'./login')
  } finally {if(previous===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=previous;fs.rmSync(home,{recursive:true,force:true})}
})

test('management page requires admin, creates hashed users and saves auth state', async () => {
  const { installManagement }=await import('../lib/management.js')
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-management-'))
  const config={enabled:false,provider:'local',local:{users:[]},usersFile:path.join(dir,'users.json')}
  let handler;let updates=0
  installManagement({webServer:{register(r){if(r.path==='/api/auth/admin')handler=r.handler}}},{isAdmin:req=>req.admin===true,getConfig:()=>config,update:async patch=>{Object.assign(config,patch);updates++},reloadUsers(){}})
  const response=()=>({headers:{},status:200,get statusCode(){return this.status},set statusCode(value){this.status=value},setHeader(k,v){this.headers[k]=v},writeHead(s,h){this.status=s;Object.assign(this.headers,h)},end(body){this.body=body}})
  const post=async(fields,admin=true)=>{
    const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams(fields).toString())})(),{method:'POST',admin,headers:{host:'test.local',origin:'https://test.local'}})
    const res=response();await handler(req,res);return res
  }
  try {
    const anonymous=response();await handler({method:'GET',headers:{}},anonymous);assert.equal(anonymous.status,403)
    const get=response();await handler({method:'GET',admin:true,headers:{}},get)
    const csrf=JSON.parse(get.body).csrf
    assert.equal((await post({action:'settings',enabled:'on',csrf})).status,400)
    assert.equal(updates,0)
    assert.equal((await post({action:'create',csrf,username:'alice',name:'Alice',password:'long-secure-password',confirm:'long-secure-password'})).status,200)
    const data=fs.readFileSync(config.usersFile,'utf8');assert.doesNotMatch(data,/long-secure-password/);assert.match(data,/scrypt/)
    assert.equal((await post({action:'settings',enabled:'on',csrf})).status,200);assert.equal(config.enabled,true)
    assert.equal((await post({action:'settings',csrf:'wrong'})).status,403);assert.equal(config.enabled,true)
    assert.equal((await post({action:'settings',csrf})).status,200);assert.equal(config.enabled,false)
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
})

test('password reset preserves identity, changes hash and revokes an old login cookie', async () => {
  const { apply }=await import('../lib/plugin.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-reset-test-'));const previous=process.env.DSH_HOME;process.env.DSH_HOME=home
  const usersFile=path.join(home,'web-user-auth/users.json');const store=new UserStore({users:[],usersFile})
  store.add({id:'alice',name:'Alice',password:'old-long-password'})
  const peers=[];const routes=new Map()
  const ctx={logger:{info(){},warn(){}},on(){return ()=>{}},effect(fn){fn()},get(name){if(name==='pluginManager')return {listBundles:async()=>[{name:'@local/dsh-web-user-auth',availability:'profile',enabled:true},{name:'example-plugin',availability:'installation',enabled:true,source:'/private/path',rows:[{config:{secret:'hidden'}}]}]}} ,
    webServer:{protocol:'http:',register(r){routes.set(r.path,r.handler);return ()=>{}}},
    connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false},createPeer({principal}){const peer={principal,signal:{aborted:false},dispose(){this.signal.aborted=true}};peers.push(peer);return peer}},
    remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},sessions:{list:()=>[]},sessionPersistence:{list:async()=>[]},sessionController:{},directoryPickerController:{},workspaceRegistry:{list:()=>[],create:async()=>({id:'test'})},typert:{local:{list:()=>[]}}}
  const res=()=>({headers:{},setHeader(k,v){this.headers[k]=v},writeHead(s,h){this.status=s;Object.assign(this.headers,h)},end(body){this.body=body}})
  try{
    await apply(ctx,{enabled:true})
    const secret=Buffer.from(fs.readFileSync(path.join(home,'web-user-auth/secret'),'utf8').trim(),'base64url')
    const userLogin=Object.assign((async function*(){yield Buffer.from(new URLSearchParams({username:'alice',password:'old-long-password'}).toString())})(),{method:'POST',headers:{host:'test.local',origin:'https://test.local'}})
    const userResponse=res();await routes.get('/login')(userLogin,userResponse)
    assert.equal(userResponse.status,303)
    const userCookie=userResponse.headers['set-cookie'][0].split(';')[0]
    assert.match(userResponse.headers['set-cookie'][1],/^dsh-admin-auth=;/)
    const userState=res();await routes.get('/api/auth/status')({method:'GET',headers:{cookie:userCookie,host:'test.local'}},userState)
    assert.equal(JSON.parse(userState.body).role,'user')
    const denied=res();await routes.get('/api/auth/admin')({method:'GET',headers:{cookie:userCookie,host:'test.local'}},denied)
    assert.equal(denied.status,403)
    const now=Date.now();const cookie='dsh-user-auth='+signSession({v:1,id:'alice',name:'Alice',provider:'local',iat:now-1000,exp:now+60000},secret)
    const request={url:'/',headers:{cookie,host:'test.local'},socket:{remoteAddress:'203.0.113.1'}}
    assert.equal(ctx.connection.admit(request).peer.principal.kind,'harness-user')
    const adminPassword=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
    const login=Object.assign((async function*(){yield Buffer.from(new URLSearchParams({username:'admin',password:adminPassword}).toString())})(),{method:'POST',headers:{host:'test.local',origin:'https://test.local'}})
    const lr=res();await routes.get('/admin')(login,lr);const adminCookie=lr.headers['set-cookie'][0].split(';')[0]
    const adminState=res();await routes.get('/api/auth/status')({method:'GET',headers:{cookie:adminCookie,host:'test.local'}},adminState)
    assert.equal(JSON.parse(adminState.body).role,'admin')
    const get=res();await routes.get('/api/auth/admin')({method:'GET',headers:{cookie:adminCookie}},get)
    const csrf=JSON.parse(get.body).csrf
    const reset=Object.assign((async function*(){yield Buffer.from(new URLSearchParams({action:'reset',csrf,username:'alice',password:'new-long-password',confirm:'new-long-password'}).toString())})(),{method:'POST',headers:{host:'test.local',origin:'https://test.local',cookie:adminCookie}})
    const rr=res();await routes.get('/api/auth/admin')(reset,rr);assert.match(rr.body,/密码已重置/)
    const reloaded=new UserStore({users:[],usersFile});assert.equal(reloaded.verify('alice','old-long-password'),false);assert.equal(reloaded.verify('alice','new-long-password'),true);assert.equal(reloaded.get('alice').name,'Alice')
    assert.equal(ctx.connection.admit(request).rejection,401);assert.equal(peers[0].signal.aborted,true)
    const logout=res();routes.get('/api/auth/logout')({method:'POST',headers:{host:'test.local',origin:'https://test.local',cookie:adminCookie+'; dsh-auth-test=test'}},logout)
    assert.equal(logout.status,204)
    assert.equal(logout.headers['set-cookie'].length,3)

  }finally{if(previous===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=previous;fs.rmSync(home,{recursive:true,force:true})}
})

test('user session creation preserves owned workspace association and rejects foreign workspace', async () => {
  const { apply }=await import('../lib/plugin.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-workspace-association-'));const previous=process.env.DSH_HOME;process.env.DSH_HOME=home
  const root=path.join(home,'web-users');const ownPath=path.join(root,userDirectoryName('alice'));const foreignPath=path.join(root,userDirectoryName('bob'))
  const own={id:'workspace-alice',path:ownPath};const foreign={id:'workspace-bob',path:foreignPath}
  fs.mkdirSync(foreignPath,{recursive:true})
  const calls=[]
  const ctx={logger:{info(){},warn(){}},on(){return ()=>{}},effect(fn){fn()},get(){},
    webServer:{protocol:'http:',register(){return ()=>{}}},
    connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false}},
    remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},sessions:{list:()=>[]},sessionPersistence:{list:async()=>[]},directoryPickerController:{},
    workspaceRegistry:{list:()=>[own,foreign],create:async()=>own,get:id=>id===own.id?own:id===foreign.id?foreign:undefined},typert:{local:{list:()=>[]}}}
  ctx.sessionController={ctx:{invocation:{peer:{principal:{kind:'harness-user',userId:'alice'}}}},create:async request=>{calls.push(request);return {sessionId:'test-session'}}}
  try{
    await apply(ctx,{enabled:true,local:{users:[{id:'alice',password:'long-test-password'}]}})
    await ctx.sessionController.create({workspaceId:own.id})
    assert.equal(calls[0].workspaceId,own.id);assert.equal(calls[0].cwd,undefined)
    await ctx.sessionController.create({})
    assert.equal(calls[1].workspaceId,own.id)
    await assert.rejects(ctx.sessionController.create({workspaceId:foreign.id}),/not owned/)
    assert.equal(calls.length,2)
  }finally{if(previous===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=previous;fs.rmSync(home,{recursive:true,force:true})}
})

test('native client exposes management only to admin and logout to both roles', async () => {
  const vm=await import('node:vm')
  const code=fs.readFileSync(new URL('../lib/client.js',import.meta.url),'utf8')
  for(const role of ['admin','user']){
    let plugin;const registrations=[]
    const occupied=new Set(['main/plugins/0'])
    const React={createElement:(type,props,...children)=>({type,props,children})}
    const sandbox={URL,URLSearchParams,fetch:async()=>({ok:true,status:200,json:async()=>({role,name:role==='admin'?'admin':'Alice'})}),setTimeout(){},window:{location:{href:'https://example.test/dsh-web/'},__ModuleLoader__:{load(module){plugin=module.factory(()=>React)}}}}
    vm.runInNewContext(code,sandbox)
    const ctx={locale:{register(){return ()=>{}}},layout:{selectPanel(){}},effect(fn){fn()},slots:{inject(name,fn){fn()},register(options,component){if(options.name==='main'){const cell=options.name+'/'+options.key+'/'+(options.priority??0);if(occupied.has(cell))throw new Error('duplicate keyed slot at the same priority');occupied.add(cell)}registrations.push({options,component});return ()=>{}}}}
    await plugin.apply(ctx)
    assert.equal(registrations.some(row=>row.options.name==='main'&&row.options.key==='web-user-auth'),role==='admin')
    assert.equal(registrations.some(row=>row.options.name==='main'&&row.options.key==='plugins'),false)
    assert.equal(registrations.some(row=>row.options.name==='sidebar.panellist'),role==='admin')
    const footer=registrations.find(row=>row.options.name==='sidebar.footer.action')
    const tree=JSON.stringify(footer.component({...footer.options.inject(),wide:true}))
    assert.match(tree,/退出登录/)
    assert.equal(tree.includes('管理后台'),false)
  }
})

test('administrator has management grants but no other user session or workspace grants', async () => {
  const { createUserAccessPolicy }=await import('../lib/policy.js')
  const { ADMIN_USER_ID }=await import('../lib/identity.js')
  const root='/srv/users',adminRoot=root+'/'+userDirectoryName(ADMIN_USER_ID),aliceRoot=root+'/'+userDirectoryName('alice')
  const ownerOf=target=>target.startsWith(aliceRoot)?'alice':ADMIN_USER_ID
  const {policy,rememberSession}=createUserAccessPolicy({ctx:{typert:{local:{list:()=>[{namespace:'pluginInventory',method:'list'},{namespace:'session',method:'page'}]}},workspaceRegistry:{list:()=>[{id:'legacy-admin',path:'/srv/daily'},{id:'alice-workspace',path:aliceRoot},{id:'admin-workspace',path:adminRoot}]},remoteAccess:{invalidate(){}}},workspaceRoot:root,workspaceOf:id=>root+'/'+userDirectoryName(id),userForPath:ownerOf,ownsPath:(id,target)=>ownerOf(target)===id})
  rememberSession('admin-old-chat','/srv/daily');rememberSession('alice-private-chat',aliceRoot)
  const bindings=policy.bindings({kind:'harness-admin',userId:ADMIN_USER_ID})
  assert.ok(bindings.some(b=>b.resource.kind==='session'&&b.resource.id==='admin-old-chat'))
  assert.ok(bindings.some(b=>b.resource.kind==='workspace'&&b.resource.id==='legacy-admin'))
  assert.ok(bindings[0].role.actions.includes('pluginInventory/list'))
  assert.equal(bindings.some(b=>b.resource.id==='alice-private-chat'||b.resource.id==='alice-workspace'),false)
  assert.deepEqual(policy.bindings({kind:'harness-admin',userId:'alice'}),[])
  assert.deepEqual(policy.bindings({kind:'harness-user',userId:ADMIN_USER_ID}),[])
})

test('administrator session list and search exclude ordinary-user sessions even when user login is disabled', async () => {
  const { apply }=await import('../lib/plugin.js');const { ADMIN_USER_ID }=await import('../lib/identity.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-admin-privacy-'));const previous=process.env.DSH_HOME;process.env.DSH_HOME=home
  const userRoot=path.join(home,'web-users',userDirectoryName('alice'));fs.mkdirSync(userRoot,{recursive:true})
  const headers=[{id:'admin-old-chat',cwd:'/srv/legacy-admin'},{id:'alice-private-chat',cwd:userRoot}]
  const items=headers.map(header=>({sessionId:header.id}))
  const ctx={logger:{info(){},warn(){}},on(){return ()=>{}},effect(fn){fn()},get(){},webServer:{protocol:'http:',register(){return ()=>{}}},
    connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false},createPeer:({principal})=>({principal,signal:{aborted:false},dispose(){}})},
    remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},sessions:{list:()=>headers.map(header=>({id:header.id,header}))},sessionPersistence:{list:async()=>[]},directoryPickerController:{},workspaceRegistry:{list:()=>[]},typert:{local:{list:()=>[]}}}
  ctx.sessionController={ctx:{invocation:{peer:{principal:{kind:'harness-admin',userId:ADMIN_USER_ID}}}},list:async()=>({items}),search:async()=>({items})}
  try{
    await apply(ctx,{enabled:false})
    assert.deepEqual((await ctx.sessionController.list({})).items.map(i=>i.sessionId),['admin-old-chat'])
    assert.deepEqual((await ctx.sessionController.search({})).items.map(i=>i.sessionId),['admin-old-chat'])
  }finally{if(previous===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=previous;fs.rmSync(home,{recursive:true,force:true})}
})

test('provider settings validate proxy requirements and never return configured secrets', async () => {
  const {parseSettings,settingsView,mergeSavedSettings}=await import('../lib/provider-settings.js')
  const config={provider:'local',http:{headers:{'X-API-Key':'secret-api-key'}},header:{sharedSecret:'secret-proxy-key-123456'}}
  const form=new URLSearchParams({provider:'http',enabled:'on','http.loginUrl':'https://auth.example.test/login'})
  const patch=parseSettings(form,config)
  assert.equal(patch.http.headers['X-API-Key'],'secret-api-key')
  assert.doesNotMatch(JSON.stringify(settingsView(patch)),/secret-api-key|secret-proxy-key/)
  form.set('http.headers','{}');assert.deepEqual(parseSettings(form,config).http.headers,{})
  form.set('http.loginUrl','file:///etc/passwd');assert.throws(()=>parseSettings(form,config),/HTTP/)
  assert.throws(()=>parseSettings(new URLSearchParams({provider:'header',enabled:'on'}),config),/可信代理/)
  assert.throws(()=>parseSettings(new URLSearchParams({provider:'header',proxyReady:'on',enabled:'on','header.sharedSecret':'short'}),config),/16/)
  assert.equal(mergeSavedSettings({stateDir:'/srv/state',local:{users:['existing']}},{enabled:true,provider:'http',stateDir:'/evil',local:{users:[]},http:{loginUrl:'https://auth.example.test'}}).stateDir,'/srv/state')
})

test('HTTP and header settings take effect, persist across restart and preserve local administrator access', async () => {
  const {createServer}=await import('node:http')
  const {apply}=await import('../lib/plugin.js')
  let receivedToken,receivedKey,reservedIdentity=false
  const server=createServer(async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk
    res.setHeader('content-type','application/json')
    if(req.url==='/login'){
      const credentials=JSON.parse(body);receivedKey=req.headers['x-api-key']
      if(credentials.username!=='alice'||credentials.password!=='external-fixture-password'){res.writeHead(401);res.end('{}');return}
      res.end(JSON.stringify({access_token:'fixture-token'}));return
    }
    if(req.url==='/me'){receivedToken=req.headers.authorization;res.end(JSON.stringify({user:{id:reservedIdentity?'__dsh_administrator__':'external-alice',name:'External Alice'}}));return}
    res.writeHead(404);res.end('{}')
  })
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
  const endpoint='http://127.0.0.1:'+server.address().port
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-provider-modes-')),previous=process.env.DSH_HOME;process.env.DSH_HOME=home
  const makeContext=()=>{
    const routes=new Map()
    return {routes,ctx:{logger:{info(){},warn(){}},on(){return ()=>{}},effect(fn){fn()},get(){},
      webServer:{protocol:'http:',register(route){routes.set(route.path,route.handler);return ()=>{}}},
      connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false},createPeer({principal}){return {principal,signal:{aborted:false},dispose(){this.signal.aborted=true}}}},
      remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},sessions:{list:()=>[]},sessionPersistence:{list:async()=>[]},sessionController:{},directoryPickerController:{},workspaceRegistry:{list:()=>[],create:async()=>({id:'fixture'})},typert:{local:{list:()=>[]}}}}
  }
  const response=()=>({headers:{},writeHead(status,headers){this.status=status;Object.assign(this.headers,headers)},setHeader(name,value){this.headers[name]=value},end(body){this.body=body}})
  const post=async(routes,route,fields,cookie)=>{
    const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams(fields).toString())})(),{method:'POST',headers:{host:'test.local',origin:'https://test.local',cookie}})
    const res=response();await routes.get(route)(req,res);return res
  }
  const status=async(routes,cookie,extra={})=>{const res=response();await routes.get('/api/auth/status')({method:'GET',headers:{host:'test.local',cookie,...extra}},res);return JSON.parse(res.body)}
  try{
    const raw={enabled:true,local:{users:[{id:'alice',password:'local-fixture-password'}]}}
    const {ctx,routes}=makeContext();await apply(ctx,raw)
    const password=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
    const login=await post(routes,'/login',{username:'admin',password}),adminCookie=login.headers['set-cookie'][0].split(';')[0]
    const local=await post(routes,'/login',{username:'alice',password:'local-fixture-password'}),localCookie=local.headers['set-cookie'][0].split(';')[0]
    const model=response();await routes.get('/api/auth/admin')({method:'GET',headers:{cookie:adminCookie}},model);const csrf=JSON.parse(model.body).csrf
    const settings=await post(routes,'/api/auth/admin',{action:'settings',csrf,enabled:'on',provider:'http','http.loginUrl':endpoint+'/login','http.userInfoUrl':endpoint+'/me','http.headers':JSON.stringify({'X-API-Key':'fixture-private-key'})},adminCookie)
    assert.equal(settings.status,200,settings.body);assert.doesNotMatch(settings.body,/fixture-private-key/)
    assert.equal((await status(routes,localCookie)).role,'anonymous')
    const external=await post(routes,'/login',{username:'alice',password:'external-fixture-password'})
    assert.equal(external.status,303)
    assert.equal(receivedToken,'Bearer fixture-token');assert.equal(receivedKey,'fixture-private-key')
    reservedIdentity=true
    assert.equal((await post(routes,'/login',{username:'alice',password:'external-fixture-password'})).status,401)
    reservedIdentity=false
    const externalCookie=external.headers['set-cookie'][0].split(';')[0]
    assert.equal((await status(routes,externalCookie)).userId,'external-alice')
    const settingsFile=path.join(home,'web-admin/auth-settings.json')
    assert.equal(fs.statSync(settingsFile).mode&0o777,0o600)
    const restarted=makeContext();await apply(restarted.ctx,raw)
    assert.equal((await status(restarted.routes,externalCookie)).userId,'external-alice')
    assert.equal((await status(restarted.routes,adminCookie)).role,'admin')
    const header=await post(routes,'/api/auth/admin',{action:'settings',csrf,enabled:'on',provider:'header',proxyReady:'on','header.sharedSecret':'fixture-proxy-secret-123456'},adminCookie)
    assert.equal(header.status,200,header.body);assert.doesNotMatch(header.body,/fixture-proxy-secret/)
    assert.equal((await status(routes,externalCookie)).role,'anonymous')
    assert.equal((await status(routes,undefined,{'x-auth-request-user':'header-alice'})).role,'anonymous')
    assert.equal((await status(routes,undefined,{'x-auth-request-user':'__dsh_administrator__','x-dsh-auth-secret':'fixture-proxy-secret-123456'})).role,'anonymous')
    assert.equal((await status(routes,undefined,{'x-auth-request-user':'header-alice','x-dsh-auth-secret':'fixture-proxy-secret-123456'})).userId,'header-alice')
    assert.equal((await status(routes,adminCookie)).role,'admin')
    const disabled=await post(routes,'/api/auth/admin',{action:'settings',csrf,provider:'header'},adminCookie);assert.equal(disabled.status,200)
    assert.equal((await status(routes,undefined,{'x-auth-request-user':'header-alice','x-dsh-auth-secret':'fixture-proxy-secret-123456'})).role,'anonymous')
    assert.equal(ctx.connection.admit({headers:{host:'test.local'}}).rejection,401)
    assert.equal((await status(routes,adminCookie)).role,'admin')
  }finally{
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve))
    if(previous===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=previous
    fs.rmSync(home,{recursive:true,force:true})
  }
})

test('native plugin manager protects authentication rows and bundles while allowing ordinary plugin operations', async () => {
  const {installPluginManagementGuards,AUTH_PACKAGE}=await import('../lib/plugin-management.js')
  const calls=[]
  const manager={ctx:{invocation:{peer:{principal:{kind:'harness-user',userId:'alice'}}}},
    async listBundles(){return [{name:AUTH_PACKAGE,enabled:true,removable:true,rows:[{rowId:'web-user-auth',moduleName:AUTH_PACKAGE}]},{name:'other',enabled:false,removable:true,rows:[{moduleName:'other'}]},{name:'auth-wrapper',rows:[{moduleName:AUTH_PACKAGE}]}]},
    async listPlugins(){return [{entryId:'include:web-user-auth',moduleName:AUTH_PACKAGE},{entryId:'other-row',moduleName:'other'}]},
    async setBundleEnabled(...args){calls.push(['bundle',...args]);return 'ok'},async removeBundle(...args){calls.push(['remove',...args]);return 'ok'},
    async setPluginEnabled(...args){calls.push(['row',...args]);return 'ok'},
    async inspect(spec){return spec==='git:unknown'?{status:'accepted',kind:'git'}:{status:'accepted',name:spec==='alias-auth'?AUTH_PACKAGE:spec}},
    async installBundle(...args){calls.push(['install',...args]);return 'ok'}}
  let handoffAuthorized=false
  const original=manager.setBundleEnabled,disposers=[]
  installPluginManagementGuards({handoffAuthorized:()=>handoffAuthorized,ctx:{get:name=>name==='pluginManager'?manager:undefined},patchMethod(target,name,create){const saved=target[name];if(typeof saved!=='function')return;target[name]=create(saved);disposers.push(()=>target[name]=saved)}})
  try{
    const bundles=await manager.listBundles(),rows=await manager.listPlugins()
    assert.equal(bundles[0].removable,false);assert.equal(bundles[0].readOnlyReason,'management-required');assert.equal(bundles[0].rows[0].readOnlyReason,'management-required')
    assert.equal(rows[0].readOnlyReason,'management-required');assert.equal(rows[1].readOnlyReason,undefined)
    for(const name of [AUTH_PACKAGE,'auth-wrapper','@deepseek-ai/dsh-web-app','@deepseek-ai/dsh-base']){
      await assert.rejects(manager.setBundleEnabled(name,false),/管理员|认证插件/)
      await assert.rejects(manager.removeBundle(name),/管理员|认证插件/)
    }
    await assert.rejects(manager.setPluginEnabled('include:web-user-auth',false),/管理员/)
    await assert.rejects(manager.installBundle('alias-auth'),/管理员/)
    await assert.rejects(manager.installBundle('git:unknown'),/确认包名/)
    assert.equal(calls.length,0)
    assert.equal(await manager.setBundleEnabled('other',true),'ok')
    assert.equal(await manager.setPluginEnabled('other-row',true),'ok')
    assert.equal(await manager.removeBundle('other'),'ok')
    assert.equal(await manager.installBundle('other'),'ok')
    assert.deepEqual(calls.map(call=>call[0]),['bundle','row','remove','install'])
    manager.ctx.invocation.peer.principal={kind:'harness-admin',userId:'__dsh_administrator__'}
    assert.equal((await manager.listBundles())[0].readOnlyReason,undefined)
    await assert.rejects(manager.setBundleEnabled(AUTH_PACKAGE,false),/原生登录验证/)
    await assert.rejects(manager.removeBundle(AUTH_PACKAGE),/原生登录验证/)
    await assert.rejects(manager.setPluginEnabled('include:web-user-auth',false),/原生登录验证/)
    handoffAuthorized=true
    assert.equal(await manager.setBundleEnabled(AUTH_PACKAGE,false),'ok')
    assert.equal(await manager.removeBundle(AUTH_PACKAGE),'ok')
    assert.equal(await manager.setPluginEnabled('include:web-user-auth',false),'ok')
  }finally{for(const dispose of disposers.reverse())dispose()}
  assert.equal(manager.setBundleEnabled,original)
})


test('service patches restore inherited and own methods through fresh Cordis-style method proxies', async () => {
  const {patchServiceMethod}=await import('../lib/service-patch.js')
  for(const inherited of [true,false]){
    const original=function(){return 'original'}
    const raw=inherited?Object.create({run:original}):{run:original}
    const service=new Proxy(raw,{get(target,key,receiver){const value=Reflect.get(target,key,receiver);return typeof value==='function'?new Proxy(value,{apply:(fn,that,args)=>Reflect.apply(fn,that,args)}):value}})
    assert.notEqual(service.run,service.run)
    let disposed=false
    const removeAdmin=patchServiceMethod(service,'run',saved=>function(){return 'admin:'+saved.call(this)})
    const removeRuntime=patchServiceMethod(service,'run',saved=>function(){assert.equal(disposed,false);return 'runtime:'+saved.call(this)})
    assert.equal(service.run(),'runtime:admin:original')
    disposed=true;removeRuntime()
    assert.equal(service.run(),'admin:original')
    removeAdmin()
    assert.equal(service.run(),'original')
    assert.equal(Object.hasOwn(raw,'run'),!inherited)
    if(!inherited)assert.equal(raw.run,original)
  }
})


test('service teardown also restores methods when outer and inner effects dispose out of order', async () => {
  const {patchServiceMethod}=await import('../lib/service-patch.js')
  const raw={run(){return 'native'}}
  const original=raw.run
  const service=new Proxy(raw,{get(target,key,receiver){const value=Reflect.get(target,key,receiver);return typeof value==='function'?new Proxy(value,{}):value}})
  const admin=patchServiceMethod(service,'run',saved=>function(){return 'admin:'+saved.call(this)})
  const runtime=patchServiceMethod(service,'run',saved=>function(){return 'runtime:'+saved.call(this)})
  admin()
  assert.equal(service.run(),'runtime:native')
  runtime()
  assert.equal(service.run(),'native')
  assert.equal(raw.run,original)
})


test('native handoff verifies browser cookies before scoped shutdown and keeps the token out of responses', async () => {
  const {createNativeHandoff}=await import('../lib/handoff.js')
  let checks=0,stops=0,handoff
  const native={authenticatedUrl:base=>base+'?token=fixture-launch-token',authorizeIndex(req,res,secure){assert.match(req.url,/token=fixture-launch-token/);assert.equal(secure,false);res.writeHead(303,{'set-cookie':'native=valid; Path=/; HttpOnly; SameSite=Lax'});res.end()},isAuthenticated(req){checks++;return req.headers.cookie?.split(';').map(pair=>pair.trim()).find(pair=>pair.startsWith('native='))==='native=valid'}}
  const ctx={webServer:{protocol:'http:'},connection:{browserAuth:native,isTrusted:req=>req.headers.host==='test.local'},get:()=>({async setBundleEnabled(name,enabled){assert.equal(handoff.authorized(),true);assert.equal(enabled,false);stops++;return {application:'applied'}}})}
  handoff=createNativeHandoff(ctx)
  const req={headers:{host:'test.local',cookie:'native=old; admin=fixture'},method:'POST',url:'/api/auth/admin'}
  assert.equal(handoff.available(),true)
  const cookies=handoff.prepare(req)
  assert.equal(req.method,'POST');assert.equal(req.headers.cookie,'native=old; admin=fixture')
  assert.doesNotMatch(JSON.stringify(cookies),/launch-token/)
  await assert.rejects(handoff.stop(req,'disable'),/浏览器未保存/);assert.equal(stops,0)
  const ready={...req,headers:{...req.headers,cookie:'native=valid; admin=fixture'}}
  assert.equal(handoff.verify(ready),true)
  assert.deepEqual(await handoff.stop(ready,'disable'),{restartRequired:false});assert.equal(stops,1)
  assert.equal(handoff.authorized(),false)
  assert.ok(checks>=3)
  assert.throws(()=>handoff.prepare({...req,headers:{host:'foreign.test'}}),/未被 Harness 信任/)
  const unsupported=createNativeHandoff({webServer:{protocol:'http:'},connection:{}})
  assert.equal(unsupported.available(),false);assert.throws(()=>unsupported.prepare(req),/不支持安全交接/)
})

test('handoff API requires administrator, same origin, CSRF, acknowledgement and a verified native cookie', async () => {
  const {installManagement}=await import('../lib/management.js')
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-handoff-route-'))
  let route,prepared=0,stopped=0
  const handler={available:()=>true,prepare(){prepared++;return ['native=fixture; Path=/; HttpOnly']},verify(req){if(req.headers.cookie!=='native=fixture')throw new Error('native cookie absent')},async stop(req){this.verify(req);stopped++;return {restartRequired:false}}}
  installManagement({webServer:{register(row){if(row.path==='/api/auth/admin')route=row.handler}}},{handoff:handler,isAdmin:req=>req.admin===true,getConfig:()=>({provider:'local',local:{users:[]},usersFile:path.join(dir,'users.json')}),reloadUsers(){},update(){}})
  const response=()=>({headers:{},setHeader(name,value){this.headers[name]=value},writeHead(code,headers){this.status=code;Object.assign(this.headers,headers)},end(body){this.body=body}})
  const post=async(fields,options={})=>{const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams(fields).toString())})(),{method:'POST',admin:options.admin!==false,headers:{host:'test.local',origin:options.origin??'https://test.local',cookie:options.cookie}});const res=response();await route(req,res);return res}
  try{
    const get=response();await route({method:'GET',admin:true},get);const csrf=JSON.parse(get.body).csrf
    const fields={action:'handoff-prepare',csrf,confirmHandoff:'yes'}
    assert.equal((await post(fields,{admin:false})).status,403)
    assert.equal((await post(fields,{origin:'https://foreign.test'})).status,403)
    assert.equal((await post({...fields,csrf:'wrong'})).status,403)
    assert.equal((await post({action:'handoff-prepare',csrf})).status,400)
    assert.equal(prepared,0)
    const preparedResponse=await post(fields);assert.equal(preparedResponse.status,200);assert.equal(preparedResponse.headers['set-cookie'][0],'native=fixture; Path=/; HttpOnly')
    assert.equal((await post({...fields,action:'handoff-disable'})).status,400);assert.equal(stopped,0)
    assert.equal((await post({...fields,action:'handoff-verify'},{cookie:'native=fixture'})).status,200)
    assert.equal((await post({...fields,action:'handoff-disable'},{cookie:'native=fixture'})).status,200);assert.equal(stopped,1)
  }finally{fs.rmSync(dir,{recursive:true,force:true})}
})

test('workspace root validation rejects relative, sensitive and nested roots and preserves migration metadata',async()=>{
  const {workspaceSettings}=await import('../lib/workspace-settings.js')
  const {persistedSettings,mergeSavedSettings}=await import('../lib/provider-settings.js')
  const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dsh-root-validation-'))),old=process.env.DSH_HOME;process.env.DSH_HOME=path.join(dir,'home')
  const root=path.join(dir,'home/web-users');fs.mkdirSync(root,{recursive:true})
  const config={workspaceRoot:root,adminWorkspaceRoot:root,stateDir:path.join(dir,'home/web-user-auth'),workspaceRootHistory:[]}
  try{
    for(const value of ['relative','/',path.join(root,'nested'),path.join(dir,'home'),config.stateDir])assert.throws(()=>workspaceSettings(value,config))
    fs.mkdirSync(config.stateDir);fs.symlinkSync(config.stateDir,path.join(dir,'sensitive-link'));assert.throws(()=>workspaceSettings(path.join(dir,'sensitive-link/new'),config))
    const next=workspaceSettings(path.join(dir,'new-users'),config)
    assert.deepEqual(next.workspaceRootHistory,[root]);assert.equal(next.adminWorkspaceRoot,root)
    const saved=persistedSettings({...config,...next});assert.equal(mergeSavedSettings(config,saved).workspaceRoot,next.workspaceRoot)
    const back=workspaceSettings(root,{...config,...next});assert.equal(back.workspaceRoot,root);assert.deepEqual(back.workspaceRootHistory,[next.workspaceRoot])
  }finally{if(old===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=old;fs.rmSync(dir,{recursive:true,force:true})}
})

test('root changes preserve historical user ownership across restart and local users can change only their own password',async()=>{
  const {apply}=await import('../lib/plugin.js');const {ADMIN_USER_ID}=await import('../lib/identity.js')
  const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dsh-root-password-'))),home=path.join(dir,'home'),old=process.env.DSH_HOME;process.env.DSH_HOME=home
  const root=path.join(home,'web-users'),alice=path.join(root,userDirectoryName('alice')),bob=path.join(root,userDirectoryName('bob'))
  fs.mkdirSync(alice,{recursive:true});fs.mkdirSync(bob,{recursive:true});fs.writeFileSync(path.join(alice,'project.txt'),'keep me')
  const usersFile=path.join(home,'web-user-auth/users.json'),store=new UserStore({users:[],usersFile})
  store.add({id:'alice',password:'original-alice-password'});store.add({id:'bob',password:'original-bob-password'})
  const headers=[{id:'alice-old-chat',cwd:alice},{id:'bob-old-chat',cwd:bob},{id:'admin-chat',cwd:'/srv/legacy-admin'}]
  const make=()=>{
    const routes=new Map(),workspaces=[{id:'alice-old',path:alice},{id:'bob-old',path:bob},{id:'legacy-admin',path:'/srv/legacy-admin'}]
    const ctx={logger:{info(){},warn(){}},on(){return ()=>{}},effect(fn){fn()},get(){},webServer:{protocol:'http:',register(row){routes.set(row.path,row.handler);return ()=>{}}},
      connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false},createPeer({principal}){return {principal,signal:{aborted:false},dispose(){this.signal.aborted=true}}}},
      remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},sessions:{list:()=>headers.map(header=>({id:header.id,header}))},sessionPersistence:{list:async()=>[]},
      sessionController:{ctx:{invocation:{peer:{principal:{kind:'harness-user',userId:'alice'}}}},list:async()=>({items:headers.map(header=>({sessionId:header.id}))})},
      directoryPickerController:{ctx:{invocation:{peer:{principal:{kind:'harness-user',userId:'alice'}}}},list:async target=>target},
      workspaceRegistry:{list:()=>workspaces,get:id=>workspaces.find(workspace=>workspace.id===id),async create(target,name){let item=workspaces.find(workspace=>workspace.path===target);if(!item){item={id:'workspace-'+workspaces.length,path:target,name};workspaces.push(item)}return item}},typert:{local:{list:()=>[]}}}
    return {ctx,routes,workspaces}
  }
  const response=()=>({headers:{},setHeader(name,value){this.headers[name]=value},writeHead(code,headers){this.status=code;Object.assign(this.headers,headers)},end(body){this.body=body}})
  const post=async(routes,route,fields,cookie,origin='https://test.local')=>{const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams(fields).toString())})(),{method:'POST',headers:{host:'test.local',origin,cookie}});const res=response();await routes.get(route)(req,res);return res}
  const get=async(routes,route,cookie)=>{const res=response();await routes.get(route)({method:'GET',headers:{host:'test.local',cookie}},res);return res}
  try{
    const initial=make();await apply(initial.ctx,{enabled:true})
    const adminPassword=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
    const admin=(await post(initial.routes,'/login',{username:'admin',password:adminPassword})).headers['set-cookie'][0].split(';')[0]
    const cookie=(await post(initial.routes,'/login',{username:'alice',password:'original-alice-password'})).headers['set-cookie'][0].split(';')[0]
    const state=JSON.parse((await get(initial.routes,'/api/auth/status',cookie)).body);assert.equal(state.canChangePassword,true);assert.equal(state.provider,'local')
    const model=JSON.parse((await get(initial.routes,'/api/auth/admin',admin)).body),newRoot=path.join(dir,'users-v2')
    const saved=await post(initial.routes,'/api/auth/admin',{action:'settings',csrf:model.csrf,enabled:'on',provider:'local',workspaceRoot:newRoot},admin);assert.equal(saved.status,200,saved.body)
    assert.equal(JSON.parse(saved.body).workspaceRoot,newRoot)
    assert.equal(JSON.parse((await get(initial.routes,'/api/auth/me',cookie)).body).workspace,path.join(newRoot,userDirectoryName('alice')))
    assert.equal(fs.readFileSync(path.join(alice,'project.txt'),'utf8'),'keep me')
    assert.deepEqual((await initial.ctx.sessionController.list({})).items.map(item=>item.sessionId),['alice-old-chat'])
    initial.ctx.sessionController.ctx.invocation.peer.principal={kind:'harness-admin',userId:ADMIN_USER_ID}
    assert.deepEqual((await initial.ctx.sessionController.list({})).items.map(item=>item.sessionId),['admin-chat'])
    assert.equal(await initial.ctx.directoryPickerController.list(alice),alice)
    await assert.rejects(initial.ctx.directoryPickerController.list(bob),/outside/)
    initial.ctx.connection.admit({headers:{host:'test.local',cookie:admin}})
    assert.ok(initial.workspaces.some(workspace=>workspace.path===path.join(root,userDirectoryName(ADMIN_USER_ID))))
    const restarted=make();await apply(restarted.ctx,{enabled:true})
    assert.equal(JSON.parse((await get(restarted.routes,'/api/auth/admin',admin)).body).workspaceRoot,newRoot)
    assert.deepEqual((await restarted.ctx.sessionController.list({})).items.map(item=>item.sessionId),['alice-old-chat'])
    const change=JSON.parse((await get(restarted.routes,'/api/auth/password',cookie)).body)
    const fields={csrf:change.csrf,currentPassword:'original-alice-password',newPassword:'new-alice-password',confirmPassword:'new-alice-password',username:'bob'}
    assert.equal((await post(restarted.routes,'/api/auth/password',{...fields,currentPassword:'wrong'},cookie)).status,400)
    assert.equal((await post(restarted.routes,'/api/auth/password',{...fields,csrf:'wrong'},cookie)).status,403)
    assert.equal((await post(restarted.routes,'/api/auth/password',fields,cookie,'https://foreign.test')).status,403)
    assert.equal((await get(restarted.routes,'/api/auth/password',admin)).status,403)
    const peer=restarted.ctx.connection.admit({headers:{host:'test.local',cookie}}).peer
    const changed=await post(restarted.routes,'/api/auth/password',fields,cookie);assert.equal(changed.status,200,changed.body);assert.match(changed.headers['set-cookie'][0],/Max-Age=0/);assert.equal(peer.signal.aborted,true)
    const updated=new UserStore({users:[],usersFile});assert.equal(updated.verify('alice','new-alice-password'),true);assert.equal(updated.verify('alice','original-alice-password'),false);assert.equal(updated.verify('bob','original-bob-password'),true)
    assert.equal(JSON.parse((await get(restarted.routes,'/api/auth/status',cookie)).body).role,'anonymous')
    assert.equal((await post(restarted.routes,'/login',{username:'alice',password:'original-alice-password'})).status,401)
    assert.equal((await post(restarted.routes,'/login',{username:'alice',password:'new-alice-password'})).status,303)
  }finally{if(old===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=old;fs.rmSync(dir,{recursive:true,force:true})}
})

test('header accounts have no password or logout controls; local account has password navigation',async()=>{
  const vm=await import('node:vm'),source=fs.readFileSync(new URL('../lib/client.js',import.meta.url),'utf8')
  for(const provider of ['local','http','header']){
    let plugin;const rows=[]
    const React={createElement:(type,props,...children)=>({type,props,children})}
    const sandbox={URL,URLSearchParams,setTimeout(){},fetch:async()=>({ok:true,status:200,json:async()=>({role:'user',name:'Alice',provider,canChangePassword:provider==='local'})}),window:{location:{href:'https://test.local/dsh-web/'},__ModuleLoader__:{load(module){plugin=module.factory(()=>React)}}}}
    vm.runInNewContext(source,sandbox)
    await plugin.apply({layout:{selectPanel(){}},effect(fn){fn()},locale:{register(){}},slots:{inject(name,fn){fn()},register(options,component){rows.push({options,component})}}})
    const footer=rows.find(row=>row.options.name==='sidebar.footer.action')
    const tree=JSON.stringify(footer.component({...footer.options.inject(),wide:true}))
    assert.equal(tree.includes('退出登录'),provider!=='header');assert.equal(tree.includes('修改密码'),provider==='local')
    assert.equal(rows.some(row=>row.options.key==='web-user-password'),provider==='local')
  }
})

test('administrator can change their own password and all old admin cookies are revoked across restart',async()=>{
  const {installAdmin}=await import('../lib/admin.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-admin-password-'))
  let revoked=0
  const make=()=>{const routes=new Map();const ctx={effect(){},webServer:{protocol:'http:',register(row){routes.set(row.path,row.handler)}},connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false}}};const isAdmin=installAdmin(ctx,home,true,{onPasswordChanged(){revoked++}});return {ctx,routes,isAdmin}}
  const response=()=>({headers:{},setHeader(name,value){this.headers[name]=value},writeHead(status,headers){this.status=status;Object.assign(this.headers,headers)},end(body){this.body=body}})
  const post=async(routes,route,fields,cookie,origin='https://test.local')=>{const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams(fields).toString())})(),{method:'POST',headers:{host:'test.local',origin,cookie}});const res=response();await routes.get(route)(req,res);return res}
  try{
    const initial=make(),password=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
    const login=await post(initial.routes,'/login',{username:'admin',password}),cookie=login.headers['set-cookie'][0].split(';')[0]
    const anonymous=response();await initial.routes.get('/api/auth/admin-password')({method:'GET',headers:{host:'test.local',cookie:'dsh-user-auth=ordinary'}},anonymous);assert.equal(anonymous.status,403)
    const state=response();await initial.routes.get('/api/auth/status')({method:'GET',headers:{host:'test.local',cookie}},state);assert.equal(JSON.parse(state.body).canChangePassword,true)
    const page=response();await initial.routes.get('/api/auth/admin-password')({method:'GET',headers:{host:'test.local',cookie}},page)
    const fields={csrf:JSON.parse(page.body).csrf,currentPassword:password,newPassword:'new-admin-fixture-password',confirmPassword:'new-admin-fixture-password'}
    assert.equal((await post(initial.routes,'/api/auth/admin-password',{...fields,currentPassword:'wrong'},cookie)).status,400)
    assert.equal((await post(initial.routes,'/api/auth/admin-password',{...fields,csrf:'wrong'},cookie)).status,403)
    assert.equal((await post(initial.routes,'/api/auth/admin-password',fields,cookie,'https://foreign.test')).status,403)
    assert.equal((await post(initial.routes,'/api/auth/admin-password',{...fields,newPassword:'short',confirmPassword:'short'},cookie)).status,400)
    const changed=await post(initial.routes,'/api/auth/admin-password',fields,cookie+'; dsh-auth-fixture=old-native')
    assert.equal(changed.status,200,changed.body);assert.equal(revoked,1);assert.equal(changed.headers['set-cookie'].length,3)
    assert.equal(initial.isAdmin({headers:{cookie}}),false)
    const credentials=path.join(home,'web-admin/credentials.json'),data=fs.readFileSync(credentials,'utf8')
    assert.doesNotMatch(data,/new-admin-fixture-password/);assert.equal(fs.statSync(credentials).mode&0o777,0o600)
    assert.equal(fs.existsSync(path.join(home,'web-admin/initial-password.txt')),false)
    const restarted=make();assert.equal(restarted.isAdmin({headers:{cookie}}),false)
    assert.equal((await post(restarted.routes,'/login',{username:'admin',password})).status,401)
    const next=await post(restarted.routes,'/login',{username:'admin',password:'new-admin-fixture-password'});assert.equal(next.status,303)
    const newCookie=next.headers['set-cookie'][0].split(';')[0];assert.equal(make().isAdmin({headers:{cookie:newCookie}}),true)
    assert.equal(fs.existsSync(path.join(home,'web-admin/initial-password.txt')),false)
  }finally{fs.rmSync(home,{recursive:true,force:true})}
})

test('recovery script uses a selected home and profile, preserving unrelated configuration and secrets',async()=>{
  const {execFileSync,spawnSync}=await import('node:child_process')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-portable-recovery-')),profile=path.join(home,'profiles/custom')
  fs.mkdirSync(profile,{recursive:true});fs.mkdirSync(path.join(home,'web-admin'))
  const manifest=path.join(profile,'package.json'),settings=path.join(home,'web-admin/auth-settings.json')
  fs.writeFileSync(manifest,JSON.stringify({private:true,dsh:{profile:{bundles:['example-existing']}}}))
  fs.writeFileSync(path.join(profile,'cordis.patch.yml'),'- id: existing-plugin\n  disabled: false\n')
  fs.writeFileSync(settings,JSON.stringify({enabled:true,provider:'http',http:{headers:{'X-Key':'fixture-secret'}},workspaceRoot:'/srv/example-users'}),{mode:0o600})
  const script=new URL('../scripts/recover-auth.py',import.meta.url).pathname
  try{
    execFileSync('python3',[script,'--home',home,'--profile','custom'])
    const saved=JSON.parse(fs.readFileSync(settings,'utf8'))
    assert.equal(saved.enabled,false);assert.equal(saved.provider,'local');assert.equal(saved.http.headers['X-Key'],'fixture-secret');assert.equal(saved.workspaceRoot,'/srv/example-users')
    assert.deepEqual(JSON.parse(fs.readFileSync(manifest,'utf8')).dsh.profile.bundles,['example-existing','@local/dsh-web-user-auth'])
    assert.match(fs.readFileSync(path.join(profile,'cordis.patch.yml'),'utf8'),/existing-plugin/)
    assert.equal(fs.statSync(settings).mode&0o777,0o600)
    execFileSync('python3',[script,'--profile','custom'],{env:{...process.env,DSH_HOME:home}})
    assert.equal(spawnSync('python3',[script,'--home',home,'--profile','../escape']).status,2)
    assert.ok(fs.readdirSync(path.dirname(settings)).some(name=>name.startsWith('auth-settings.json.recovery-')))
  }finally{fs.rmSync(home,{recursive:true,force:true})}
})

test('server password reset script produces compatible admin hashes and revokes old cookies without touching users',async()=>{
  const {execFileSync,spawnSync}=await import('node:child_process')
  const {installAdmin}=await import('../lib/admin.js')
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-admin-cli-reset-'))
  const routes=new Map(),ctx={effect(){},webServer:{protocol:'http:',register(row){routes.set(row.path,row.handler)}},connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false}}}
  const isAdmin=installAdmin(ctx,home)
  const credentials=path.join(home,'web-admin/credentials.json'),initial=path.join(home,'web-admin/initial-password.txt'),script=new URL('../scripts/reset-admin-password.py',import.meta.url).pathname
  fs.mkdirSync(path.join(home,'web-user-auth'));const ordinary=path.join(home,'web-user-auth/users.json');fs.writeFileSync(ordinary,'{"fixture":"preserve-existing-users"}')
  const login=async password=>{const req=Object.assign((async function*(){yield Buffer.from(new URLSearchParams({username:'admin',password}).toString())})(),{method:'POST',headers:{host:'test.local',origin:'http://test.local'}});const res={headers:{},setHeader(key,value){this.headers[key]=value},writeHead(status,headers){this.status=status;Object.assign(this.headers,headers)},end(){}};await routes.get('/login')(req,res);return res}
  try{
    const oldPassword=fs.readFileSync(initial,'utf8').trim(),oldLogin=await login(oldPassword),oldCookie=oldLogin.headers['set-cookie'][0].split(';')[0],before=fs.readFileSync(credentials,'utf8')
    const rejected=spawnSync('python3',[script,'--home',home,'--password-stdin'],{input:'short\n',encoding:'utf8'})
    assert.equal(rejected.status,2);assert.equal(fs.readFileSync(credentials,'utf8'),before)
    const output=execFileSync('python3',[script,'--home',home,'--password-stdin'],{input:'cli-new-admin-password\n',encoding:'utf8'})
    assert.doesNotMatch(output,/cli-new-admin-password/)
    const record=JSON.parse(fs.readFileSync(credentials,'utf8'))
    assert.equal(record.username,'admin');assert.equal(verifyPassword('cli-new-admin-password',record),true);assert.equal(verifyPassword(oldPassword,record),false)
    assert.ok(record.passwordChangedAt);assert.equal(isAdmin({headers:{cookie:oldCookie}}),false)
    assert.equal(fs.readFileSync(ordinary,'utf8'),'{"fixture":"preserve-existing-users"}');assert.equal(fs.existsSync(initial),false);assert.equal(fs.statSync(credentials).mode&0o777,0o600)
    const backup=fs.readdirSync(path.dirname(credentials)).find(name=>name.startsWith('credentials.json.before-reset-'))
    assert.equal(fs.readFileSync(path.join(path.dirname(credentials),backup),'utf8'),before);assert.equal(fs.statSync(path.join(path.dirname(credentials),backup)).mode&0o777,0o600)
    assert.equal((await login(oldPassword)).status,401);assert.equal((await login('cli-new-admin-password')).status,303)
    execFileSync('python3',[script,'--password-stdin'],{input:'second-cli-admin-password\n',encoding:'utf8',env:{...process.env,DSH_HOME:home}})
    assert.equal((await login('second-cli-admin-password')).status,303)
    const missing=path.join(home,'missing-instance');assert.equal(spawnSync('python3',[script,'--home',missing,'--password-stdin'],{input:'example-long-password\n'}).status,2);assert.equal(fs.existsSync(missing),false)
  }finally{fs.rmSync(home,{recursive:true,force:true})}
})
