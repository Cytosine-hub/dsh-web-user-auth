import assert from 'node:assert/strict'
import test from 'node:test'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import vm from 'node:vm'
import {createServer} from 'node:http'
import {normalizeTokenConfig,tokenIdentity,TokenSessions} from '../lib/token-auth.js'
import {tokenBrowserScript,tokenLoginMarkup} from '../lib/token-browser.js'
import {parseSettings,mergeSavedSettings,persistedSettings} from '../lib/provider-settings.js'
import {verifySession} from '../lib/cookies.js'

const origin='https://portal.example.test'
const config=extra=>normalizeTokenConfig({siteOrigin:origin,userInfoUrl:'/api/me',...extra},true)
const body=()=>({user:{id:'alice',name:'Alice'}})

test('token configuration enforces same origin, storage names, safe headers and persisted response rules',()=>{
  const value=config({storage:'sessionStorage',storageKey:'auth',storageField:'access.token'})
  assert.equal(value.userInfoUrl,origin+'/api/me')
  for(const userInfoUrl of ['https://evil.example.test/me','//evil.example.test/me','https://portal.example.test.evil/me','https://user:password@portal.example.test/me','/api/me#fragment'])assert.throws(()=>config({userInfoUrl}),/同源/)
  for(const tokenHeader of ['cookie','host','origin','x-forwarded-host','proxy-authorization','content-length'])assert.throws(()=>config({tokenHeader}),/请求控制头/)
  assert.throws(()=>config({storage:'sessionstorge'}),/存储位置/)
  assert.throws(()=>config({successStatuses:[401]}),/2xx/)
  assert.throws(()=>config({siteOrigin:origin+'/sub/'}),/同源站点/)
  const form=new URLSearchParams({provider:'token',enabled:'on','token.siteOrigin':origin,'token.userInfoUrl':'/api/me','token.storage':'sessionStorage','token.successField':'code','token.successValue':'0','token.expiredField':'expired','token.expiredValue':'true'})
  const next=parseSettings(form,{provider:'local'},origin)
  assert.equal(next.token.successValue,0);assert.equal(next.token.expiredValue,true)
  assert.equal(mergeSavedSettings({provider:'local'},persistedSettings(next)).provider,'token')
  assert.throws(()=>parseSettings(form,{provider:'local'},'https://other.example.test'),/当前配置页面同源/)
})

test('token identity requires matching JSON rules, valid expiration and non-reserved user identity',()=>{
  const rules=config({successField:'code',successValue:0,expiredField:'expired',expiredValue:true,userField:'data.user',idField:'uid',nameField:'display',expiresAtField:'expires',expiresAtFormat:'milliseconds'})
  const response={code:0,expired:false,expires:2000,data:{user:{uid:42,display:'Alice'}}}
  assert.deepEqual(tokenIdentity(response,rules,1000),{identity:{id:'42',name:'Alice',provider:'token'},expiresAt:2000})
  for(const patch of [{code:'0'},{expired:true},{expired:undefined},{expires:1000},{expires:'invalid'},{data:{user:{uid:'__dsh_administrator__'}}},{data:{user:{uid:'../alice'}}}])assert.throws(()=>tokenIdentity({...response,...patch},rules,1000))
  assert.equal(tokenIdentity({id:'alice'},config({userField:''})).identity.id,'alice')
  assert.throws(()=>tokenIdentity({user:{name:'No id'}},config()))
  assert.throws(()=>config({idField:'__proto__.id'}))
  assert.throws(()=>tokenIdentity({user:{id:'alice'},exp:null},config({expiresAtField:'exp'})))
})

test('token sessions revalidate and revoke expired identities, dispose credentials, and fail closed on faults',async()=>{
  let now=1000,valid=true,calls=0;const timers=[],revoked=[]
  const sessions=new TokenSessions(config({expiredField:'expired'}),{now:()=>now,onRevoke:id=>revoked.push(id),setTimer:callback=>{timers.push(callback);return timers.length},clearTimer(){},fetchImpl:async(url,options)=>{calls++;assert.equal(url,origin+'/api/me');assert.equal(options.headers.authorization,'Bearer fixture-token');assert.equal(options.redirect,'error');return new Response(JSON.stringify({...body(),expired:!valid}),{status:200})}})
  const first=await sessions.exchange('fixture-token')
  assert.equal(first.changed,true);assert.equal(first.record.identity.id,'alice')
  assert.equal((await sessions.exchange('fixture-token',first.record.sid)).changed,false);assert.equal(calls,1)
  valid=false;await timers.shift()();assert.equal(sessions.get(first.record.sid),undefined);assert.deepEqual(revoked,['alice']);assert.equal(first.record.token,'')
  await assert.rejects(sessions.exchange('fixture-token'),/过期/)
  valid=true;const next=await sessions.exchange('fixture-token');sessions.dispose();assert.equal(next.record.token,'');assert.equal(sessions.sessions.size,0)
  const fault=new TokenSessions(config(),{fetchImpl:async()=>{throw new Error('fixture-sensitive-token')}})
  await assert.rejects(fault.exchange('fixture-sensitive-token'),error=>error.status===503&&!error.message.includes('fixture-sensitive-token'))
  for(const response of [new Response('{}',{status:401}),new Response('{}',{status:403}),new Response('bad json'),new Response('x'.repeat(70000))]){
    const invalid=new TokenSessions(config(),{fetchImpl:async()=>response});await assert.rejects(invalid.exchange('fixture-token'));assert.equal(invalid.sessions.size,0);invalid.dispose()
  }
})

test('token sessions enforce response deadlines and revoke a changed upstream identity',async()=>{
  let now=1000,id='alice';const timers=[],revoked=[]
  const sessions=new TokenSessions(config({expiresAtField:'expires',expiresAtFormat:'milliseconds'}),{now:()=>now,setTimer:callback=>{timers.push(callback);return timers.length},clearTimer(){},onRevoke:value=>revoked.push(value),fetchImpl:async()=>new Response(JSON.stringify({user:{id},expires:2000}))})
  const first=await sessions.exchange('fixture-one');id='bob';await timers.shift()();assert.equal(sessions.get(first.record.sid),undefined);assert.deepEqual(revoked,['alice'])
  const second=await sessions.exchange('fixture-two');now=2001;assert.equal(sessions.get(second.record.sid),undefined);assert.equal(second.record.token,'');sessions.dispose()
})

function browser({storage='localStorage',value='fixture-token',field='',siteOrigin=origin,query='',fail=false}={}){
  const nodes=[],events={},intervals=[],navigations=[],requests=[],reads=[];let stored=value
  const node=tag=>({tag,children:[],append(...children){this.children.push(...children)},addEventListener(name,callback){this[name]=callback}})
  const window={location:{href:origin+'/assistant/login'+query,origin,replace:url=>navigations.push(url)},addEventListener:(name,fn)=>events[name]=fn,removeEventListener:name=>delete events[name]}
  for(const area of ['localStorage','sessionStorage'])window[area]={getItem(key){reads.push([area,key]);return area===storage?stored:null}}
  const sandbox={window,URL,Date,Object,JSON,document:{createElement:tag=>{const result=node(tag);nodes.push(result);return result},body:node('body')},setInterval:fn=>{intervals.push(fn);return intervals.length},clearInterval(){},fetch:async(url,options)=>{requests.push({url,options});const denied=fail||options?.method==='POST'&&!JSON.parse(options.body).token;return {ok:!denied,status:denied?401:200,json:async()=>denied?{error:'Token 已过期'}:url.endsWith('/status')?{role:'user',provider:'token'}:{id:'alice',changed:false}}}}
  vm.runInNewContext(tokenBrowserScript,sandbox)
  return {window,nodes,events,intervals,navigations,requests,reads,config:{siteOrigin,storage,storageKey:'auth-key',storageField:field,role:'user'},setStored:value=>stored=value}
}
const flush=()=>new Promise(resolve=>setImmediate(resolve))

test('browser bridge reads both storage areas and JSON mapping, sending tokens only to same-origin POST',async()=>{
  for(const storage of ['localStorage','sessionStorage']){
    const fixture=browser({storage,value:JSON.stringify({auth:{token:'fixture-token'}}),field:'auth.token'})
    fixture.window.__DshTokenAuth.startLogin(fixture.config);await flush()
    assert.deepEqual(fixture.reads[0],[storage,'auth-key']);assert.equal(fixture.requests[0].url,origin+'/assistant/api/auth/token')
    assert.equal(fixture.requests[0].options.method,'POST');assert.equal(fixture.requests[0].options.credentials,'same-origin');assert.equal(JSON.parse(fixture.requests[0].options.body).token,'fixture-token')
    assert.equal(fixture.requests[0].url.includes('fixture-token'),false);assert.equal(fixture.navigations[0],origin+'/assistant/')
  }
  const foreign=browser({siteOrigin:'https://foreign.example.test'});foreign.window.__DshTokenAuth.startLogin(foreign.config);await flush();assert.equal(foreign.reads.length,0);assert.equal(foreign.requests.length,0)
  const admin=browser({query:'?admin=1'});admin.window.__DshTokenAuth.startLogin(admin.config);await flush();assert.equal(admin.requests.length,0);assert.equal(admin.reads.length,0)
  assert.doesNotMatch(tokenLoginMarkup({storageKey:'</script><script>alert(1)</script>'}),/<script>alert/)
})

test('browser bridge surfaces expired token errors and watches storage removal without logging secrets',async()=>{
  const failed=browser({fail:true});failed.window.__DshTokenAuth.startLogin(failed.config);await flush();assert.ok(failed.nodes.some(node=>node.textContent==='Token 已过期'));assert.equal(failed.navigations.length,0)
  const watched=browser();watched.window.__DshTokenAuth.watch(watched.config);await flush();assert.equal(watched.requests.length,2)
  watched.setStored('');await watched.events.storage();assert.equal(JSON.parse(watched.requests.at(-1).options.body).token,'');assert.equal(watched.navigations.at(-1),origin+'/assistant/login')
})

test('token mode integrates same-origin exchange, signed opaque sessions, expiry and preserved admin access',async()=>{
  const {apply}=await import('../lib/plugin.js')
  let expiresAt=Date.now()+100000,expired=false,headersSeen,bodyIdentity='alice',bodyRoles=['member']
  const server=createServer((req,res)=>{headersSeen=req.headers.authorization;res.setHeader('content-type','application/json');if(expired){res.writeHead(401);res.end('{}');return}res.end(JSON.stringify({code:0,expired:false,expiresAt,data:{uid:bodyIdentity,display:'Alice',roles:bodyRoles}}))})
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve))
  const site='http://127.0.0.1:'+server.address().port,host=new URL(site).host
  const home=fs.mkdtempSync(path.join(os.tmpdir(),'dsh-token-mode-')),previous=process.env.DSH_HOME;process.env.DSH_HOME=home
  const routes=new Map(),peers=[],disposers=[]
  const ctx={logger:{info(){},warn(){}},on(){return ()=>{}},effect(fn){const dispose=fn();if(typeof dispose==='function')disposers.push(dispose)},get(){},webServer:{protocol:'http:',register(route){routes.set(route.path,route.handler);return ()=>routes.delete(route.path)}},
    connection:{browserPeer:{principal:{kind:'owner'}},admit(){return {rejection:401}},authorizeIndex(){return false},createPeer({principal}){const peer={principal,signal:{aborted:false},dispose(){this.signal.aborted=true}};peers.push(peer);return peer}},remoteAccess:{registerPolicy(){return ()=>{}},invalidate(){}},sessions:{list:()=>[]},sessionPersistence:{list:async()=>[]},sessionController:{},directoryPickerController:{},workspaceRegistry:{list:()=>[],create:async()=>({id:'token-workspace'})},typert:{local:{list:()=>[]}}}
  const res=()=>({headers:{},setHeader(name,value){this.headers[name]=value},writeHead(status,headers){this.status=status;Object.assign(this.headers,headers)},end(body){this.body=body}})
  const post=async(route,body,cookie,requestOrigin=site,requestHost=host)=>{const req=Object.assign((async function*(){yield Buffer.from(typeof body==='string'?body:JSON.stringify(body))})(),{method:'POST',headers:{host:requestHost,origin:requestOrigin,cookie,'content-type':'application/json','sec-fetch-site':'same-origin'}});const result=res();await routes.get(route)(req,result);return result}
  const get=async(route,cookie,url=route)=>{const result=res();await routes.get(route)({method:'GET',url,headers:{host,cookie}},result);return result}
  try{
    await apply(ctx,{enabled:true,provider:'token',token:{siteOrigin:site,userInfoUrl:'/me',storage:'sessionStorage',storageKey:'auth',storageField:'access.token',roleField:'roles',adminRoles:['admin'],userField:'data',idField:'uid',nameField:'display',successField:'code',successValue:0,expiredField:'expired',expiresAtField:'expiresAt',expiresAtFormat:'milliseconds'}})
    assert.match((await get('/login')).body,/auth-token-client.js/)
    assert.match((await get('/login')).body,/sessionStorage/)
    assert.equal((await post('/api/auth/token',{token:'fixture-user-token'},undefined,'https://foreign.example.test')).status,403)
    assert.equal((await post('/api/auth/token',{token:'fixture-user-token'},undefined,site,'foreign.example.test')).status,403)
    assert.equal((await get('/api/auth/token')).status,405)
    const logged=await post('/api/auth/token',{token:'fixture-user-token',user:{id:'__dsh_administrator__'}});assert.equal(logged.status,200,logged.body);assert.equal(JSON.parse(logged.body).id,'alice');assert.equal(headersSeen,'Bearer fixture-user-token')
    const cookie=logged.headers['set-cookie'][0].split(';')[0],secret=Buffer.from(fs.readFileSync(path.join(home,'web-user-auth/secret'),'utf8').trim(),'base64url')
    const payload=verifySession(cookie.slice(cookie.indexOf('=')+1),secret);assert.equal(payload.provider,'token');assert.ok(payload.tokenSessionId);assert.equal(payload.exp,expiresAt);assert.ok(Number(logged.headers['set-cookie'][0].match(/Max-Age=(\d+)/)[1])<=100);assert.doesNotMatch(JSON.stringify(payload),/fixture-user-token/)
    const state=JSON.parse((await get('/api/auth/status',cookie)).body);assert.equal(state.role,'user');assert.equal(state.tokenClient.storage,'sessionStorage');assert.equal(state.canChangePassword,false)
    assert.equal((await get('/api/auth/admin',cookie)).status,403)
    const peer=ctx.connection.admit({headers:{host,cookie}}).peer;assert.equal(peer.principal.userId,'alice')
    const password=fs.readFileSync(path.join(home,'web-admin/initial-password.txt'),'utf8').trim()
    const administrator=await post('/login',new URLSearchParams({username:'admin',password}).toString());assert.equal(administrator.status,303)
    const adminCookie=administrator.headers['set-cookie'][0].split(';')[0]
    assert.equal(JSON.parse((await get('/api/auth/status',adminCookie)).body).role,'admin')
    assert.equal(JSON.parse((await post('/api/auth/token',{token:'fixture-user-token'},adminCookie)).body).administrator,true)
    bodyRoles=['admin']
    const promoted=await post('/api/auth/token',{token:'fixture-admin-token'},cookie)
    const externalAdminCookie=promoted.headers['set-cookie'][0].split(';')[0]
    const externalState=JSON.parse((await get('/api/auth/status',externalAdminCookie)).body)
    assert.equal(externalState.role,'admin');assert.equal(externalState.userId,'alice');assert.equal(externalState.provider,'token');assert.equal(externalState.canChangePassword,false);assert.equal(externalState.tokenClient.role,'admin')
    assert.equal((await get('/api/auth/admin',externalAdminCookie)).status,200)
    assert.equal((await get('/api/auth/admin-password',externalAdminCookie)).status,403)
    const externalPeer=ctx.connection.admit({headers:{host,cookie:externalAdminCookie}}).peer
    assert.equal(externalPeer.principal.kind,'harness-admin');assert.equal(externalPeer.principal.userId,'alice')
    bodyRoles=['member']
    const demoted=await post('/api/auth/token',{token:'fixture-member-token'},externalAdminCookie)
    const memberCookie=demoted.headers['set-cookie'][0].split(';')[0]
    assert.equal(externalPeer.signal.aborted,true)
    assert.equal((await get('/api/auth/admin',memberCookie)).status,403)
    assert.equal(ctx.connection.admit({headers:{host,cookie:memberCookie}}).peer.principal.kind,'harness-user')
    bodyIdentity='__dsh_administrator__';assert.equal((await post('/api/auth/token',{token:'another-fixture'})).status,401);bodyIdentity='alice'
    expired=true
    assert.equal((await post('/api/auth/token',{token:'expired-fixture'},cookie)).status,401)
    assert.equal(peer.signal.aborted,true);assert.equal(ctx.connection.admit({headers:{host,cookie}}).rejection,401)
    const invalidState=await get('/api/auth/status',cookie);assert.equal(JSON.parse(invalidState.body).role,'anonymous');assert.match(invalidState.headers['set-cookie'][0],/Max-Age=0/)
    const deniedRoot=res();assert.equal(ctx.connection.authorizeIndex({url:'/',headers:{host,cookie}},deniedRoot),false);assert.match(deniedRoot.headers['set-cookie'][0],/Max-Age=0/)
    assert.equal(JSON.parse((await get('/api/auth/status',adminCookie)).body).role,'admin')
  }finally{
    for(const dispose of disposers.reverse())dispose()
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve))
    if(previous===undefined)delete process.env.DSH_HOME;else process.env.DSH_HOME=previous
    fs.rmSync(home,{recursive:true,force:true})
  }
})


test('periodic server revalidation revokes an expired response without waiting for another browser request',async()=>{
  const expiresAt=Date.now()+150
  let resolveRevoked
  const revoked=new Promise(resolve=>resolveRevoked=resolve)
  const sessions=new TokenSessions(config({expiresAtField:'expiresAt',expiresAtFormat:'milliseconds'}),{onRevoke:resolveRevoked,fetchImpl:async()=>new Response(JSON.stringify({...body(),expiresAt}))})
  const record=(await sessions.exchange('fixture-short-lived')).record
  let timeout
  try{
    assert.equal(await Promise.race([revoked,new Promise((_,reject)=>timeout=setTimeout(()=>reject(new Error('periodic revocation did not run')),1500))]),'alice')
    assert.equal(record.token,'');assert.equal(sessions.sessions.size,0)
  }finally{clearTimeout(timeout);sessions.dispose()}
})

test('invalid inactive token settings do not block recovery into local mode',async()=>{
  const {normalizeConfig}=await import('../lib/plugin.js')
  const value=normalizeConfig({provider:'local',token:{siteOrigin:'invalid',userInfoUrl:'https://outside.example.test'}})
  assert.equal(value.provider,'local')
  assert.throws(()=>normalizeConfig({provider:'token',token:{siteOrigin:'invalid',userInfoUrl:'https://outside.example.test'}}))
})


test('token administrator roles use explicit exact matching and fail closed for missing or malformed roles',()=>{
  const rules=config({roleField:'access.roles',adminRoles:['admin','superadmin']})
  for(const roles of ['admin',['member','superadmin']])assert.equal(tokenIdentity({user:{id:'alice',access:{roles}}},rules).identity.administrator,true)
  for(const roles of [undefined,null,1,{},['admin',{}],'ADMIN','administrator','admin,member',[]])assert.equal(tokenIdentity({user:{id:'alice',access:{roles}}},rules).identity.administrator,undefined)
  assert.equal(tokenIdentity({user:{id:'alice',role:'admin'}},config()).identity.administrator,undefined)
  for(const patch of [{adminRoles:['admin']},{roleField:'role',adminRoles:'admin'},{roleField:'role',adminRoles:['']}])assert.throws(()=>config(patch),/角色/)
  const form=new URLSearchParams({provider:'token','token.siteOrigin':origin,'token.userInfoUrl':'/api/me','token.roleField':'roles','token.adminRoles':'["admin"]'})
  assert.deepEqual(mergeSavedSettings({},persistedSettings(parseSettings(form,{},origin))).token.adminRoles,['admin'])
})

test('periodic role demotion revokes administrator sessions and credentials',async()=>{
  let roles=['admin'];const timers=[],revoked=[]
  const sessions=new TokenSessions(config({roleField:'roles',adminRoles:['admin']}),{setTimer:callback=>{timers.push(callback);return timers.length},clearTimer(){},onRevoke:id=>revoked.push(id),fetchImpl:async()=>new Response(JSON.stringify({user:{id:'alice',roles}}))})
  const {record}=await sessions.exchange('fixture-administrator')
  assert.equal(sessions.administrator('alice').administrator,true)
  roles=['member'];await timers.shift()()
  assert.equal(sessions.administrator('alice'),undefined);assert.equal(sessions.get(record.sid),undefined);assert.equal(record.token,'');assert.deepEqual(revoked,['alice']);sessions.dispose()
})

test('token administrators receive management grants while sessions and workspaces stay isolated',async()=>{
  const {createUserAccessPolicy}=await import('../lib/policy.js')
  let administrator=true
  const {policy,rememberSession}=createUserAccessPolicy({ctx:{typert:{local:{list:()=>[{namespace:'pluginManager',method:'setPluginEnabled'}]}},workspaceRegistry:{list:()=>[{id:'alice-workspace',path:'/srv/users/alice'},{id:'bob-workspace',path:'/srv/users/bob'}]},remoteAccess:{invalidate(){}}},workspaceRoot:'/srv/users',workspaceOf:id=>'/srv/users/'+id,userForPath:target=>target.split('/')[3],isAdministrator:id=>administrator&&id==='alice'})
  rememberSession('alice-chat','/srv/users/alice');rememberSession('bob-chat','/srv/users/bob')
  const bindings=policy.bindings({kind:'harness-admin',userId:'alice'})
  assert.ok(bindings[0].role.actions.includes('pluginManager/setPluginEnabled'))
  assert.ok(bindings.some(binding=>binding.resource.id==='alice-chat'))
  assert.ok(bindings.some(binding=>binding.resource.id==='alice-workspace'))
  assert.equal(bindings.some(binding=>binding.resource.id==='bob-chat'||binding.resource.id==='bob-workspace'),false)
  assert.deepEqual(policy.bindings({kind:'harness-admin',userId:'bob'}),[])
  administrator=false;assert.deepEqual(policy.bindings({kind:'harness-admin',userId:'alice'}),[])
})
