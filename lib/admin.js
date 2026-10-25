import fs from 'node:fs'
import { patchServiceMethod } from './service-patch.js'
import path from 'node:path'
import crypto from 'node:crypto'
import { hashPassword, verifyPassword, loadOrCreateSecret } from './users.js'
import { builtInCookieState, cookiesWithPrefix, readCookie, signSession, verifySession, sessionCookie, clearCookie } from './cookies.js'

const COOKIE = 'dsh-admin-auth'
export function installAdmin(ctx, home, userAuthEnabled = false, options = {}) {
  const listenerSecure = ctx.webServer.protocol === 'https:'
  const dir = path.join(home, 'web-admin')
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  const secret = loadOrCreateSecret(path.join(dir, 'secret'))
  const credentials = path.join(dir, 'credentials.json')
  if (!fs.existsSync(credentials)) {
    const password = crypto.randomBytes(24).toString('base64url')
    fs.writeFileSync(credentials, JSON.stringify({ username: 'admin', passwordHash: hashPassword(password) }), { mode: 0o600, flag: 'wx' })
    fs.writeFileSync(path.join(dir, 'initial-password.txt'), password + '\n', { mode: 0o600, flag: 'wx' })
  }
  const enabled = () => typeof userAuthEnabled === 'function' ? userAuthEnabled() : userAuthEnabled
  const isAdmin = req => {
    const value = verifySession(readCookie(req.headers.cookie, COOKIE), secret)
    if(value?.id!=='owner'||value?.provider!=='local')return false
    try{const record=JSON.parse(fs.readFileSync(credentials,'utf8'));return typeof record.passwordChangedAt!=='number'||value.iat>record.passwordChangedAt}catch{return false}
  }
  const secure = req => req.headers['x-forwarded-proto'] === 'https' || listenerSecure
  const originAllowed = req => {
    if (!req.headers.origin) return true
    try { return new URL(req.headers.origin).host === req.headers.host } catch { return false }
  }
  const page = (message = '',request) => `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>登录 · DeepSeek Harness</title><style>body{background:#101720;color:#eee;font:16px system-ui;max-width:440px;margin:12vh auto;padding:24px}input,button{box-sizing:border-box;width:100%;padding:14px;margin:10px 0;border-radius:8px}input{background:#19232f;color:#fff;border:1px solid #536172}button{background:#a9c7ff;border:0;cursor:pointer}p{line-height:1.7;color:#bcc9d9}.error{color:#ffb2ac}</style><p>DEEPSEEK HARNESS</p><h1>登录</h1><p>管理员和普通用户使用同一入口，登录后按账号权限访问。</p>${enabled()?'':'<p>当前仅开放管理员登录，普通用户认证尚未开启。</p>'}<p class="error" role="alert">${message}</p><form method="post" action="./login"><label>用户名<input name="username" autocomplete="username" required autofocus></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label><button>登录</button></form><p>此账号用于访问本机 Web UI，与 DeepSeek 平台账号独立。</p>${request?options.tokenLoginMarkup?.(request)??'':''}</html>`
  let attempts = []
  const login = async (req, res) => {
    res.setHeader('cache-control', 'no-store'); res.setHeader('referrer-policy', 'same-origin')
    if (req.method === 'GET' || req.method === 'HEAD') { res.setHeader('content-type', 'text/html; charset=utf-8'); res.end(req.method === 'HEAD' ? undefined : page(new URL(req.url??'/','http://dsh.invalid').searchParams.get('passwordChanged')==='1'?'密码已修改，请使用新密码登录。':'',req)); return }
    if (req.method !== 'POST') { res.writeHead(405, { allow: 'GET, HEAD, POST' }); res.end(); return }
    if (!originAllowed(req)) { res.writeHead(403, { 'content-type': 'text/html; charset=utf-8' }); res.end(page('登录页面已过期，请重新打开登录页后提交。',req)); return }
    attempts = attempts.filter(time => time > Date.now() - 60000)
    if (attempts.length >= 20) { res.writeHead(429, { 'retry-after': '60' }); res.end('请稍后再试'); return }
    attempts.push(Date.now())
    let body = ''; for await (const chunk of req) { body += chunk; if (Buffer.byteLength(body) > 8192) { res.writeHead(413); res.end(); return } }
    const form = new URLSearchParams(body)
    const username = (form.get('username') ?? '').trim(), password = form.get('password') ?? ''
    const record = JSON.parse(fs.readFileSync(credentials, 'utf8'))
    if (username === record.username && verifyPassword(password, record)) {
      const now = Date.now()
      const cookie = signSession({ v:1,id:'owner',name:'Administrator',provider:'local',iat:now,exp:now+7*86400000 },secret)
      res.writeHead(303, { location:'./', 'set-cookie': [sessionCookie(COOKIE,cookie,{maxAgeSeconds:7*86400,secure:secure(req)}),clearCookie('dsh-user-auth',{secure:secure(req)})] }); res.end(); return
    }
    // The administrator name is reserved and can never fall through to a local/remote user account.
    if (username !== record.username && enabled() && options.loginUser) {
      try { if (await options.loginUser(username, password, req, res)) return } catch { /* Generic message avoids disclosing provider or credential details. */ }
    }
    res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' }); res.end(page('用户名或密码错误，或该账号暂未开放登录。',req))
  }
  ctx.webServer.register({ kind:'exact',path:'/login',handler:login })
  ctx.webServer.register({ kind:'exact',path:'/admin',handler:(req,res)=>{
    if(req.method==='POST') return login(req,res)
    res.writeHead(303,{location:'./login','cache-control':'no-store'});res.end()
  } })
  const passwordCsrf=crypto.randomBytes(32).toString('hex')
  let passwordAttempts=[]
  ctx.webServer.register({kind:'exact',path:'/api/auth/admin-password',handler:async(req,res)=>{
    const send=(status,body)=>{res.writeHead(status,{'cache-control':'no-store','content-type':'application/json; charset=utf-8'});res.end(JSON.stringify(body))}
    if(!isAdmin(req)){send(403,{error:'需要管理员登录'});return}
    if(req.method==='GET'){send(200,{csrf:passwordCsrf});return}
    if(req.method!=='POST'){res.writeHead(405,{allow:'GET, POST'});res.end();return}
    if(!req.headers.origin||!originAllowed(req)){send(403,{error:'来源校验失败'});return}
    let body='';for await(const chunk of req){body+=chunk;if(Buffer.byteLength(body)>8192){send(413,{error:'提交内容过长'});return}}
    const form=new URLSearchParams(body)
    if(form.get('csrf')!==passwordCsrf){send(403,{error:'页面已过期，请刷新重试'});return}
    passwordAttempts=passwordAttempts.filter(time=>time>Date.now()-60000)
    if(passwordAttempts.length>=5){send(429,{error:'尝试过于频繁，请一分钟后再试'});return}
    passwordAttempts.push(Date.now())
    const record=JSON.parse(fs.readFileSync(credentials,'utf8'))
    if(!verifyPassword(form.get('currentPassword')??'',record)){send(400,{error:'当前密码不正确'});return}
    const password=form.get('newPassword')??''
    if(password.length<12||password.length>1024){send(400,{error:'密码长度需要为 12 到 1024 个字符'});return}
    if(password!==form.get('confirmPassword')){send(400,{error:'两次输入的新密码不一致'});return}
    const next={username:record.username,passwordHash:hashPassword(password),passwordChangedAt:Date.now()}
    const temporary=credentials+'.tmp-'+crypto.randomBytes(8).toString('hex')
    try{
      fs.writeFileSync(temporary,JSON.stringify(next)+'\n',{mode:0o600,flag:'wx'})
      fs.renameSync(temporary,credentials)
    }catch{
      try{fs.unlinkSync(temporary)}catch{}
      send(500,{error:'密码保存失败，请检查服务器目录写入权限'});return
    }
    try{fs.unlinkSync(path.join(dir,'initial-password.txt'))}catch{}
    options.onPasswordChanged?.()
    const cookies=[clearCookie(COOKIE,{secure:secure(req)}),clearCookie('dsh-user-auth',{secure:secure(req)})]
    for(const cookie of cookiesWithPrefix(req.headers.cookie,'dsh-auth-'))cookies.push(clearCookie(cookie.name,{secure:listenerSecure}))
    res.setHeader('set-cookie',cookies)
    send(200,{message:'管理员密码已修改，请重新登录；旧管理员登录凭据已失效。'})
  }})
  const logout = (req,res,json=false) => {
    if(req.method!=='POST'){res.writeHead(405,{allow:'POST'});res.end();return}
    if(!req.headers.origin || !originAllowed(req)){res.writeHead(403);res.end();return}
    const cookies=[clearCookie(COOKIE,{secure:secure(req)}),clearCookie('dsh-user-auth',{secure:secure(req)})]
    for(const cookie of cookiesWithPrefix(req.headers.cookie,'dsh-auth-'))cookies.push(clearCookie(cookie.name,{secure:listenerSecure}))
    if(json) {res.writeHead(204,{'cache-control':'no-store','set-cookie':cookies});res.end()}
    else {res.writeHead(303,{location:'../login','cache-control':'no-store','set-cookie':cookies});res.end()}
  }
  ctx.webServer.register({kind:'exact',path:'/admin/logout',handler:(req,res)=>logout(req,res)})
  ctx.webServer.register({kind:'exact',path:'/api/auth/logout',handler:(req,res)=>logout(req,res,true)})
  ctx.webServer.register({kind:'exact',path:'/api/auth/status',handler:(req,res)=>{
    if(req.method!=='GET'){res.writeHead(405,{allow:'GET'});res.end();return}
    options.clearTokenCookie?.(req,res)
    let state={role:'anonymous',name:'',userId:null}
    if(isAdmin(req))state={role:'admin',name:'admin',userId:'owner',provider:'local'}
    else {
      const user=options.identifyUser?.(req)
      if(user)state={role:user.administrator===true?'admin':'user',name:user.name,userId:user.id,provider:user.provider}
    }
    res.writeHead(200,{'content-type':'application/json; charset=utf-8','cache-control':'no-store'})
    res.end(JSON.stringify({...state,...(state.provider==='token'?{tokenClient:options.tokenClientConfig?.(req)}:{}),userAuthEnabled:enabled(),canChangePassword:state.role==='admin'&&state.provider==='local'||state.role==='user'&&state.provider==='local'&&options.canChangePassword?.(state.userId)===true}))
  }})
  for (const name of ['admit','authorizeIndex']) {
    const dispose = patchServiceMethod(ctx.connection,name,original => name === 'admit' ? function(req) {
      if (!isAdmin(req)) return original.call(this,req)
      const peer = options.adminPeer ? options.adminPeer(req) : this.browserPeer
      return peer ? {peer} : {rejection:401}
    } : function(req,res) {
      if (isAdmin(req)) return true
      const url = new URL(req.url ?? '/', 'http://dsh.invalid')
      if (!url.searchParams.has('token') && !builtInCookieState(req.headers, listenerSecure).present) {
        res.writeHead(303, {location:'./login','cache-control':'no-store'}); res.end(); return false
      }
      return original.call(this,req,res)
    }
    )
    ctx.effect(() => dispose)
  }
  return isAdmin
}
