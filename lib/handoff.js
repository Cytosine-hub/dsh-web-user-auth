import { AsyncLocalStorage } from 'node:async_hooks'
import { AUTH_PACKAGE } from './plugin-management.js'

/** A same-origin, administrator-only exchange into the existing Harness login.
 * Uses Harness's own cookie issuer; never returns a launch token to the UI. */
export function createNativeHandoff(ctx) {
  const scope=new AsyncLocalStorage(),approval={}
  let stopping=false
  const auth=()=>ctx.connection.browserAuth
  const secure=()=>ctx.webServer.protocol==='https:'
  const available=()=>['authenticatedUrl','authorizeIndex','isAuthenticated'].every(key=>typeof auth()?.[key]==='function')&&typeof ctx.connection.isTrusted==='function'
  const verified=req=>available()&&ctx.connection.isTrusted(req)&&auth().isAuthenticated(req,secure())
  return {
    available,
    authorized:()=>scope.getStore()===approval,
    prepare(req){
      if(!available())throw new Error('当前 Harness 版本不支持安全交接，请保留插件并通过服务器管理')
      if(!ctx.connection.isTrusted(req))throw new Error('当前访问地址未被 Harness 信任，未执行停用')
      const native=auth(),exchange=Object.create(req)
      exchange.method='GET'
      const launch=new URL(native.authenticatedUrl('http://dsh.invalid/'))
      exchange.url=launch.pathname+launch.search
      let status,headers
      native.authorizeIndex(exchange,{writeHead(code,values){status=code;headers=values},end(){}},secure())
      const cookies=typeof headers?.['set-cookie']==='string'?[headers['set-cookie']]:headers?.['set-cookie']
      if(status!==303||!Array.isArray(cookies)||!cookies.length)throw new Error('未能建立 Harness 原生登录，未执行停用')
      const proof=Object.create(req)
      const pairs=cookies.map(cookie=>cookie.split(';')[0]),names=new Set(pairs.map(pair=>pair.split('=')[0]))
      const old=(req.headers.cookie??'').split(';').map(pair=>pair.trim()).filter(pair=>pair&&!names.has(pair.split('=')[0]))
      proof.headers={...req.headers,cookie:[...old,...pairs].join('; ')}
      if(!native.isAuthenticated(proof,secure()))throw new Error('原生登录校验失败，未执行停用')
      return cookies
    },
    verify(req){if(!verified(req))throw new Error('浏览器未保存有效的原生登录凭据，请检查 Cookie 设置；未执行停用');return true},
    async stop(req,operation){
      if(!['disable','remove'].includes(operation))throw new Error('未知停用操作')
      this.verify(req)
      if(stopping)throw new Error('停用正在执行，请勿重复提交')
      stopping=true
      try{
        const manager=ctx.get('pluginManager')
        const result=await scope.run(approval,()=>operation==='remove'?manager.removeBundle(AUTH_PACKAGE):manager.setBundleEnabled(AUTH_PACKAGE,false))
        if(result?.error||!['applied','restart-required'].includes(result?.application))throw new Error('插件操作未完成：'+(result?.error?.code??result?.application??'unknown'))
        return {restartRequired:result.application==='restart-required'}
      }finally{stopping=false}
    },
  }
}
