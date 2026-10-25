import { workspaceSettings } from './workspace-settings.js'
import { tokenDefaults,normalizeTokenConfig } from './token-auth.js'
const providers = ['local', 'http', 'header', 'token']
const httpDefaults = {loginUrl:'',userInfoUrl:'',requestFormat:'json',tokenField:'access_token',userField:'user',idField:'id',nameField:'name',tokenHeader:'authorization',tokenPrefix:'Bearer ',timeoutMs:10000}
const headerDefaults = {userHeader:'x-auth-request-user',nameHeader:'x-auth-request-name',secretHeader:'x-dsh-auth-secret'}
export function settingsView(config) {
  return {
    token:{...tokenDefaults,...config.token},
    workspaceRoot:config.workspaceRoot??'',
    cookieMaxAgeDays:config.cookieMaxAgeDays??7,
    http:{...httpDefaults,...Object.fromEntries(Object.keys(httpDefaults).map(key=>[key,config.http?.[key]??httpDefaults[key]])),headersConfigured:Object.keys(config.http?.headers??{}).length>0,userInfoHeadersConfigured:Object.keys(config.http?.userInfoHeaders??{}).length>0},
    header:{...headerDefaults,...Object.fromEntries(Object.keys(headerDefaults).map(key=>[key,config.header?.[key]??headerDefaults[key]])),sharedSecretConfigured:Boolean(config.header?.sharedSecret)},
  }
}
function endpoint(value, required) {
  if(!value&&!required)return ''
  let parsed;try{parsed=new URL(value)}catch{throw new Error('请填写完整的 HTTP/HTTPS 身份服务地址')}
  if(!['http:','https:'].includes(parsed.protocol)||parsed.username||parsed.password)throw new Error('身份服务地址只支持 HTTP/HTTPS，账号或密钥请填写在请求头中')
  return value
}
function headerName(value) {
  if(!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value))throw new Error('请求头名称格式不正确')
  return value.toLowerCase()
}
function secretHeaders(form,key,previous) {
  const value=form.get(key)?.trim()
  if(!value)return previous??{}
  let parsed;try{parsed=JSON.parse(value)}catch{throw new Error('附加请求头必须是 JSON 对象')}
  if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw new Error('附加请求头必须是 JSON 对象')
  for(const [name,item] of Object.entries(parsed)){headerName(name);if(typeof item!=='string'||/[\r\n]/.test(item))throw new Error('附加请求头的值必须是不含换行的字符串')}
  return parsed
}
export function parseSettings(form, config,origin) {
  const provider=form.get('provider')??config.provider
  if(!providers.includes(provider))throw new Error('未知认证模式')
  const age=Number(form.get('cookieMaxAgeDays')??config.cookieMaxAgeDays??7)
  if(!Number.isInteger(age)||age<1||age>365)throw new Error('登录有效期应为 1 到 365 天')
  const http={...httpDefaults,...config.http},header={...headerDefaults,...config.header}
  if(provider==='http'){
    for(const key of Object.keys(httpDefaults))if(form.has('http.'+key))http[key]=form.get('http.'+key).trim()
    http.loginUrl=endpoint(http.loginUrl,true);http.userInfoUrl=endpoint(http.userInfoUrl,false)
    if(!['json','form'].includes(http.requestFormat))throw new Error('请求格式应为 JSON 或 Form')
    http.timeoutMs=Number(http.timeoutMs)
    if(!Number.isInteger(http.timeoutMs)||http.timeoutMs<100||http.timeoutMs>60000)throw new Error('超时应为 100 到 60000 毫秒')
    http.tokenHeader=headerName(http.tokenHeader)
    if(/[\r\n]/.test(http.tokenPrefix))throw new Error('Token 前缀不能包含换行')
    // Preserve trailing space in prefixes such as "Bearer ".
    if(form.has('http.tokenPrefix'))http.tokenPrefix=form.get('http.tokenPrefix')
    if(/[\r\n]/.test(http.tokenPrefix))throw new Error('Token 前缀不能包含换行')
    http.headers=secretHeaders(form,'http.headers',http.headers)
    http.userInfoHeaders=secretHeaders(form,'http.userInfoHeaders',http.userInfoHeaders)
    http.method='POST'
  }
  if(provider==='header'){
    for(const key of Object.keys(headerDefaults))if(form.has('header.'+key))header[key]=headerName(form.get('header.'+key).trim())
    if(new Set(Object.keys(headerDefaults).map(key=>header[key])).size!==3)throw new Error('身份、显示名称和共享密钥请求头必须使用不同的名称')
    const secret=form.get('header.sharedSecret')
    if(secret)header.sharedSecret=secret
    if(!header.sharedSecret||header.sharedSecret.length<16||/[\r\n]/.test(header.sharedSecret))throw new Error('代理模式需要至少 16 位、不含换行的共享密钥')
    if(form.has('enabled')&&!form.has('proxyReady'))throw new Error('请先确认可信代理已完成认证并覆盖身份头和共享密钥头')
  }
  let token={...tokenDefaults,...config.token}
  if(provider==='token'){
    for(const key of Object.keys(tokenDefaults))if(form.has('token.'+key)){
      const input=form.get('token.'+key)
      if(['successValue','expiredValue'].includes(key)){try{token[key]=JSON.parse(input)}catch{throw new Error('Token 响应比较值必须为 JSON，例如 0、true 或 \"ok\"')}}
      else if(key==='adminRoles'){try{token[key]=JSON.parse(input)}catch{throw new Error('管理员角色必须为 JSON 字符串数组')}}
      else if(key==='successStatuses'){token[key]=input.split(',').map(value=>Number(value.trim()))}
      else if(['checkIntervalSeconds','timeoutMs'].includes(key))token[key]=Number(input)
      else token[key]=key==='tokenPrefix'?input:input.trim()
    }
    token=normalizeTokenConfig(token,true)
    if(!origin||token.siteOrigin!==origin)throw new Error('Token 模式必须与当前配置页面同源部署')
  }
  return {enabled:form.has('enabled'),provider,cookieMaxAgeDays:age,http,header,token,...(form.has('workspaceRoot')?workspaceSettings(form.get('workspaceRoot'),config):{})}
}
export function persistedSettings(config) {
  return {enabled:config.enabled,provider:config.provider,workspaceRoot:config.workspaceRoot,workspaceRootHistory:config.workspaceRootHistory,adminWorkspaceRoot:config.adminWorkspaceRoot,cookieMaxAgeDays:config.cookieMaxAgeDays,token:config.token,http:config.http,header:config.header}
}
export function mergeSavedSettings(raw,saved) {
  const input=raw??{},overrides={}
  if(typeof saved.enabled==='boolean')overrides.enabled=saved.enabled
  if(providers.includes(saved.provider))overrides.provider=saved.provider
  for(const key of ['workspaceRoot','adminWorkspaceRoot'])if(typeof saved[key]==='string')overrides[key]=saved[key]
  if(Array.isArray(saved.workspaceRootHistory))overrides.workspaceRootHistory=saved.workspaceRootHistory
  if(saved.cookieMaxAgeDays!==undefined)overrides.cookieMaxAgeDays=saved.cookieMaxAgeDays
  for(const key of ['http','header','token'])if(saved[key]&&typeof saved[key]==='object'&&!Array.isArray(saved[key]))overrides[key]={...input[key],...saved[key]}
  return {...input,...overrides}
}
