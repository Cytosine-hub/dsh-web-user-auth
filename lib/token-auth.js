import crypto from 'node:crypto'
import { ADMIN_USER_ID } from './identity.js'

export const tokenDefaults={siteOrigin:'',storage:'localStorage',storageKey:'access_token',storageField:'',userInfoUrl:'',tokenHeader:'authorization',tokenPrefix:'Bearer ',userField:'user',idField:'id',nameField:'name',successStatuses:[200],successField:'',successValue:0,expiredField:'',expiredValue:true,expiresAtField:'',expiresAtFormat:'seconds',checkIntervalSeconds:30,timeoutMs:10000}
const own=(value,key)=>value!==null&&typeof value==='object'&&Object.hasOwn(value,key)
export function tokenField(value,field){
  if(field==='')return value
  for(const part of field.split('.')){if(['__proto__','prototype','constructor'].includes(part)||!own(value,part))return undefined;value=value[part]}
  return value
}
export function normalizeTokenConfig(raw={},required=false){
  const value={...tokenDefaults,...raw}
  if(!required){
    return Object.fromEntries(Object.entries(tokenDefaults).map(([key,fallback])=>{
      const item=raw?.[key]
      const valid=['successValue','expiredValue'].includes(key)?item===null||['string','number','boolean'].includes(typeof item):Array.isArray(fallback)?Array.isArray(item):typeof item===typeof fallback
      return [key,valid?item:fallback]
    }))
  }
  if(!['localStorage','sessionStorage'].includes(value.storage))throw new Error('Token 存储位置必须为 localStorage 或 sessionStorage')
  if(typeof value.storageKey!=='string'||!value.storageKey.trim()||value.storageKey.length>256||/[\0\r\n]/.test(value.storageKey))throw new Error('请填写有效的 Token 存储键名')
  for(const field of ['storageField','userField','idField','nameField','successField','expiredField','expiresAtField']){
    if(typeof value[field]!=='string'||value[field].length>256||value[field].split('.').some(part=>['__proto__','prototype','constructor'].includes(part)))throw new Error('Token 字段映射不正确')
  }
  if(!value.idField)throw new Error('请配置用户 ID 字段')
  if(!Number.isInteger(value.checkIntervalSeconds)||value.checkIntervalSeconds<5||value.checkIntervalSeconds>300)throw new Error('Token 检查间隔应为 5 到 300 秒')
  if(!Number.isInteger(value.timeoutMs)||value.timeoutMs<100||value.timeoutMs>60000)throw new Error('Token 接口超时应为 100 到 60000 毫秒')
  if(!['seconds','milliseconds','iso'].includes(value.expiresAtFormat))throw new Error('Token 过期时间格式不正确')
  if(!Array.isArray(value.successStatuses)||!value.successStatuses.length||value.successStatuses.some(status=>!Number.isInteger(status)||status<200||status>299))throw new Error('Token 成功状态码必须为 2xx 状态码列表')
  for(const key of ['successValue','expiredValue'])if(value[key]!==null&&!['string','number','boolean'].includes(typeof value[key]))throw new Error('Token 响应比较值必须是 JSON 基本类型')
  if(typeof value.tokenHeader!=='string'||!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value.tokenHeader))throw new Error('Token 请求头名称不正确')
  value.tokenHeader=value.tokenHeader.toLowerCase()
  if(/^(host|cookie|origin|referer|connection|content-length|transfer-encoding|te|trailer|upgrade|forwarded|proxy-.*|sec-.*|x-forwarded-.*)$/.test(value.tokenHeader))throw new Error('Token 不能放入请求控制头或 Cookie')
  if(typeof value.tokenPrefix!=='string'||value.tokenPrefix.length>256||/[\r\n\0]/.test(value.tokenPrefix))throw new Error('Token 前缀不正确')
  if(required||value.siteOrigin||value.userInfoUrl){
    let origin,url
    try{origin=new URL(value.siteOrigin);url=new URL(value.userInfoUrl,origin)}catch{throw new Error('Token 模式需要同源站点地址和用户信息接口')}
    if(!['http:','https:'].includes(origin.protocol)||origin.username||origin.password||origin.pathname!=='/'||origin.search||origin.hash)throw new Error('同源站点只能填写协议、域名和端口')
    if(!value.userInfoUrl||url.origin!==origin.origin||url.username||url.password||url.hash)throw new Error('Token 用户信息接口必须与部署站点同源')
    value.siteOrigin=origin.origin;value.userInfoUrl=url.href
  }
  return value
}
export class TokenAuthError extends Error{constructor(message,status=401){super(message);this.status=status}}
export function tokenIdentity(body,config,now=Date.now()){
  if(config.successField&&tokenField(body,config.successField)!==config.successValue)throw new TokenAuthError('Token 校验未通过，请在业务系统重新登录')
  if(config.expiredField){const value=tokenField(body,config.expiredField);if(value===undefined||value===config.expiredValue)throw new TokenAuthError('Token 已过期或过期字段不可用')}
  let expiresAt=Infinity
  if(config.expiresAtField){
    const raw=tokenField(body,config.expiresAtField)
    expiresAt=config.expiresAtFormat==='iso'?(typeof raw==='string'?Date.parse(raw):NaN):((typeof raw==='number'||typeof raw==='string'&&raw.trim()!=='')?Number(raw):NaN)*(config.expiresAtFormat==='seconds'?1000:1)
    if(!Number.isFinite(expiresAt)||expiresAt<=now)throw new TokenAuthError('Token 已过期或过期时间无效')
  }
  const user=tokenField(body,config.userField),rawId=tokenField(user,config.idField)
  const id=typeof rawId==='string'?rawId:(Number.isSafeInteger(rawId)?String(rawId):'')
  if(!id.trim()||id.length>256||id===ADMIN_USER_ID||/[/\\\0]/.test(id))throw new TokenAuthError('用户信息接口未返回有效的普通用户 ID')
  const rawName=tokenField(user,config.nameField),name=typeof rawName==='string'&&rawName.trim()?rawName.slice(0,256):id
  return {identity:{id,name,provider:'token'},expiresAt}
}
async function readJson(response){
  let bytes=0;const chunks=[]
  for await(const chunk of response.body){bytes+=chunk.length;if(bytes>65536)throw new TokenAuthError('用户信息响应过大',503);chunks.push(chunk)}
  try{return JSON.parse(Buffer.concat(chunks).toString('utf8'))}catch(error){if(error instanceof TokenAuthError)throw error;throw new TokenAuthError('用户信息接口必须返回 JSON',503)}
}
export class TokenSessions{
  constructor(config,{onRevoke=()=>{},fetchImpl=fetch,now=Date.now,setTimer=setTimeout,clearTimer=clearTimeout}={}){Object.assign(this,{config,onRevoke,fetchImpl,now,setTimer,clearTimer});this.sessions=new Map();this.disposed=false}
  async validate(token){
    let response
    try{response=await this.fetchImpl(this.config.userInfoUrl,{method:'GET',headers:{accept:'application/json',[this.config.tokenHeader]:this.config.tokenPrefix+token},redirect:'error',signal:AbortSignal.timeout(this.config.timeoutMs)})}catch{throw new TokenAuthError('用户信息接口暂不可用，未授予访问权限',503)}
    if(!this.config.successStatuses.includes(response.status)){await response.body?.cancel();throw new TokenAuthError('Token 无效、已过期或接口拒绝访问',response.status>=500?503:401)}
    return tokenIdentity(await readJson(response),this.config,this.now())
  }
  get(sid){const record=this.sessions.get(sid);if(record&&record.validUntil<=this.now()){this.revoke(sid);return undefined}if(record)record.lastSeen=this.now();return record}
  schedule(record){
    record.timer=this.setTimer(async()=>{
      try{
        if(this.now()-record.lastSeen>900000){this.revoke(record.sid);return}
        const checked=await this.validate(record.token)
        if(this.disposed||this.sessions.get(record.sid)!==record)return
        if(checked.identity.id!==record.identity.id)throw new TokenAuthError('Token 身份已变化')
        record.identity=checked.identity;record.expiresAt=checked.expiresAt;record.validUntil=Math.min(checked.expiresAt,this.now()+this.config.checkIntervalSeconds*1000+this.config.timeoutMs)
        this.schedule(record)
      }catch{this.revoke(record.sid)}
    },Math.max(1,Math.min(this.config.checkIntervalSeconds*1000,record.validUntil-this.now())))
    record.timer?.unref?.()
  }
  async exchange(raw,previousSid){
    const previous=this.get(previousSid)
    if(typeof raw!=='string'||!raw.trim()||raw.length>16384||/[\r\n\0]/.test(raw)){this.revoke(previousSid);throw new TokenAuthError('未找到有效 Token，请先在同源业务系统登录')}
    const token=raw.trim()
    if(previous&&previous.token===token)return {record:previous,changed:false}
    let checked
    try{checked=await this.validate(token)}catch(error){this.revoke(previousSid);throw error}
    if(this.disposed)throw new TokenAuthError('认证配置已变化，请重新登录')
    this.revoke(previousSid)
    if(this.sessions.size>=1000)throw new TokenAuthError('Token 会话数量已达上限，请稍后再试',503)
    const record={lastSeen:this.now(),sid:crypto.randomBytes(32).toString('base64url'),token,identity:checked.identity,expiresAt:checked.expiresAt,validUntil:Math.min(checked.expiresAt,this.now()+this.config.checkIntervalSeconds*1000+this.config.timeoutMs)}
    this.sessions.set(record.sid,record);this.schedule(record)
    return {record,changed:true}
  }
  revoke(sid){const record=this.sessions.get(sid);if(!record)return;this.sessions.delete(sid);this.clearTimer(record.timer);record.token='';this.onRevoke(record.identity.id)}
  dispose(){this.disposed=true;for(const record of this.sessions.values()){this.clearTimer(record.timer);record.token=''}this.sessions.clear()}
}
