import crypto from 'node:crypto'
import { ADMIN_USER_ID } from './identity.js'
import { UserStore } from './users.js'
import { settingsView, parseSettings } from './provider-settings.js'

export function installManagement(ctx, { isAdmin, getConfig, update, reloadUsers, handoff }) {
  let busy = false
  const csrf = crypto.randomBytes(32).toString('hex')
  const storeOf = () => { const config=getConfig();return new UserStore({users:config.local.users,usersFile:config.usersFile}) }
  const model = message => {
    const config=getConfig()
    return {enabled:config.enabled,provider:config.provider,...settingsView(config),handoffAvailable:handoff?.available()??false,csrf,message,
      users:storeOf().list().map(user=>({id:user.id,name:user.name,configured:config.local.users.some(item=>item.id===user.id)}))}
  }
  const send=(res,status,body)=>{res.writeHead(status,{'cache-control':'no-store','content-type':'application/json; charset=utf-8'});res.end(JSON.stringify(body))}
  const handler=async(req,res)=>{
    if(!isAdmin(req)){send(res,403,{error:'需要管理员登录'});return}
    if(req.method==='GET'){send(res,200,model(''));return}
    if(req.method!=='POST'){res.writeHead(405,{allow:'GET, POST'});res.end();return}
    let originHost;try{originHost=new URL(req.headers.origin).host}catch{}
    if(originHost!==req.headers.host){send(res,403,{error:'来源校验失败，请刷新页面。'});return}
    let body='';for await(const chunk of req){body+=chunk;if(Buffer.byteLength(body)>16384){send(res,413,{error:'提交内容过长'});return}}
    const form=new URLSearchParams(body)
    if(form.get('csrf')!==csrf){send(res,403,{error:'页面已过期，请刷新后重试。'});return}
    if(busy){send(res,409,{error:'设置正在保存，请稍后重试。'});return}
    busy=true
    try{
      if((form.get('action')??'').startsWith('handoff-')){
        if(!handoff||!form.has('confirmHandoff'))throw new Error('请先确认停用影响')
        const action=form.get('action')
        if(action==='handoff-prepare'){
          const cookies=handoff.prepare(req)
          res.setHeader('set-cookie',cookies)
          send(res,200,{prepared:true});return
        }
        if(action==='handoff-verify'){
          handoff.verify(req);send(res,200,{ready:true});return
        }
        if(action==='handoff-disable'||action==='handoff-remove'){
          const outcome=await handoff.stop(req,action==='handoff-remove'?'remove':'disable')
          send(res,200,{completed:true,...outcome});return
        }
        throw new Error('未知交接操作')
      }
      const config=getConfig(),store=storeOf()
      let message
      if(form.get('action')==='create'){
        const password=form.get('password')??''
        if(password.length<12||password.length>1024)throw new Error('密码长度需要为 12 到 1024 个字符')
        if(password!==form.get('confirm'))throw new Error('两次输入的密码不一致')
        const id=(form.get('username')??'').trim()
        if(id==='admin'||id===ADMIN_USER_ID)throw new Error('admin 是管理员保留账号，不能创建为普通用户')
        if(id.length>256)throw new Error('用户名过长')
        if(store.has(id))throw new Error('用户名已存在')
        store.add({id,name:form.get('name')??id,password});reloadUsers()
        message='普通用户已创建。'
      }else if(form.get('action')==='reset'){
        const password=form.get('password')??''
        if(password!==form.get('confirm'))throw new Error('两次输入的新密码不一致')
        const id=form.get('username')??''
        store.resetPassword(id,password);reloadUsers(id)
        message='密码已重置，该用户需要重新登录。原有会话和工作目录已保留。'
      }else if(form.get('action')==='settings'){
        const next=parseSettings(form,config,new URL(req.headers.origin).origin)
        if(next.enabled&&next.provider==='local'&&store.needsSetup())throw new Error('请先创建至少一个普通用户，再开启认证')
        await update(next);message=next.enabled?'普通用户认证已开启，设置立即生效。':'普通用户认证已关闭，管理员入口保持可用。'
      }else throw new Error('未知操作')
      send(res,200,model(message))
    }catch(error){send(res,400,{error:error.message??'操作失败'})}finally{busy=false}
  }
  const dispose=ctx.webServer.register({kind:'exact',path:'/api/auth/admin',handler})
  ctx.webServer.register({kind:'exact',path:'/admin/users',handler:(req,res)=>{
    if(req.method!=='GET'){res.writeHead(405,{allow:'GET'});res.end();return}
    res.writeHead(303,{location:'../?panel=web-user-auth','cache-control':'no-store'});res.end()
  }})
  return dispose
}
