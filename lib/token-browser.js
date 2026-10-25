/** Shared browser bridge served from the Harness mount, without credentials in its source. */
function installTokenBridge(){
  const root=new URL('./',window.location.href),endpoint=new URL('api/auth/token',root),loginUrl=new URL('login',root)
  function read(config){
    if(window.location.origin!==config.siteOrigin)throw new Error('Token 认证仅支持同源部署')
    if(!['localStorage','sessionStorage'].includes(config.storage))throw new Error('Token 存储配置不正确')
    let value;try{value=window[config.storage].getItem(config.storageKey)}catch{throw new Error('无法读取浏览器存储，请检查隐私设置')}
    if(!value)return ''
    if(config.storageField){
      try{value=JSON.parse(value)}catch{throw new Error('Token 存储值不是有效的 JSON')}
      for(const key of config.storageField.split('.')){
        if(['__proto__','prototype','constructor'].includes(key)||!value||typeof value!=='object'||!Object.hasOwn(value,key))return ''
        value=value[key]
      }
    }
    return typeof value==='string'?value:''
  }
  async function exchange(token){
    const response=await fetch(endpoint.href,{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'content-type':'application/json'},body:JSON.stringify({token})})
    const data=await response.json()
    if(!response.ok)throw new Error(data.error||'Token 登录暂不可用')
    return data
  }
  function startLogin(config){
    const box=document.createElement('section'),title=document.createElement('h2'),message=document.createElement('p'),button=document.createElement('button'),admin=document.createElement('a')
    title.textContent='同源 Token 登录';button.textContent='重试 Token 登录';button.type='button'
    const adminUrl=new URL(loginUrl);adminUrl.searchParams.set('admin','1');admin.href=adminUrl.href;admin.textContent='本地管理员登录'
    box.append(title,message,button,admin);document.body.append(box)
    if(new URL(window.location.href).searchParams.get('admin')==='1'){message.textContent='请使用上方表单登录本地管理员，普通用户由同源业务系统认证。';button.hidden=true;return ()=>{}}
    let pending=false,previous
    async function attempt(force=false){
      if(pending)return
      try{
        const token=read(config)
        if(!force&&token===previous)return
        previous=token
        if(!token){message.textContent='未找到 Token，请先在同源业务系统登录，再点击重试。上方账号密码表单用于本地管理员。';return}
        pending=true;button.disabled=true;message.textContent='正在验证 Token…'
        await exchange(token);window.location.replace(root.href)
      }catch(error){message.textContent=error.message}
      finally{pending=false;button.disabled=false}
    }
    button.addEventListener('click',()=>attempt(true))
    const timer=setInterval(()=>attempt(),1000),changed=()=>attempt()
    window.addEventListener('storage',changed);attempt(true)
    return ()=>{clearInterval(timer);window.removeEventListener('storage',changed)}
  }
  function watch(config){
    let previous,pending=false,lastStatus=0,stopped=false
    async function tick(){
      if(pending||stopped)return
      pending=true
      try{
        const token=read(config)
        if(token!==previous){
          previous=token
          const data=await exchange(token)
          if(stopped)return
          if(data.administrator||data.changed){window.location.replace(root.href);return}
        }
        if(Date.now()-lastStatus>=5000){
          lastStatus=Date.now()
          const response=await fetch(new URL('api/auth/status',root).href,{credentials:'same-origin',cache:'no-store',redirect:'error'})
          if(!response.ok)throw new Error('登录状态不可用')
          const state=await response.json()
          if(stopped)return
          if(state.role==='anonymous')window.location.replace(loginUrl.href)
          else if(state.role!=='user'||state.provider!=='token')window.location.replace(root.href)
        }
      }catch{if(!stopped)window.location.replace(loginUrl.href)}
      finally{pending=false}
    }
    const timer=setInterval(tick,1000),changed=()=>tick()
    window.addEventListener('storage',changed);tick()
    return ()=>{stopped=true;clearInterval(timer);window.removeEventListener('storage',changed)}
  }
  window.__DshTokenAuth={startLogin,watch}
}
export const tokenBrowserScript=`(${installTokenBridge.toString()})();`
export function tokenLoginMarkup(config){
  const json=JSON.stringify(config).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029')
  return `<script src="./auth-token-client.js"></script><script>window.__DshTokenAuth.startLogin(${json});</script>`
}
