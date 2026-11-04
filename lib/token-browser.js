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
  async function exchange(token, signal){
    const response=await fetch(endpoint.href,{method:'POST',signal,credentials:'same-origin',cache:'no-store',redirect:'error',headers:{'content-type':'application/json'},body:JSON.stringify({token})})
    const data=await response.json()
    if(!response.ok)throw new Error(data.error||'Token 登录暂不可用')
    return data
  }
  function startLogin(config, automatic = true) {
    const loading = document.getElementById('dsh-token-loading')
    const form = document.getElementById('dsh-login-form')
    const adminOnly = new URL(window.location.href).searchParams.get('admin') === '1'
    function showLoading(active) {
      loading.hidden = !active
      form.hidden = active
      document.title = (active ? '正在登录' : '登录') + ' · DeepSeek Harness'
    }
    if (adminOnly) {
      showLoading(false)
      return () => {}
    }

    const box = document.createElement('section')
    const title = document.createElement('h2')
    const message = document.createElement('p')
    const retry = document.createElement('button')
    title.textContent = '同源 Token 登录'
    message.setAttribute('role', 'alert')
    retry.textContent = '重试 Token 登录'
    retry.type = 'button'
    const admin = document.createElement('a')
    const adminUrl = new URL(loginUrl)
    adminUrl.searchParams.set('admin', '1')
    admin.href = adminUrl.href
    admin.textContent = '本地管理员登录'
    box.append(title, message, retry, admin)
    form.append(box)

    let pending = false
    let previous
    let stopped = false
    let request
    async function attempt(force = false) {
      if (pending || stopped) return
      let timeout
      try {
        const token = read(config)
        if (!force && token === previous) return
        previous = token
        if (!token) throw new Error('未找到 Token，请先在同源业务系统登录，再点击重试。')
        pending = true
        showLoading(true)
        request = new AbortController()
        // Leave room for proxy transit and session creation after the API call.
        timeout = setTimeout(() => request.abort(), (config.timeoutMs ?? 10000) + 5000)
        await exchange(token, request.signal)
        if (!stopped) window.location.replace(root.href)
      } catch (error) {
        pending = false
        if (stopped) return
        message.textContent = request?.signal.aborted
          ? '验证身份超时，请重试 Token 登录。'
          : error.message
        showLoading(false)
      } finally {
        clearTimeout(timeout)
        request = undefined
      }
    }
    retry.addEventListener('click', () => attempt(true))
    const changed = () => attempt()
    let timer
    if (automatic) {
      timer = setInterval(changed, 1000)
      window.addEventListener('storage', changed)
      attempt(true)
    }
    return () => {
      stopped = true
      request?.abort()
      clearInterval(timer)
      window.removeEventListener('storage', changed)
    }
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
          else if(state.role!==config.role||state.provider!=='token')window.location.replace(root.href)
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
export function tokenLoginMarkup(config, automatic = true){
  const json=JSON.stringify(config).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029')
  return `<script>${tokenBrowserScript}window.__DshTokenAuth.startLogin(${json},${automatic});</script>`
}
