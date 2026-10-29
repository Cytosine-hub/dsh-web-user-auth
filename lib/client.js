window.__ModuleLoader__.load({
  id: '@local/dsh-web-user-auth',
  factory: require => {
    const React = require('react')
    const h = React.createElement
    const PANEL = 'web-user-auth'
    const ROOT = new URL('./', window.location.href)
    const url = suffix => new URL(suffix, ROOT).href
    async function request(suffix, form) {
      const response = await fetch(url(suffix), { credentials: 'same-origin', cache: 'no-store', ...(form ? {method:'POST',body:form} : {}) })
      if(response.status===204)return null
      const data=await response.json()
      if(!response.ok)throw new Error(data.error||'请求失败，请刷新后重试')
      return data
    }
    async function logout(){
      try { await request('api/auth/logout',new URLSearchParams());window.location.replace(url('login')) }
      catch(error){window.alert(error.message)}
    }
    const style = `.dsh-auth-panel{height:100%;overflow:auto;box-sizing:border-box;padding:32px;color:var(--dsw-alias-label-primary,#e8edf5);font:14px/1.7 system-ui}.dsh-auth-content{max-width:920px;margin:0 auto}.dsh-auth-panel h1{font-size:26px;margin:0}.dsh-auth-panel h2{font-size:18px;margin:0 0 12px}.dsh-auth-panel p{color:var(--dsw-alias-label-secondary,#a5afbd)}.dsh-auth-card{padding:24px;margin:20px 0;border:1px solid var(--dsw-alias-border-l2,#333a46);background:var(--dsw-alias-settings-card-fill,#191d24);border-radius:14px}.dsh-auth-panel input:not([type=checkbox]),.dsh-auth-panel select,.dsh-auth-panel textarea{display:block;width:100%;box-sizing:border-box;border:1px solid var(--dsw-alias-border-l3,#454c59);background:var(--dsw-alias-bg-base,#12161d);color:inherit;border-radius:8px;padding:10px 12px;margin:6px 0 14px;font:inherit}.dsh-auth-panel button{padding:9px 16px;border:1px solid var(--dsw-alias-border-l3,#4c5564);border-radius:8px;background:var(--dsw-alias-button-primary-fill,#cadbff);color:var(--dsw-alias-label-primary-foreground,#14213a);font:inherit;cursor:pointer}.dsh-auth-panel button:disabled{opacity:.5;cursor:default}.dsh-auth-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px}.dsh-auth-grid .dsh-auth-card{margin:0}.dsh-auth-status{padding:10px 14px;margin:16px 0;border-radius:8px;background:var(--dsw-alias-interactive-bg-hover,#293347)}.dsh-auth-panel table{width:100%;border-collapse:collapse;text-align:left}.dsh-auth-panel th,.dsh-auth-panel td{padding:10px;border-bottom:1px solid var(--dsw-alias-border-l2,#333a46)}.dsh-auth-help{font-size:12px}.dsh-auth-panel label{display:block}.dsh-auth-panel input[type=checkbox]{margin-right:8px}`
    function Field({label,name,type='text',required=true}){
      return h('label',null,label,h('input',{name,type,required,...(type==='password'?{minLength:12,maxLength:1024,autoComplete:'new-password'}:{maxLength:256,autoComplete:'off'})}))
    }
    function ProviderFields({provider,data}){
      const input=(prefix,key,label,opts={})=>h('label',{key:prefix+key},label,h('input',{name:prefix+'.'+key,defaultValue:data[prefix]?.[key]??'',...opts}))
      if(provider==='local')return h('p',{className:'dsh-auth-help'},'使用下方创建的本地账号登录，无需更改反向代理。')
      if(provider==='http')return h('div',null,
        h('p',null,'由插件调用已有账号密码登录 API。通常无需更改 Caddy；此模式不支持直接填写 OIDC/SAML 授权地址。'),
        input('http','loginUrl','登录 API 地址',{type:'url',required:true,placeholder:'https://auth.example.com/api/login'}),
        input('http','userInfoUrl','用户资料 API 地址（可选）',{type:'url',placeholder:'https://auth.example.com/api/me'}),
        h('label',null,'请求格式',h('select',{name:'http.requestFormat',defaultValue:data.http.requestFormat},h('option',{value:'json'},'JSON'),h('option',{value:'form'},'Form 表单'))),
        h('details',null,h('summary',null,'高级字段映射与请求头'),
          ...[['tokenField','Token 字段'],['userField','用户对象字段（留空使用整个响应）'],['idField','用户 ID 字段'],['nameField','显示名称字段'],['tokenHeader','Token 请求头'],['tokenPrefix','Token 前缀（例如 Bearer 后保留空格）'],['timeoutMs','请求超时（毫秒）']].map(([key,label])=>input('http',key,label,key==='timeoutMs'?{type:'number',min:100,max:60000}:{})),
          ...[['headers','登录请求附加头'],['userInfoHeaders','用户资料请求附加头']].map(([key,label])=>h('label',{key},label+'（JSON，留空保留，填 {} 清空）',h('textarea',{name:'http.'+key,rows:3,autoComplete:'off',placeholder:data.http[key+'Configured']?'已配置，内容不回显':'例如 {"X-API-Key":"…"}'}))))
      )
      if(provider==='token'){
        const config=data.token
        const field=(key,label,opts={})=>h('label',{key},label,h('input',{name:'token.'+key,defaultValue:['successValue','expiredValue','adminRoles'].includes(key)?JSON.stringify(config[key]):key==='siteOrigin'?(config.siteOrigin||window.location.origin):key==='successStatuses'?config[key].join(','):config[key],...opts}))
        return h('div',null,h('p',null,'仅支持与业务系统相同的协议、域名和端口。浏览器读取 Token，服务端调用同源用户信息接口确认身份；不信任前端传入的用户信息。'),
          field('siteOrigin','同源站点地址（仅协议、域名、端口）',{required:true,type:'url'}),
          h('label',null,'Token 存储位置',h('select',{name:'token.storage',defaultValue:config.storage},h('option',{value:'localStorage'},'localStorage'),h('option',{value:'sessionStorage'},'sessionStorage'))),
          field('storageKey','Token 存储键名',{required:true}),field('storageField','存储值内的 Token 字段（可选，点路径；留空直接使用字符串）'),
          field('userInfoUrl','用户信息接口（同源地址或 / 开头的路径）',{required:true,placeholder:'/api/user/me'}),
          field('tokenHeader','Token 请求头名称',{required:true}),field('tokenPrefix','Token 前缀（例如 Bearer 后保留空格）'),
          h('details',null,h('summary',null,'用户信息字段映射'),field('userField','用户对象字段（留空使用整个响应）'),field('idField','用户 ID 字段',{required:true}),field('nameField','显示名称字段'),field('roleField','角色字段（相对于用户对象，字符串或字符串数组）'),field('adminRoles','管理员角色（JSON 字符串数组，例如 ["admin","superadmin"]）'),h('p',null,'精确匹配任一配置角色即授予管理权限；留空不启用角色提权。管理员仍仅能访问自己的会话和工作区。')),
          h('details',null,h('summary',null,'Token 检查与过期规则'),
            field('successStatuses','允许的 HTTP 状态码（逗号分隔，只允许 2xx）',{required:true}),
            field('successField','成功字段（可选，响应根节点的点路径）'),field('successValue','成功字段期望值（JSON，例如 0、true 或 "ok"）'),
            field('expiredField','过期标志字段（可选，点路径）'),field('expiredValue','表示已过期的值（JSON，例如 true 或 1）'),
            field('expiresAtField','过期时间字段（可选，点路径）'),
            h('label',null,'过期时间格式',h('select',{name:'token.expiresAtFormat',defaultValue:config.expiresAtFormat},h('option',{value:'seconds'},'Unix 秒'),h('option',{value:'milliseconds'},'Unix 毫秒'),h('option',{value:'iso'},'ISO 时间字符串'))),
            field('checkIntervalSeconds','登录后检查间隔（秒）',{type:'number',min:5,max:300,required:true}),field('timeoutMs','接口超时（毫秒）',{type:'number',min:100,max:60000,required:true})),
          h('p',{className:'dsh-auth-help'},'HTTP 401/403、规则不匹配、身份无效、过期、重定向或接口故障均不会授予访问。定时复查失败会撤销会话。Token 只存放在浏览器原存储和服务端内存，不写入配置、Cookie 或日志。管理员仍通过 login?admin=1 使用本地账号。'))
      }
      return h('div',null,h('p',null,'由可信反向代理先完成登录，再向 Harness 注入身份。保存本表单不会自动修改 Caddy。代理必须覆盖外部传入的下列请求头，并限制 Harness 上游只接受可信代理连接。'),
        ...[['userHeader','用户 ID 请求头'],['nameHeader','显示名称请求头'],['secretHeader','共享密钥请求头']].map(([key,label])=>input('header',key,label,{required:true})),
        h('label',null,'代理共享密钥（至少 16 位，留空保留）',h('input',{name:'header.sharedSecret',type:'password',minLength:16,autoComplete:'new-password',placeholder:data.header.sharedSecretConfigured?'已配置，内容不回显':'请输入与可信代理相同的共享密钥'})),
        h('label',null,h('input',{name:'proxyReady',type:'checkbox'}),'我已配置可信代理认证、覆盖身份和密钥请求头，并保留 /login 管理员入口'),
        h('p',{className:'dsh-auth-help'},'用户身份和退出流程由外部认证系统负责；本地退出只能清除 Harness Cookie，代理仍可能自动登录。管理员始终使用 /login 的本地 admin 账号。'))
    }
    function SafeDisable({initial}){
      const [model,setModel]=React.useState(initial??null),[accepted,setAccepted]=React.useState(false),[ready,setReady]=React.useState(false),[busy,setBusy]=React.useState(false),[error,setError]=React.useState('')
      React.useEffect(()=>{if(!initial)request('api/auth/admin').then(setModel).catch(e=>setError(e.message))},[])
      async function act(action){
        setBusy(true);setError('')
        try{
          const fields=new URLSearchParams({action,csrf:model.csrf,confirmHandoff:'yes'})
          const result=await request('api/auth/admin',fields)
          if(action==='handoff-prepare'){
            fields.set('action','handoff-verify');await request('api/auth/admin',fields);setReady(true)
          }else{
            if(result.restartRequired)window.alert('设置已保存，需要重启 Harness 才会完成操作。当前浏览器的原生登录已准备。')
            window.location.replace(ROOT.href)
          }
        }catch(e){setError(e.message);setReady(false)}finally{setBusy(false)}
      }
      return h('section',{className:'dsh-auth-card dsh-auth-safety',style:{padding:20,border:'1px solid #555',borderRadius:12,margin:'20px 0'}},
        h('style',null,'.dsh-auth-safety{font:14px/1.7 system-ui}.dsh-auth-safety h2{font-size:18px}.dsh-auth-safety button{padding:9px 14px;background:var(--dsw-alias-button-primary-fill,#cadbff);color:var(--dsw-alias-label-primary-foreground,#14213a);border:1px solid #555;border-radius:8px;cursor:pointer;font:inherit}.dsh-auth-safety button:disabled{opacity:.5;cursor:default}.dsh-auth-safety input[type=checkbox]{margin-right:8px}'),
        h('h2',null,'安全停用 / 卸载认证插件'),
        h('p',null,'停用整个插件会停止本地账号登录、用户隔离和认证管理。Harness 原生管理员可访问整个实例。仅想停止普通用户登录，请使用“用户与认证”里的开关。'),
        h('p',null,'先准备并验证当前浏览器的原生登录，再停用或卸载。验证失败不会执行停用；不会开放匿名访问。'),
        error&&h('p',{role:'alert'},error),
        model&&!model.handoffAvailable&&h('p',{role:'alert'},'当前 Harness 版本不支持安全交接，请保留插件并通过服务器管理。'),
        h('label',null,h('input',{type:'checkbox',checked:accepted,disabled:busy,onChange:e=>{setAccepted(e.target.checked);setReady(false)}}),'我确认停止本插件的账号登录及用户隔离，并切换为 Harness 原生管理员访问'),
        h('p',null,ready?'已验证：当前浏览器可使用原生登录。凭据有效期由 Harness 管理，其他浏览器仍需原生启动登录链接。':'当前尚未验证原生登录。'),
        !ready?h('button',{type:'button',disabled:busy||!accepted||!model?.handoffAvailable,onClick:()=>act('handoff-prepare')},busy?'正在验证…':'准备并验证原生登录'):
        h('div',{style:{display:'flex',gap:10,flexWrap:'wrap'}},h('button',{type:'button',disabled:busy||!accepted,onClick:()=>act('handoff-disable')},'停用并继续访问'),h('button',{type:'button',disabled:busy||!accepted,onClick:()=>act('handoff-remove')},'卸载并继续访问')))
    }
    function Management(){
      const [data,setData]=React.useState(null),[error,setError]=React.useState(''),[busy,setBusy]=React.useState(false),[enabled,setEnabled]=React.useState(false),[provider,setProvider]=React.useState('local')
      const refresh=React.useCallback(async()=>{try{const next=await request('api/auth/admin');setData(next);setEnabled(next.enabled);setProvider(next.provider);setError('')}catch(e){setError(e.message)}},[])
      React.useEffect(()=>{refresh()},[refresh])
      async function submit(event){
        event.preventDefault();const form=event.currentTarget;setBusy(true);setError('')
        try{
          const fields=new URLSearchParams(new FormData(form));fields.set('csrf',data.csrf)
          const next=await request('api/auth/admin',fields);setData(next);setEnabled(next.enabled);setProvider(next.provider)
          for(const name of ['header.sharedSecret','http.headers','http.userInfoHeaders']){const field=form.elements.namedItem(name);if(field)field.value=''}
          if(fields.get('action')!=='settings')form.reset()
        }catch(e){setError(e.message)}finally{setBusy(false)}
      }
      const action=value=>h('input',{type:'hidden',name:'action',value})
      const notice=error||data?.message
      return h('div',{className:'dsh-auth-panel'},h('style',null,style),h('div',{className:'dsh-auth-content'},
        h('h1',null,'用户与认证'),h('p',null,'管理访问本机 Web UI 的账号。DeepSeek 平台登录仍用于模型服务，两者独立。'),
        notice&&h('div',{className:'dsh-auth-status',role:error?'alert':'status'},notice),
        !data?h('button',{onClick:refresh},error?'重试':'正在加载…'):h(React.Fragment,null,
          h('section',{className:'dsh-auth-card'},h('h2',null,'普通用户认证'),
            h('p',null,`当前状态：${data.enabled?'已开启':'未开启'} · 认证方式：${data.provider}`),
            h('form',{onSubmit:submit},action('settings'),
              h('label',null,h('input',{type:'checkbox',name:'enabled',checked:enabled,onChange:e=>setEnabled(e.target.checked),disabled:busy}),'允许普通用户登录'),
              h('p',{className:'dsh-auth-help'},'关闭后仅管理员可登录，不提供匿名访问。设置保存后立即生效，并在重启后保留。'),
              h('label',null,'认证方式',h('select',{name:'provider',value:provider,onChange:e=>setProvider(e.target.value),disabled:busy},h('option',{value:'local'},'本地账号（Local）'),h('option',{value:'http'},'已有登录 API（HTTP）'),h('option',{value:'header'},'可信代理身份（Header）'),h('option',{value:'token'},'同源存储 Token'))),
              h('label',null,'本地会话最长有效期（天）',h('input',{name:'cookieMaxAgeDays',type:'number',min:1,max:365,required:true,defaultValue:data.cookieMaxAgeDays})),
              h('label',null,'普通用户工作目录根目录',h('input',{name:'workspaceRoot',defaultValue:data.workspaceRoot,placeholder:'/srv/harness-users'})),
              h('p',{className:'dsh-auth-help'},'填写服务器绝对路径，留空使用默认目录。每个用户在其下拥有独立子目录。切换后旧文件不搬迁，历史工作区和会话继续隔离可用；管理员工作目录不变。'),
              h(ProviderFields,{key:provider,provider,data}),
              h('p',{className:'dsh-auth-help'},'切换认证方式后，普通用户需要按新方式重新登录。管理员本地登录不受影响。'),
              h('button',{disabled:busy},'保存认证设置'))),
          data.provider==='local'&&h('div',{className:'dsh-auth-grid'},
            h('section',{className:'dsh-auth-card'},h('h2',null,'创建普通用户'),h('form',{onSubmit:submit},action('create'),h(Field,{label:'用户名',name:'username'}),h(Field,{label:'显示名称',name:'name',required:false}),h(Field,{label:'密码（至少 12 位）',name:'password',type:'password'}),h(Field,{label:'确认密码',name:'confirm',type:'password'}),h('button',{disabled:busy},'创建普通用户'))),
            h('section',{className:'dsh-auth-card'},h('h2',null,'重置普通用户密码'),h('p',{className:'dsh-auth-help'},'旧密码和该用户已有登录凭据将失效，会话与工作目录保留。'),h('form',{onSubmit:submit},action('reset'),h('label',null,'选择普通用户',h('select',{name:'username',required:true,defaultValue:''},h('option',{value:'',disabled:true},'请选择用户'),...data.users.filter(user=>!user.configured).map(user=>h('option',{key:user.id,value:user.id},`${user.name} (${user.id})`)))),h(Field,{label:'新密码',name:'password',type:'password'}),h(Field,{label:'确认新密码',name:'confirm',type:'password'}),h('button',{disabled:busy||!data.users.length},'重置密码')))),
          data.provider==='local'&&h('section',{className:'dsh-auth-card'},h('h2',null,'普通用户列表'),h('table',null,h('thead',null,h('tr',null,h('th',null,'用户名'),h('th',null,'显示名称'),h('th',null,'角色'))),h('tbody',null,data.users.length?data.users.map(user=>h('tr',{key:user.id},h('td',null,user.id),h('td',null,user.name),h('td',null,'普通用户'))):h('tr',null,h('td',{colSpan:3},'尚未创建普通用户'))))),
          h(SafeDisable,{initial:data}),
          h('p',{className:'dsh-auth-help'},data.provider==='local'?'本地账号密码仅保存哈希。普通用户看不到此管理面板。':'当前使用外部认证。本地账号仍保留，切回 Local 后可继续使用；外部用户的创建和密码重置请在原认证系统操作。')
        )
      ))
    }
    function PasswordChange({administrator=false}){
      const endpoint=administrator?'api/auth/admin-password':'api/auth/password'
      const [csrf,setCsrf]=React.useState(''),[error,setError]=React.useState(''),[busy,setBusy]=React.useState(false)
      React.useEffect(()=>{request(endpoint).then(data=>setCsrf(data.csrf)).catch(e=>setError(e.message))},[])
      async function submit(event){
        event.preventDefault();setBusy(true);setError('')
        try{const fields=new URLSearchParams(new FormData(event.currentTarget));fields.set('csrf',csrf);await request(endpoint,fields);window.location.replace(url('login?passwordChanged=1'))}
        catch(e){setError(e.message);setBusy(false)}
      }
      return h('div',{className:'dsh-auth-panel'},h('style',null,style),h('div',{className:'dsh-auth-content'},h('h1',null,administrator?'修改管理员密码':'修改密码'),
        h('p',null,'请输入当前密码。修改后所有设备的旧登录凭据会失效，请使用新密码重新登录。'),error&&h('p',{role:'alert'},error),
        h('form',{onSubmit:submit,className:'dsh-auth-card'},h('label',null,'当前密码',h('input',{name:'currentPassword',type:'password',autoComplete:'current-password',required:true,maxLength:1024})),
          h(Field,{label:'新密码（至少 12 位）',name:'newPassword',type:'password'}),h(Field,{label:'确认新密码',name:'confirmPassword',type:'password'}),h('button',{disabled:busy||!csrf},busy?'正在保存…':'修改密码'))))
    }
    function AccountFooter({status,wide,openPassword}){
      return h('div',{style:{display:'flex',flexDirection:'column',gap:6,padding:wide?'8px 4px':'6px 0',width:'100%',minWidth:0}},
        h('div',{title:`${status.name} · ${status.role==='admin'?'管理员':'普通用户'}`,style:{fontSize:12,opacity:.8,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}},wide?`${status.name} · ${status.role==='admin'?'管理员':'普通用户'}`:status.role==='admin'?'管':'用户'),
        !['header','token'].includes(status.provider)&&h('div',{style:{display:'flex',gap:8,flexWrap:'wrap'}},
          status.canChangePassword&&h('button',{type:'button',onClick:openPassword,style:buttonStyle},wide?'修改密码':'密码'),
          h('button',{type:'button',onClick:logout,title:'退出 Web UI 登录',style:buttonStyle},wide?'退出登录':'退出')))
    }
    const buttonStyle={background:'transparent',color:'inherit',border:'1px solid var(--dsw-alias-border-l3,#444)',borderRadius:7,padding:'5px 9px',cursor:'pointer',fontSize:12}
    function PanelIcon(){return h('svg',{width:18,height:18,viewBox:'0 0 24 24',fill:'none',stroke:'currentColor',strokeWidth:1.7,'aria-hidden':true},h('path',{d:'M12 3 20 6v6c0 5-8 9-8 9s-8-4-8-9V6Z'}),h('circle',{cx:12,cy:10,r:2}),h('path',{d:'M8 16c0-4 8-4 8 0'}))}
    async function apply(ctx){
      const status=await request('api/auth/status')
      if(status.role==='anonymous')return
      ctx.effect(()=>ctx.locale.register('web-user-auth',{zh:{panel:'用户与认证',download:'下载',downloadTitle:'下载到本机'},en:{panel:'Users & Authentication',download:'Download',downloadTitle:'Download to this device'}}))
      if(status.provider==='token'&&status.tokenClient){
        ctx.effect(()=>{
          let disposed=false,stop
          const start=()=>{if(!disposed)stop=window.__DshTokenAuth.watch(status.tokenClient)}
          let script
          if(window.__DshTokenAuth)start()
          else{script=document.createElement('script');script.src=url('auth-token-client.js');script.onload=start;script.onerror=()=>{if(!disposed)window.location.replace(url('login'))};document.head.append(script)}
          return ()=>{disposed=true;stop?.();script?.remove()}
        })
      }
      const t = ctx.locale.bind('web-user-auth')
      function Download({ actionUrl }) {
        if (typeof actionUrl !== 'string') return null
        const coordinates = new URL(actionUrl, ROOT).searchParams
        const href = new URL(url('api/auth/download'))
        for (const key of ['sessionId', 'seq', 'index']) {
          const value = coordinates.get(key)
          if (value === null) return null
          href.searchParams.set(key, value)
        }
        return h('a', { href: href.href, download: '', title: t('downloadTitle'),
          style: { ...buttonStyle, textDecoration: 'none', display: 'inline-flex', alignItems: 'center' },
        }, t('download'))
      }
      ctx.slots.inject('deliverables.file.actions', () => ctx.slots.register({
        name: 'deliverables.file.actions', id: 'web-user-auth-download', order: 0,
        locale: 'web-user-auth',
      }, Download))
      const layout=ctx.layout
      const openManagement=()=>layout.selectPanel(PANEL)
      const openPassword=()=>layout.selectPanel(status.role==='admin'?'web-admin-password':'web-user-password')
      if(status.role==='user'&&status.provider==='local'&&status.canChangePassword){
        ctx.slots.inject('main',()=>ctx.slots.register({name:'main',key:'web-user-password',locale:'web-user-auth'},PasswordChange))
      }
      if(status.role==='admin'){
        if(status.canChangePassword)ctx.slots.inject('main',()=>ctx.slots.register({name:'main',key:'web-admin-password',locale:'web-user-auth',inject:()=>({administrator:true})},PasswordChange))
        ctx.slots.inject('plugins.bundle.config',()=>ctx.slots.register({name:'plugins.bundle.config',key:'@local/dsh-web-user-auth',locale:'web-user-auth'},SafeDisable))
        ctx.slots.inject('main',()=>ctx.slots.register({name:'main',key:PANEL,locale:'web-user-auth'},Management))
        ctx.slots.inject('sidebar.panellist',()=>ctx.slots.register({name:'sidebar.panellist',id:PANEL,order:20,label:()=> '用户与认证',locale:'web-user-auth'},PanelIcon))
      }
      ctx.slots.inject('sidebar.footer.action',()=>ctx.slots.register({name:'sidebar.footer.action',id:'web-user-auth-account',order:30,locale:'web-user-auth',inject:()=>({status,openPassword})},AccountFooter))
      if(status.role==='admin'&&new URLSearchParams(window.location.search).get('panel')===PANEL){
        let attempts=0;const navigate=()=>{try{openManagement()}catch{if(attempts++<20)setTimeout(navigate,100)}};setTimeout(navigate,0)
      }
    }
    return {apply,inject:['slots','locale','layout']}
  }
})
