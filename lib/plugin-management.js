export const AUTH_PACKAGE = '@local/dsh-web-user-auth'
const coreBundles = new Set([AUTH_PACKAGE,'@deepseek-ai/dsh-base','@deepseek-ai/dsh-web-app'])
const protectedRow = row => row?.moduleName === AUTH_PACKAGE || row?.name === AUTH_PACKAGE || row?.patchId === 'web-user-auth' || row?.rowId === 'web-user-auth'
export const protectedBundle = bundle => coreBundles.has(bundle?.name) || [...(bundle?.rows??[]),...(bundle?.overrides??[])].some(protectedRow)
const authBundle = bundle => bundle?.name===AUTH_PACKAGE || [...(bundle?.rows??[]),...(bundle?.overrides??[])].some(protectedRow)
const requireHandoff = runtime => {if(!runtime.handoffAuthorized?.())throw new Error('请先打开 Web 用户认证插件详情，使用“安全停用/卸载”完成原生登录验证；本次未执行操作。')}
const denied = () => { throw new Error('Web UI 认证和基础服务由管理员管理，普通用户不能关闭、卸载、替换或修改。') }

/** Keep the native manager, protecting authentication at both display and mutation boundaries. */
export function installPluginManagementGuards(runtime) {
  const manager=runtime.ctx.get?.('pluginManager')
  if(!manager)return
  const ordinary=service=>service.ctx?.invocation?.peer?.principal?.kind==='harness-user'
  for(const method of ['listBundles','listPlugins'])runtime.patchMethod(manager,method,original=>async function(...args){
    const rows=await original.apply(this,args)
    if(!ordinary(this))return rows
    return rows.map(row=>(method==='listBundles'?protectedBundle(row):protectedRow(row))?{
      ...row,readOnlyReason:'management-required',
      ...(method==='listBundles'?{removable:false,rows:row.rows?.map(item=>({...item,readOnlyReason:'management-required'}))}:{})
    }:row)
  })
  for(const method of ['setBundleEnabled','removeBundle'])runtime.patchMethod(manager,method,original=>async function(name,...args){
    const bundle=(await this.listBundles()).find(item=>item.name===name)
    if(ordinary(this)){
      if(coreBundles.has(name)||protectedBundle(bundle))denied()
    }
    if((name===AUTH_PACKAGE||authBundle(bundle))&&(method==='removeBundle'||args[0]===false))requireHandoff(runtime)
    return original.call(this,name,...args)
  })
  runtime.patchMethod(manager,'setPluginEnabled',original=>async function(id,...args){
    if(ordinary(this)){
      const row=(await this.listPlugins()).find(item=>item.entryId===id)
      if(protectedRow(row)||id==='web-user-auth'||id==='include:web-user-auth')denied()
    }
    if(args[0]===false){
      const row=(await this.listPlugins()).find(item=>item.entryId===id)
      if(protectedRow(row)||id==='web-user-auth'||id==='include:web-user-auth')requireHandoff(runtime)
    }
    return original.call(this,id,...args)
  })
  runtime.patchMethod(manager,'installBundle',original=>async function(spec,options){
    if(ordinary(this)){
      // Resolve aliases and local directories rather than trusting the spec text.
      const inspection=await this.inspect(spec,{registry:options?.registry})
      if(inspection.status!=='accepted'||typeof inspection.name!=='string')throw new Error('普通用户只能安装可确认包名的插件。Git 或压缩包等无法确认包名的来源请由管理员安装。')
      if(coreBundles.has(inspection.name))denied()
    }
    return original.call(this,spec,options)
  })
}
