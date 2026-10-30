// Keep native event streams, queues, cancellation and settlement. Only isolated
// Harness user peers need an adapter for the owner's transport-only restriction.
const managed=peer=>['harness-user','harness-admin'].includes(peer?.principal?.kind)
const record=value=>value!==null&&typeof value==='object'&&!Array.isArray(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value))
const keys=(value,required,optional=[])=>record(value)&&required.every(key=>Object.hasOwn(value,key))&&Reflect.ownKeys(value).every(key=>required.includes(key)||optional.includes(key))
function json(value,seen=new Set(),depth=0){
  if(value===null||typeof value==='string'||typeof value==='boolean')return true
  if(typeof value==='number')return Number.isFinite(value)
  if(depth>64||typeof value!=='object'||seen.has(value))return false
  if(!Array.isArray(value)&&!record(value))return false
  seen.add(value)
  const valid=Object.values(value).every(item=>json(item,seen,depth+1))
  seen.delete(value);return valid
}
function resultOf(payload){
  if(!keys(payload,['args'])||!keys(payload.args,['clientId','eventId','outcome']))throw new Error('Invalid interaction result')
  const result=payload.args,outcome=result.outcome
  if(![result.clientId,result.eventId].every(id=>typeof id==='string'&&id.length>0)||!record(outcome))throw new Error('Invalid interaction correlation')
  if(outcome.kind==='next'&&keys(outcome,['kind']))return result
  if(outcome.kind==='result'&&keys(outcome,['kind'],['value'])&&(!Object.hasOwn(outcome,'value')||json(outcome.value)))return result
  const error=outcome.error
  if(outcome.kind==='rejected'&&keys(outcome,['kind','error'])&&keys(error,['name','message'],['code','details'])&&typeof error.name==='string'&&error.name.length>0&&typeof error.message==='string'&&(!Object.hasOwn(error,'code')||typeof error.code==='string')&&(!Object.hasOwn(error,'details')||json(error.details)))return result
  throw new Error('Invalid interaction outcome')
}
export function installInteractions(runtime,gateway,patch){
  const methods=['hasLiveClient','openRemoteEvents','startRemoteEvent','deliverRemoteEvent','receiveRemoteEventResult','dispatchRpc','removeRemoteEventClient','removeRemoteEventDelivery','settleRemoteEvent','cancelRemoteEvent']
  if(methods.some(name=>typeof gateway[name]!=='function')||!(gateway.remoteEventClients instanceof Map)||!(gateway.pendingRemoteEvents instanceof Map))throw new Error('web-user-auth: unsupported Gateway interaction API')
  const allowed=(pending,client)=>{
    if(!managed(client.peer)||client.signal.aborted||client.peer.signal.aborted||client.peer.interactions!=='answer')return false
    if(!['approval/request','user-questions/request'].includes(pending.source.event))return false
    const id=pending.source.context.subject?.session?.id,user=runtime.userFromPrincipal(client.principal)
    if(!user||typeof id!=='string'||!id||!runtime.ownsSession(user.id,id))return false
    try{return runtime.ctx.remoteAccess.decide({principal:client.principal,action:'session/control',resources:[{kind:'session',id}],args:{sessionId:id}}).kind==='allow'}catch{return false}
  }
  patch('hasLiveClient',original=>function(){
    if(original.call(this))return true
    return [...this.remoteEventClients.values()].some(client=>managed(client.peer)&&!client.signal.aborted&&!client.peer.signal.aborted&&client.peer.interactions==='answer'&&runtime.userFromPrincipal(client.principal)!==undefined)
  })
  patch('deliverRemoteEvent',original=>function(pending,client){
    if(managed(client.peer)&&!allowed(pending,client))return
    if(pending.deliveries.has(client))return
    if(!managed(client.peer))return original.call(this,pending,client)
    pending.deliveries.add(client);client.deliveries.set(pending.id,pending);client.queue.push(pending.frame)
  })
  patch('openRemoteEvents',original=>async function*(payload,signal,peer){
    const stream=original.call(this,payload,signal,peer)
    try{
      const ready=await stream.next()
      if(!ready.done&&managed(peer)){
        const client=this.remoteEventClients.get(ready.value.clientId)
        if(!client||client.peer!==peer)throw new Error('web-user-auth: invalid Gateway stream')
        // answers stays false so native notification resource filtering remains
        // active. The adapter dispatches only owned interactive requests.
        client.answers=false
        for(const pending of this.pendingRemoteEvents.values())this.deliverRemoteEvent(pending,client)
      }
      if(!ready.done){yield ready.value;yield* stream}
    }finally{await stream.return?.()}
  })
  patch('startRemoteEvent',original=>function(source){
    const result=original.call(this,source)
    for(const pending of this.pendingRemoteEvents.values())for(const client of this.remoteEventClients.values())if(managed(client.peer))this.deliverRemoteEvent(pending,client)
    return result
  })
  patch('receiveRemoteEventResult',original=>function(client,result){
    const pending=this.pendingRemoteEvents.get(result.eventId)
    if(!managed(client.peer))return original.call(this,client,result)
    result=resultOf({args:result})
    if(!pending||!pending.deliveries.has(client)||!allowed(pending,client))throw new Error('Interaction access denied')
    this.removeRemoteEventDelivery(pending,client)
    const outcome=result.outcome
    if(outcome.kind==='result')this.settleRemoteEvent(pending,{kind:'result',value:outcome.value})
    else if(outcome.kind==='rejected'){
      const error=new Error(outcome.error.message);error.name=outcome.error.name
      for(const key of ['code','details'])if(Object.hasOwn(outcome.error,key))error[key]=outcome.error[key]
      this.cancelRemoteEvent(pending,error)
    }else if(pending.deliveries.size===0)this.settleRemoteEvent(pending,{kind:'next'})
  })
  patch('dispatchRpc',original=>async function(endpoint,payload,signal,peer){
    if(endpoint!=='$events/result'||!managed(peer))return original.call(this,endpoint,payload,signal,peer)
    try{
      if(peer.signal.aborted||signal?.aborted||peer.interactions!=='answer')throw new Error('Inactive interaction peer')
      const result=resultOf(payload),client=this.remoteEventClients.get(result.clientId)
      if(!client||client.peer!==peer)throw new Error('Interaction peer mismatch')
      this.receiveRemoteEventResult(client,result)
      return {ok:true,value:undefined}
    }catch{return {ok:false,error:{code:'gateway/interactions-forbidden',message:'Interaction access denied',details:{}}}}
  })
  // Remove live streams before restoring native methods on reload/disable.
  return ()=>{for(const client of [...gateway.remoteEventClients.values()])if(managed(client.peer))gateway.removeRemoteEventClient(client)}
}
