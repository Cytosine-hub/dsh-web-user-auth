// Cordis returns a fresh method proxy for every read. Restore raw descriptors;
// inactive layers forward to their predecessor even when disposal is not LIFO.
const LAYER=Symbol('web-user-auth/service-patch')
export function patchServiceMethod(target,name,create) {
  if(target===null||typeof target!=='object')return ()=>{}
  const descriptor=Object.getOwnPropertyDescriptor(target,name)
  const original=target[name]
  if(typeof original!=='function')return ()=>{}
  const implementation=create(original),state={active:true,descriptor}
  const replacement=function(...args){return (state.active?implementation:original).apply(this,args)}
  Object.defineProperty(replacement,LAYER,{value:state})
  target[name]=replacement
  return ()=>{
    state.active=false
    let current=Object.getOwnPropertyDescriptor(target,name)
    while(current?.value?.[LAYER]?.active===false){
      current=current.value[LAYER].descriptor
      if(current)Object.defineProperty(target,name,current)
      else delete target[name]
    }
  }
}
