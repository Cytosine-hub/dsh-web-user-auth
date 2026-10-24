import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {canonicalPath,contains} from './paths.js'

function resolvedFuture(value){
  let current=path.resolve(value),suffix=[]
  while(!fs.existsSync(current)){
    const parent=path.dirname(current)
    if(parent===current)break
    suffix.unshift(path.basename(current));current=parent
  }
  return path.join(canonicalPath(current),...suffix)
}
/** Validate before reactivation. Keep old roots as ownership boundaries, without moving files. */
export function workspaceSettings(value,config){
  const home=path.resolve(process.env.DSH_HOME??path.join(os.homedir(),'.deepseek-harness'))
  const requested=value.trim()||path.join(home,'web-users')
  if(!path.isAbsolute(requested)||/[\0\r\n]/.test(requested))throw new Error('工作目录根目录必须是服务器上的绝对路径')
  const root=resolvedFuture(requested),previous=resolvedFuture(config.workspaceRoot)
  if(root===previous)return {workspaceRoot:previous}
  const history=[...new Set([...(config.workspaceRootHistory??[]),previous].map(resolvedFuture))]
  for(const sensitive of [home,config.stateDir,path.join(home,'web-admin')].filter(Boolean)){
    const target=resolvedFuture(sensitive)
    if(contains(root,target)||contains(resolvedFuture(config.stateDir??path.join(home,'web-user-auth')),root))throw new Error('不能将配置、密钥目录或其父目录作为工作目录根目录')
  }
  if(root===path.parse(root).root)throw new Error('不能使用文件系统根目录')
  for(const old of [...history,resolvedFuture(config.adminWorkspaceRoot??previous)]){
    if(root!==old&&(contains(root,old)||contains(old,root)))throw new Error('新根目录不能与当前或历史根目录互相嵌套，请选择独立目录')
  }
  if(fs.existsSync(root)&&!fs.statSync(root).isDirectory())throw new Error('工作目录根目录必须是文件夹')
  fs.mkdirSync(root,{recursive:true,mode:0o700})
  fs.accessSync(root,fs.constants.R_OK|fs.constants.W_OK|fs.constants.X_OK)
  return {workspaceRoot:canonicalPath(root),workspaceRootHistory:history.filter(old=>old!==root),adminWorkspaceRoot:config.adminWorkspaceRoot??previous}
}
