import assert from 'node:assert/strict'
import test from 'node:test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {spawnSync} from 'node:child_process'
import {repairGateway} from '../lib/gateway-compat.js'

test('gateway repair refuses unknown bytes or versions without modifying the installation',()=>{
  const manifest={name:'@deepseek-ai/dsh-api-gateway',version:'0.2.1-rc.2'}
  assert.throws(()=>repairGateway('unknown',manifest),/not a reviewed/)
  assert.throws(()=>repairGateway('unknown',{...manifest,version:'0.3.0'}),/Unsupported/)
  assert.throws(()=>repairGateway('unknown',{...manifest,name:'other'}),/Unsupported/)
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'gateway-compat-'))
  try{
    fs.mkdirSync(path.join(root,'lib'));fs.writeFileSync(path.join(root,'package.json'),JSON.stringify(manifest));fs.writeFileSync(path.join(root,'lib/index.js'),'unknown')
    const result=spawnSync(process.execPath,['scripts/repair-gateway.mjs','--apply',root],{encoding:'utf8'})
    assert.equal(result.status,1);assert.equal(fs.readFileSync(path.join(root,'lib/index.js'),'utf8'),'unknown');assert.equal(fs.existsSync(path.join(root,'lib/index.js.web-user-auth-backup')),false)
  }finally{fs.rmSync(root,{recursive:true,force:true})}
})

test('reviewed native and approval-only Gateway repairs are idempotent with backup', {skip:!process.env.DSH_GATEWAY_RAW_ENTRY},()=>{
  const manifest={name:'@deepseek-ai/dsh-api-gateway',version:'0.2.1-rc.2'}
  const original=fs.readFileSync(process.env.DSH_GATEWAY_RAW_ENTRY,'utf8')
  const fixed=repairGateway(original,manifest)
  assert.equal(fixed.status,'repair-required');assert.equal(repairGateway(fixed.source,manifest).status,'compatible')
  const old=fixed.source.replaceAll('canAnswerSessionInteraction','canAnswerSessionApproval').replace('if (!["approval/request", "user-questions/request"].includes(pending.source.event)) return false;','if (pending.source.event !== "approval/request") return false;').replace('Session interaction access was revoked','Session approval access was revoked')
  assert.equal(repairGateway(old,manifest).source,fixed.source)
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'gateway-reviewed-'))
  try{
    fs.mkdirSync(path.join(root,'lib'));fs.writeFileSync(path.join(root,'package.json'),JSON.stringify(manifest));fs.writeFileSync(path.join(root,'lib/index.js'),original)
    const run=mode=>spawnSync(process.execPath,['scripts/repair-gateway.mjs',mode,root],{encoding:'utf8'})
    assert.match(run('--check').stdout,/repair-required/);assert.equal(fs.readFileSync(path.join(root,'lib/index.js'),'utf8'),original)
    assert.equal(run('--apply').status,0);assert.equal(fs.readFileSync(path.join(root,'lib/index.js.web-user-auth-backup'),'utf8'),original)
    assert.equal(fs.readFileSync(path.join(root,'lib/index.js'),'utf8'),fixed.source);assert.match(run('--apply').stdout,/compatible/)
  }finally{fs.rmSync(root,{recursive:true,force:true})}
})
