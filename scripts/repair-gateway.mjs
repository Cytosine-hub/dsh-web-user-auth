#!/usr/bin/env node
// Deliberate operator action, not an npm lifecycle or plugin startup hook.
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import {repairGateway} from '../lib/gateway-compat.js'
const [mode,root,...extra]=process.argv.slice(2)
try {
  if(!['--check','--apply'].includes(mode)||!root||extra.length)throw new Error('Usage: node scripts/repair-gateway.mjs --check|--apply <Gateway package directory>')
  const entry=path.join(fs.realpathSync(root),'lib/index.js')
  const stat=fs.statSync(entry)
  if(stat.size>1024*1024)throw new Error('Unexpected Gateway entry size')
  const manifest=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'))
  const original=fs.readFileSync(entry,'utf8'),result=repairGateway(original,manifest)
  if(mode==='--check'||result.status==='compatible'){console.log(result.status);process.exit(0)}
  const backup=entry+'.web-user-auth-backup'
  if(!fs.existsSync(backup))fs.writeFileSync(backup,original,{flag:'wx',mode:stat.mode&0o777})
  const temporary=entry+'.tmp-'+crypto.randomBytes(8).toString('hex')
  try {
    fs.writeFileSync(temporary,result.source,{flag:'wx',mode:stat.mode&0o777})
    if(fs.readFileSync(entry,'utf8')!==original)throw new Error('Gateway changed during repair; retry after stopping updates')
    fs.renameSync(temporary,entry)
  }finally{try{fs.unlinkSync(temporary)}catch(error){if(error.code!=='ENOENT')throw error}}
  console.log('repaired; restart the target Harness instance to activate. Backup: '+backup)
}catch(error){console.error(error.message);process.exitCode=1}
