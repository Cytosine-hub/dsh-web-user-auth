import path from 'node:path'
import { administratorIdentity } from './identity.js'

function reply(res, status, body = '') {
  res.writeHead(status, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' })
  res.end(body)
}

function coordinate(value, minimum) {
  if (value === null || !/^\d+$/.test(value)) return undefined
  const result = Number(value)
  return Number.isSafeInteger(result) && result >= minimum ? result : undefined
}

/** Download one durable delivery declaration; never accept an arbitrary path. */
export async function downloadPresentedFile(runtime, req, res) {
  if (req.method !== 'GET') { reply(res, 405); return }
  const identity = () => runtime.isAdmin(req)
    ? runtime.ensureUserSync(administratorIdentity()) : runtime.identify(req)
  const user = identity()
  if (user === undefined) { reply(res, 401); return }
  const query = new URL(req.url, 'http://dsh.invalid').searchParams
  const sessionId = query.get('sessionId')
  const seq = coordinate(query.get('seq'), 1)
  const index = coordinate(query.get('index'), 0)
  if (!sessionId || seq === undefined || index === undefined) { reply(res, 400); return }
  if (!runtime.ownsSession(user.id, sessionId)) { reply(res, 403); return }
  const queries = runtime.ctx.get('sessionQuery')
  const files = runtime.ctx.get('workspaceFiles')
  if (!queries || !files) { reply(res, 503); return }
  const signal = AbortSignal.timeout(30000)
  try {
    const { session, target } = await queries.readEvent({ sessionId, seq, before: 0, after: 0 }, signal)
    const file = target?.type === 'deliverables/presented' && Array.isArray(target.data?.files)
      ? target.data.files[index] : undefined
    if (typeof file?.path !== 'string' || file.path.trim() === '') { reply(res, 404); return }
    const cwd = session?.cwd
    if (typeof cwd !== 'string') { reply(res, 404); return }
    const absolute = path.resolve(cwd, file.path)
    if (!runtime.pathAllowed(user, absolute)) { reply(res, 403); return }
    const result = await files.readBytes({ sessionId, workspaceRoot: cwd }, absolute, {}, signal)
    if (!runtime.pathAllowed(user, result.absolutePath)) { reply(res, 403); return }
    if (result.eof !== true || result.bytes !== result.data.byteLength) { reply(res, 413); return }
    if (identity()?.id !== user.id) { reply(res, 401); return }
    const filename = encodeURIComponent(path.basename(absolute)).replace(/['()*]/g,
      char => '%' + char.charCodeAt(0).toString(16).toUpperCase())
    res.writeHead(200, {
      'cache-control': 'no-store',
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="download"; filename*=UTF-8''${filename}`,
      'content-length': String(result.data.byteLength),
      'x-content-type-options': 'nosniff',
      'content-security-policy': "sandbox; default-src 'none'",
    })
    res.end(Buffer.from(result.data))
  } catch (error) {
    const code = error?.code
    const status = /not-found|not-regular-file|NOT_FOUND|NOT_REGULAR_FILE/.test(code) ? 404
      : /too-large|TOO_LARGE/.test(code) ? 413
        : /denied|DENIED/.test(code) ? 403 : 500
    reply(res, status, '无法下载该文件，请确认文件仍存在且属于当前用户。')
  }
}
