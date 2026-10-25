/**
 * Remote-access policy for Web users.
 *
 * DSH's owner Peer is never checked. Every authenticated Web user gets a Peer
 * whose principal is `{ kind: 'harness-user', userId }`; this policy grants:
 *
 * - the `global` resource only for the small set of endpoints the browser
 *   needs to discover Sessions, models, and the user's Workspace;
 * - a `session` resource for every Session whose cwd lives under that user's
 *   directory;
 * - a `workspace` resource for every Workspace under that same directory.
 *
 * Session ownership is inferred from the immutable `cwd` in the Session header,
 * so it survives restarts and needs no schema addition.
 */
import path from 'node:path'
import { ADMIN_USER_ID } from './identity.js'
import { contains, userFromCwd } from './paths.js'

const GLOBAL_ENDPOINTS = new Set([
  'session/list',
  'session/search',
  'session/control',
  'session/create',
  'session/modelCatalog',
  'session/initializeDefaultModel',
  'session/canOpenWorkspacePath',
  'session/openWorkspacePath',
  'session/workspacePathApplications',
  'workspace/create',
  'workspace/follow',
  'directoryPicker/list',
  'directoryPicker/createDirectory',
  'directoryPicker/pick',
  'agentPresets/list',
  'agentPresets/read',
  'commands/list',
  'permissionPresets/catalog',
  'remoteAccess/follow',
  'pluginInventory/list',
  'pluginRegistryProbe/fastest',
  ...['listBundles','listPlugins','registries','inspect','installBundle','waitForInstall','cancelInstall','setBundleEnabled','setPluginEnabled','removeBundle','listVersionExemptions'].map(method=>'pluginManager/'+method),
])

const EVENT_ACTIONS = [
  'event:api-session/added',
  'event:api-session/activity',
  'event:api-session/error',
  'event:api-session/removed',
  'event:api-session/status',
  'event:permission-presets/catalog-changed',
  'event:schedule/changed',
  'event:plugin-manager/changed',
  'event:plugin-manager/install-log',
  'event:plugin-manager/install-state',
]

function nested(args, key) {
  if (args === undefined || args === null || typeof args !== 'object') return undefined
  const direct = args[key]
  if (direct !== undefined) return direct
  for (const value of Object.values(args)) {
    if (value !== null && typeof value === 'object' && !Array.isArray(value) && value[key] !== undefined) return value[key]
  }
  return undefined
}

function requestPath(args) {
  const request = nested(args, 'path')
  if (typeof request === 'string') return request
  return undefined
}

function allEndpoints(ctx) {
  const actions = new Set(EVENT_ACTIONS)
  try {
    for (const descriptor of ctx.typert.local.list()) {
      if (typeof descriptor?.namespace !== 'string' || typeof descriptor?.method !== 'string') continue
      actions.add(`${descriptor.namespace}/${descriptor.method}`)
    }
  } catch {
    // A composition without Typert still gets the explicit global set.
  }
  for (const action of GLOBAL_ENDPOINTS) actions.add(action)
  return Array.from(actions)
}

/**
 * Build the policy plus the session-ownership index it reads.
 * @param {object} options
 * @param {import('@deepseek-ai/cordis').Context} options.ctx
 * @param {string} options.workspaceRoot
 * @param {(userId: string) => string} options.workspaceOf
 * @param {(path: string) => string | undefined} options.userForPath
 */
export function createUserAccessPolicy({ ctx, workspaceRoot, workspaceOf, userForPath, ownsPath, isAdministrator=()=>false }) {
  const sessions = new Map()
  let sessionRole
  let workspaceRole
  let globalRole
  let adminGlobalRole

  function roles() {
    if (sessionRole === undefined) {
      const actions = allEndpoints(ctx)
      sessionRole = { name: 'web-user/session', resource: 'session', actions }
      workspaceRole = { name: 'web-user/workspace', resource: 'workspace', actions }
      globalRole = { name: 'web-user/global', resource: 'global', actions: Array.from(GLOBAL_ENDPOINTS).concat(EVENT_ACTIONS) }
      const adminNamespaces = new Set(['pluginInventory', 'pluginManager', 'pluginRegistryProbe', 'configForms', 'settings', 'credentials'])
      adminGlobalRole = { name: 'web-admin/global', resource: 'global', actions: [...new Set([...globalRole.actions, ...actions.filter(action => adminNamespaces.has(action.split('/')[0]))])] }
    }
    return { sessionRole, workspaceRole, globalRole, adminGlobalRole }
  }

  function ownedSessions(userId) {
    const ids = sessions.get(userId)
    return ids === undefined ? [] : Array.from(ids)
  }

  function ownedWorkspaces(userId) {
    const result = []
    try {
      const ownRoot = workspaceOf(userId)
      for (const workspace of ctx.workspaceRegistry.list()) {
        if (ownsPath) { if (!ownsPath(userId, workspace.path)) continue }
        else {
          if (workspace.path !== ownRoot && !contains(ownRoot, workspace.path)) continue
          if (workspace.path !== ownRoot && userFromCwd(workspaceRoot, workspace.path) !== userId) continue
        }
        result.push(workspace)
      }
    } catch {
      // The registry may not be ready during early activation.
    }
    return result
  }

  function globalCondition(userId, { action, args }) {
    if (action === 'session/create') return { kind: 'allow' }
    if (action === 'directoryPicker/pick') return { kind: 'allow' }
    if (action === 'directoryPicker/list' || action === 'directoryPicker/createDirectory') {
      const target = requestPath(args)
      if (target === undefined || target === '') return { kind: 'allow' }
      const root = workspaceOf(userId)
      return (ownsPath ? ownsPath(userId, path.isAbsolute(target) ? path.resolve(target) : path.resolve(root, target)) : contains(root, path.isAbsolute(target) ? path.resolve(target) : path.resolve(root, target)))
        ? { kind: 'allow' }
        : { kind: 'deny', reason: 'path is outside the user workspace' }
    }
    if (action === 'workspace/create') {
      const target = requestPath(args)
      if (target === undefined) return { kind: 'deny', reason: 'workspace path is required' }
      const root = workspaceOf(userId)
      return (ownsPath ? ownsPath(userId, path.isAbsolute(target) ? path.resolve(target) : path.resolve(root, target)) : contains(root, path.isAbsolute(target) ? path.resolve(target) : path.resolve(root, target)))
        ? { kind: 'allow' }
        : { kind: 'deny', reason: 'workspace path is outside the user workspace' }
    }
    if (action === 'session/openWorkspacePath' || action === 'session/workspacePathApplications') {
      const target = requestPath(args)
      if (target === undefined || target === '') return { kind: 'allow' }
      const root = workspaceOf(userId)
      return (ownsPath ? ownsPath(userId, path.isAbsolute(target) ? path.resolve(target) : path.resolve(root, target)) : contains(root, path.isAbsolute(target) ? path.resolve(target) : path.resolve(root, target)))
        ? { kind: 'allow' }
        : { kind: 'deny', reason: 'path is outside the user workspace' }
    }
    return { kind: 'allow' }
  }


  const policy = {
    bindings(principal) {
      if (principal === null || typeof principal !== 'object' || !['harness-user','harness-admin'].includes(principal.kind) || typeof principal.userId !== 'string') return []
      if (principal.kind === 'harness-admin' && principal.userId !== ADMIN_USER_ID && !isAdministrator(principal.userId)) return []
      if (principal.kind === 'harness-user' && principal.userId === ADMIN_USER_ID) return []
      const { sessionRole: session, workspaceRole: workspace, globalRole: global } = roles()
      const bindings = [{ role: principal.kind === 'harness-admin' ? roles().adminGlobalRole : global, resource: { kind: 'global' }, condition: request => globalCondition(principal.userId, request) }]
      for (const sessionId of ownedSessions(principal.userId)) {
        bindings.push({ role: session, resource: { kind: 'session', id: sessionId } })
      }
      for (const record of ownedWorkspaces(principal.userId)) {
        bindings.push({ role: workspace, resource: { kind: 'workspace', id: record.id } })
      }
      return bindings
    },
    explain(request) {
      if (!['harness-user','harness-admin'].includes(request.principal.kind)) return 'not a Web user'
      return `no grant for ${String(request.action)} on ${request.resources.map((resource) => resource.kind).join(', ')}`
    },
  }

  return {
    policy,
    rememberSession(sessionId, cwd) {
      if (typeof sessionId !== 'string' || typeof cwd !== 'string') return false
      const userId = userForPath(cwd)
      if (userId === undefined) return false
      let set = sessions.get(userId)
      if (set === undefined) {
        set = new Set()
        sessions.set(userId, set)
      }
      if (set.has(sessionId)) return false
      set.add(sessionId)
      try {
        ctx.remoteAccess.invalidate({ kind: userId === ADMIN_USER_ID ? 'harness-admin' : 'harness-user', userId })
      } catch {
        // Invalidation is best effort during shutdown.
      }
      return true
    },
    forgetSession(sessionId) {
      for (const set of sessions.values()) set.delete(sessionId)
    },
    sessionsOf(userId) {
      return ownedSessions(userId)
    },
  }
}
