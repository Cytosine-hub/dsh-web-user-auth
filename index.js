/**
 * Host half of the Web user-authentication bundle.
 *
 * Login is served by the Host; the Client half adds account controls and a
 * native management panel to the Harness shell.
 */
export { apply } from './lib/plugin.js'

/** Host services this bundle composes with. */
export const inject = [
  'webServer',
  'connection',
  'remoteAccess',
  'sessions',
  'sessionPersistence',
  'sessionController',
  'workspaceRegistry',
  'directoryPickerController',
  'typert',
  'pluginManager',
]

export { Config } from './lib/config.js'
