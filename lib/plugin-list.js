// Return display data only. Never expose profile paths, configuration or patch rows.
const AUTH_PACKAGE = '@local/dsh-web-user-auth'
function text(value) { return typeof value === 'string' ? value : undefined }
function localized(value) {
  if (typeof value === 'string') return value
  return text(value?.zh) ?? text(value?.['zh-CN']) ?? text(value?.en)
}
export function publicPluginList(bundles, administrator = false) {
  return bundles.filter(bundle =>
    typeof bundle.name === 'string' &&
    (administrator || bundle.name !== AUTH_PACKAGE) &&
    (bundle.availability === 'profile' || bundle.availability === 'installation')
  ).map(bundle => ({
    name: bundle.name,
    title: localized(bundle.meta?.title) ?? bundle.name,
    description: localized(bundle.meta?.description) ?? text(bundle.description) ?? '',
    version: text(bundle.version) ?? '',
    enabled: bundle.enabled === true,
  }))
}
