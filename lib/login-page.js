/**
 * Standalone login and first-run setup pages.
 *
 * These are deliberately not React pages: they must render before any
 * authenticated DSH API request exists, so they are served by the HTTP route
 * owner as ordinary documents.
 */

const TEXT = {
  en: {
    lang: 'en',
    title: 'Sign in',
    subtitle: 'DeepSeek Harness',
    username: 'User name',
    password: 'Password',
    signIn: 'Sign in',
    signingIn: 'Signing in…',
    invalid: 'The user name or password is incorrect.',
    missing: 'Enter both a user name and a password.',
    upstream: 'This deployment authenticates users through its reverse proxy.',
    upstreamHint: 'If you reached this page directly, sign in through the configured gateway instead.',
    noUsers: 'No local users exist yet. Complete first-run setup from the Harness host.',
    setup: 'First-run setup',
    setupTitle: 'Create the first user',
    setupHint: 'This page is available only from the Harness host (loopback) or with the setup token stored in the plugin state directory.',
    setupToken: 'Setup token',
    displayName: 'Display name',
    confirm: 'Confirm password',
    create: 'Create user and sign in',
    mismatch: 'The passwords do not match.',
    short: 'Use a password of at least 8 characters.',
    exists: 'Setup is already complete.',
    failed: 'Setup failed. Check the values and try again.',
    logout: 'Sign out',
    signedInAs: 'Signed in as',
    workspace: 'Workspace',
    continue: 'Continue',
    back: 'Back to sign in',
    error: 'Something went wrong.',
    lockLabel: 'Account',
  },
  zh: {
    lang: 'zh-CN',
    title: '登录',
    subtitle: 'DeepSeek Harness',
    username: '用户名',
    password: '密码',
    signIn: '登录',
    signingIn: '正在登录…',
    invalid: '用户名或密码不正确。',
    missing: '请输入用户名和密码。',
    upstream: '此部署通过反向代理完成用户认证。',
    upstreamHint: '如果你直接打开了此页面，请通过配置的网关登录。',
    noUsers: '尚未创建本地用户。请在 Harness 主机上完成首次设置。',
    setup: '首次设置',
    setupTitle: '创建第一个用户',
    setupHint: '此页面仅能从 Harness 主机（本机回环地址）打开，或使用插件状态目录中的设置令牌。',
    setupToken: '设置令牌',
    displayName: '显示名称',
    confirm: '确认密码',
    create: '创建用户并登录',
    mismatch: '两次输入的密码不一致。',
    short: '密码至少需要 8 个字符。',
    exists: '首次设置已完成。',
    failed: '设置失败，请检查输入后重试。',
    logout: '退出登录',
    signedInAs: '当前用户',
    workspace: '工作目录',
    continue: '继续',
    back: '返回登录',
    error: '发生错误。',
    lockLabel: '账户',
  },
}

/** Pick one of the two built-in server-page locales from Accept-Language. */
export function serverLocale(header) {
  if (typeof header === 'string' && /(?:^|,)\s*zh(?:-|,|;|$)/iu.test(header)) return 'zh'
  return 'en'
}

/** Escape text before placing it in HTML. */
export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

const STYLE = `
:root {
  color-scheme: light dark;
  --bg: #f4f1ea;
  --panel: rgba(255, 255, 255, 0.86);
  --panel-edge: rgba(23, 32, 44, 0.12);
  --text: #17202c;
  --muted: #5f6b7a;
  --accent: #1f6feb;
  --accent-strong: #1558c0;
  --danger: #b42318;
  --ok: #087443;
  --field: rgba(255, 255, 255, 0.78);
  --field-edge: rgba(23, 32, 44, 0.18);
  --focus: rgba(31, 111, 235, 0.24);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f141b;
    --panel: rgba(24, 31, 41, 0.9);
    --panel-edge: rgba(255, 255, 255, 0.12);
    --text: #e8edf5;
    --muted: #9aa7b8;
    --accent: #79a9ff;
    --accent-strong: #a9c8ff;
    --danger: #ff8a80;
    --ok: #6ed3a4;
    --field: rgba(10, 15, 22, 0.55);
    --field-edge: rgba(255, 255, 255, 0.16);
    --focus: rgba(121, 169, 255, 0.26);
  }
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 28px 18px;
  color: var(--text);
  background:
    radial-gradient(circle at 18% 12%, rgba(31, 111, 235, 0.16), transparent 36rem),
    radial-gradient(circle at 84% 88%, rgba(8, 116, 67, 0.12), transparent 32rem),
    var(--bg);
  font: 15px/1.5 ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans SC", sans-serif;
}
.shell { width: min(420px, 100%); }
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 0 0 18px;
  font-size: 13px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
}
.brand svg { width: 22px; height: 22px; flex: none; }
.card {
  border: 1px solid var(--panel-edge);
  border-radius: 20px;
  background: var(--panel);
  box-shadow: 0 24px 70px rgba(15, 23, 42, 0.16);
  padding: 28px;
  backdrop-filter: blur(16px);
}
h1 { margin: 0 0 6px; font-size: 28px; letter-spacing: -0.02em; }
.sub { margin: 0 0 24px; color: var(--muted); }
.notice {
  margin: 0 0 18px;
  padding: 11px 13px;
  border-radius: 11px;
  border: 1px solid var(--panel-edge);
  background: color-mix(in srgb, var(--panel) 70%, var(--accent) 8%);
  color: var(--muted);
  font-size: 13px;
}
.error {
  margin: 0 0 18px;
  padding: 11px 13px;
  border-radius: 11px;
  border: 1px solid color-mix(in srgb, var(--danger) 42%, transparent);
  background: color-mix(in srgb, var(--danger) 10%, transparent);
  color: var(--danger);
  font-size: 13px;
}
label { display: block; margin: 0 0 7px; font-size: 13px; font-weight: 600; }
.field { margin-bottom: 15px; }
input {
  width: 100%;
  border: 1px solid var(--field-edge);
  border-radius: 11px;
  background: var(--field);
  color: var(--text);
  padding: 11px 12px;
  font: inherit;
  outline: none;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 4px var(--focus); }
button, .button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  min-height: 44px;
  margin-top: 4px;
  border: 0;
  border-radius: 11px;
  background: var(--accent);
  color: #fff;
  font: inherit;
  font-weight: 650;
  text-decoration: none;
  cursor: pointer;
}
button:hover, .button:hover { background: var(--accent-strong); }
@media (prefers-color-scheme: dark) {
  button, .button { color: #07111f; }
}
button:disabled { opacity: 0.6; cursor: wait; }
.links { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 10px; margin-top: 18px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.hint { margin: 16px 0 0; color: var(--muted); font-size: 12px; }
.meta { margin: 18px 0 0; padding-top: 16px; border-top: 1px solid var(--panel-edge); color: var(--muted); font-size: 13px; }
code { font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
`

function lockIcon() {
  return `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4.5" y="10" width="15" height="10.5" rx="2.2"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10"/><path d="M12 14.2v2.4"/></svg>`
}

function page(locale, body) {
  const text = TEXT[locale] ?? TEXT.en
  return `<!doctype html>
<html lang="${escapeHtml(text.lang)}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${escapeHtml(text.title)} · ${escapeHtml(text.subtitle)}</title>
<style>${STYLE}</style>
</head>
<body>
<main class="shell">
  <div class="brand">${lockIcon()}<span>${escapeHtml(text.subtitle)}</span></div>
  <section class="card">${body}</section>
</main>
</body>
</html>`
}

/** Login page for local and HTTP providers. */
export function renderLoginPage({ locale, provider, error, needsSetup, setupAvailable }) {
  const text = TEXT[locale] ?? TEXT.en
  if (provider === 'header') {
    return page(locale, `<h1>${escapeHtml(text.title)}</h1>
<p class="sub">${escapeHtml(text.subtitle)}</p>
<div class="notice">${escapeHtml(text.upstream)}<br>${escapeHtml(text.upstreamHint)}</div>
<a class="button" href="./">${escapeHtml(text.continue)}</a>`)
  }
  const errorText = error === 'missing' ? text.missing : error === 'invalid' ? text.invalid : error ? text.error : ''
  const setupLink = needsSetup && setupAvailable
    ? `<div class="links"><a href="./setup">${escapeHtml(text.setup)}</a></div>`
    : ''
  const noUsers = needsSetup
    ? `<div class="notice">${escapeHtml(text.noUsers)}</div>`
    : ''
  return page(locale, `<h1>${escapeHtml(text.title)}</h1>
<p class="sub">${escapeHtml(text.subtitle)}</p>
${errorText ? `<div class="error" role="alert">${escapeHtml(errorText)}</div>` : ''}
${noUsers}
<form method="post" action="./login" autocomplete="on">
  <div class="field">
    <label for="username">${escapeHtml(text.username)}</label>
    <input id="username" name="username" autocapitalize="none" autocomplete="username" required autofocus>
  </div>
  <div class="field">
    <label for="password">${escapeHtml(text.password)}</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
  </div>
  <button type="submit">${escapeHtml(text.signIn)}</button>
</form>
${setupLink}`)
}

/** First-run setup page. */
export function renderSetupPage({ locale, error, needsToken, token }) {
  const text = TEXT[locale] ?? TEXT.en
  const errorText = error === 'mismatch' ? text.mismatch : error === 'short' ? text.short : error === 'exists' ? text.exists : error ? text.failed : ''
  return page(locale, `<h1>${escapeHtml(text.setupTitle)}</h1>
<p class="sub">${escapeHtml(text.subtitle)}</p>
<div class="notice">${escapeHtml(text.setupHint)}</div>
${errorText ? `<div class="error" role="alert">${escapeHtml(errorText)}</div>` : ''}
<form method="post" action="./setup" autocomplete="on">
  ${needsToken ? `<div class="field"><label for="token">${escapeHtml(text.setupToken)}</label><input id="token" name="token" value="${escapeHtml(token ?? '')}" autocomplete="one-time-code"></div>` : ''}
  <div class="field">
    <label for="username">${escapeHtml(text.username)}</label>
    <input id="username" name="username" autocapitalize="none" autocomplete="username" required autofocus>
  </div>
  <div class="field">
    <label for="name">${escapeHtml(text.displayName)}</label>
    <input id="name" name="name" autocomplete="name">
  </div>
  <div class="field">
    <label for="password">${escapeHtml(text.password)}</label>
    <input id="password" name="password" type="password" autocomplete="new-password" minlength="8" required>
  </div>
  <div class="field">
    <label for="confirm">${escapeHtml(text.confirm)}</label>
    <input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="8" required>
  </div>
  <button type="submit">${escapeHtml(text.create)}</button>
</form>
<div class="links"><a href="./login">${escapeHtml(text.back)}</a></div>`)
}

/** A tiny non-JS page for logout/error outcomes. */
export function renderMessagePage({ locale, title, message, href = './login', label }) {
  const text = TEXT[locale] ?? TEXT.en
  return page(locale, `<h1>${escapeHtml(title)}</h1>
<p class="sub">${escapeHtml(message)}</p>
<a class="button" href="${escapeHtml(href)}">${escapeHtml(label ?? text.back)}</a>`)
}
