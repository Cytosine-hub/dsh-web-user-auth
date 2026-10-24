import z from '@deepseek-ai/schemastery'
export const Config = z.object({
  enabled: z.boolean().default(false).description('允许普通用户登录。关闭此项后仅开放管理员登录，不提供匿名访问；不要关闭整个插件行。'),
  provider: z.union(['local','http','header']).default('local').description('local：本地账号；http：插件调用现有登录接口，无需修改代理；header：由可信代理认证，必须配置代理请求头。'),
  workspaceRoot: z.string().default('').description('普通用户工作目录根目录，留空使用默认目录；管理面板切换会保留历史根目录归属，不搬迁文件。'),
  stateDir: z.string().default('').description('用户和签名密钥存储目录，留空使用默认目录。'),
  publicUrl: z.string().default('').description('公开部署地址，必须以 / 结尾。'),
  cookieMaxAgeDays: z.number().min(1).step(1).default(7).description('普通用户登录有效天数。'),
  allowOwnerLoopback: z.boolean().default(true).description('保留 SSH 端口转发后的本机管理员回退。'),
  allowApiTokens: z.boolean().default(false).description('放行内置 API token，通常保持关闭。'),
  secureCookies: z.union([true,false,'auto']).default('auto'),
  setup: z.object({ enabled:z.boolean().default(true), tokenFile:z.string().default('') }).description('首次用户设置：远程需要服务器上的 setup-token。'),
  local: z.object({
    usersFile:z.string().default('').description('本地账号 JSON 文件路径，留空使用默认值。'),
    users:z.array(z.object({id:z.string().required(),name:z.string(),passwordHash:z.string().role('secret'),password:z.string().role('secret')})).default([]).description('本地用户，建议使用密码哈希；这些账号均为普通用户。'),
  }),
  http: z.object({
    loginUrl:z.string().default('').description('登录 API URL，POST 发送 username、password。'),
    userInfoUrl:z.string().default('').description('可选：用户资料 API URL。'),
    method:z.union(['POST']).default('POST'),
    requestFormat:z.union(['json','form']).default('json'),
    tokenField:z.string().default('access_token'),userField:z.string().default('user'),
    idField:z.string().default('id'),nameField:z.string().default('name'),
    tokenHeader:z.string().default('authorization'),tokenPrefix:z.string().default('Bearer '),
    timeoutMs:z.number().min(1).default(10000),
    headers:z.dict(z.string()).role('secret').default({}),userInfoHeaders:z.dict(z.string()).role('secret').default({}),
  }).description('HTTP 身份服务：通常无需改 Caddy。字段支持点路径；并非通用 OIDC/SAML 客户端。'),
  header:z.object({
    userHeader:z.string().default('x-auth-request-user'),nameHeader:z.string().default('x-auth-request-name'),
    secretHeader:z.string().default('x-dsh-auth-secret'),sharedSecret:z.string().role('secret').default(''),
  }).description('代理认证：必须由代理覆盖身份头，并配置共享密钥。此表单不会自动修改 Caddy。'),
})
