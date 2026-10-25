# Web 用户认证插件

[![CI](https://github.com/Cytosine-hub/dsh-web-user-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/Cytosine-hub/dsh-web-user-auth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

为 DeepSeek Harness Web UI 提供 Local、HTTP、Header、Token 四种普通用户认证方式、本地管理员入口、用户工作区隔离和原生管理面板。

这是独立插件包，不需要修改 Harness 源码。已验证的宿主版本为 `@deepseek-ai/dsh-web-app 0.2.1-rc.2`；其他版本需要先验证连接、Remote Access 和 UI 插槽接口兼容性。

## 部署地址与目录约定

插件不要求特定域名、端口或 URL 前缀。下文的 `BASE_URL` 指你自己的 Web UI 公开入口，必须以 `/` 结尾。以下均为示例地址：

| 部署形式 | BASE_URL 示例 | 登录页示例 |
|---|---|---|
| 根路径 | `https://harness.example.test/` | `https://harness.example.test/login` |
| 子路径 | `https://harness.example.test/assistant/` | `https://harness.example.test/assistant/login` |

所有插件路由均相对于 `BASE_URL`，例如登录页为 `<BASE_URL>login`、管理面板为 `<BASE_URL>?panel=web-user-auth`。子路径部署需要由你配置反向代理前缀转发，以及 Harness 的公开地址和可信 Host；插件不会自动配置反向代理、TLS 或系统服务。

`DSH_HOME` 是运行该 Harness 实例的应用数据目录；未设置时默认为运行账号的 `~/.deepseek-harness`。profile 名称由部署者选择，下文以 `web` 为例。服务器安装目录、系统用户名、服务名及普通用户工作目录均不要求固定值。

## 安装与首次启用

从 [GitHub Releases](https://github.com/Cytosine-hub/dsh-web-user-auth/releases/latest) 下载 `.tgz` 安装包。GitHub 自动生成的 Source code 压缩包是源码，不是已打包的插件；也可以从源码目录执行 `npm pack --ignore-scripts` 构建。

1. 将插件 `.tgz` 放到目标服务器可读取的位置。通过原生插件面板安装本地包，或使用 CLI：

   ```sh
   # 替换为实际安装包的绝对路径；web 替换为目标实例的 profile。
   dsh plugin --profile web add /absolute/path/to/local-dsh-web-user-auth-0.8.0.tgz
   ```

   如果 `dsh` 不在 PATH 中，请使用本机安装位置的可执行文件路径。

2. 检查 `<DSH_HOME>/profiles/<profile>/package.json` 的 `dsh.profile.bundles` 数组，确保包含 `@local/dsh-web-user-auth`，并保留其他 bundle。若安装器已自动添加，无需重复。

3. 插件的默认 bundle 条目不会自动启用。在该 profile 的 `cordis.patch.yml` 添加以下覆盖，首次启用只开放管理员登录：

   ```yaml
   - id: web-user-auth
     disabled: false
     config:
       enabled: false
       provider: local
   ```

4. 按实际部署方式重启对应 Harness 实例。插件不会替你创建 systemd 服务或配置开机启动。
5. 首次启用自动创建本地管理员 `admin`。在目标服务器读取 `<DSH_HOME>/web-admin/initial-password.txt`，然后通过 `<BASE_URL>login` 登录。不要公开该密码或数据目录。
6. 打开侧栏“用户与认证”。Local 模式先创建普通用户，再打开“允许普通用户登录”；HTTP/Header 模式按下文配置。

安装包仅包含插件代码、元数据、文档和辅助脚本，不包含部署者的账号、密钥、会话或认证服务配置。升级同一实例时保留其应用数据目录；迁移账号和会话需要单独迁移数据。

## 账号与认证方式

本地管理员始终使用 `admin` 和本地密码登录，不受普通用户认证模式切换影响。`admin` 是保留用户名。HTTP 返回的角色或 Header 身份不会自动成为插件管理员，目前不提供外部管理员映射。

管理员和 Local/HTTP 普通用户共用 `<BASE_URL>login`。Token 普通用户在同一页面通过浏览器存储自动认证，本地管理员可使用 `<BASE_URL>login?admin=1` 暂停自动 Token 登录。Harness 原有 DeepSeek 平台账号登录仍用于模型服务等功能，与本机 Web UI 访问身份独立。

| 模式 | 普通用户身份来源 | 配置与操作 |
|---|---|---|
| Local | 插件本地用户目录 | 管理员创建、重置账号；可自助修改密码的用户显示改密和退出按钮 |
| HTTP | 已有账号密码登录 API | 插件 POST JSON/Form 的 `username`、`password`，可用返回 token 请求用户资料；通常不需要修改反向代理 |
| Header | 可信代理注入的身份请求头 | 代理先认证，再覆盖身份头和共享密钥头；普通用户不显示本地改密、退出按钮 |
| Token | 同源浏览器存储中的 Token | 从 localStorage/sessionStorage 读取 Token，服务端验证同源用户信息接口；由业务系统管理登录、退出和密码 |

在“用户与认证”中选择认证方式并保存，立即生效，重启后保留。管理员的本地登录入口保留，普通用户需要按新方式重新登录。

### HTTP

配置登录 API 地址、可选用户资料 API 地址、请求格式、字段映射、Token 请求头/前缀与超时。字段支持点路径。附加请求头使用 JSON 对象，密钥不回显；留空保留，填写 `{}` 清空。

这是账号密码 API 适配，不是通用 OIDC/SAML 客户端；不能直接填写授权跳转地址。

### Header

配置用户 ID 头、显示名称头、共享密钥头和至少十六位共享密钥。代理必须覆盖外部传入的这些头，并限制上游只接受可信代理连接。保存表单不会自动修改代理。

如果外层代理也拦截管理员请求，需在代理层保留管理员的可用访问路径；插件本地登录无法越过外层代理。用户的登录、会话有效期和退出由外部认证系统负责。本地管理员依然使用本地认证，提供修改密码和退出登录。

### 同源 Token

适用于已有业务系统将访问 Token 存入浏览器存储的场景。业务系统、Harness 和用户信息接口必须具有**完全相同的协议、域名和端口**；不同路径可以，例如业务系统在 `/`、Harness 在 `/assistant/`。不支持跨域部署，不会通过放宽 CORS 绕过限制。

在管理面板选择“同源存储 Token”，配置：

- 同源站点地址：仅协议、域名、端口，必须与当前配置页面相同。
- 存储位置：`localStorage` 或 `sessionStorage`，以及存储键名。可选点路径用于从 JSON 存储值取出 Token；留空直接使用字符串。
- 用户信息接口：同源完整 URL 或相对于站点根的路径，例如 `/api/user/me`。接口须支持服务端使用指定请求头 GET 验证 Token；不转发浏览器的业务 Cookie，不跟随重定向。响应上限 64 KiB。
- Token 请求头和前缀：默认 `authorization`、`Bearer `，前缀后的空格需要保留。禁止 Host、Cookie、Origin 等请求控制头。
- 用户映射：用户对象路径，以及相对于该对象的 ID、显示名称路径。用户对象留空表示整个响应。用户 ID 必须有效且不能是内部管理员身份。
- 角色映射：可选角色字段（相对于用户对象，支持字符串或字符串数组），以及管理员角色 JSON 字符串数组，例如 `["admin","superadmin"]`。区分大小写、精确匹配任一配置角色才授予管理权限；留空默认不授予，缺失或类型无效的角色按普通用户处理。
- 响应规则：允许的 2xx HTTP 状态码，可选成功字段/期望值、过期标志字段/过期值、过期时间字段及秒/毫秒/ISO 格式。响应规则的路径均相对于响应根节点；比较值使用 JSON 基本类型，严格区分 `0` 与 `"0"`。
- 检查间隔和超时：默认 30 秒复查、10 秒超时，可在面板调整。

例如接口返回：

```json
{
  "code": 0,
  "expired": false,
  "expiresAt": 4102444800,
  "data": { "uid": "example-user", "displayName": "示例用户" }
}
```

可配置用户对象 `data`、ID `uid`、名称 `displayName`，成功字段 `code` 等于 `0`，过期字段 `expired` 等于 `true` 时拒绝，过期时间字段 `expiresAt` 采用 Unix 秒。配置了某个检查字段后，响应缺少该字段也会被拒绝。所有检查均需通过，401/403 或其他未允许状态、非 JSON、重定向、接口故障、过期及无效身份均不授予访问。

浏览器只提交 Token，身份由服务端接口响应决定。原始 Token 仅保留在原浏览器存储和服务端内存，不写入配置、日志或 Harness Cookie；Cookie 中只包含签名身份及随机会话 ID。管理员权限仅来自管理员明确配置的角色映射，不接受浏览器提交的角色。

**Cookie 与 Token 同步失效：** 接口提供过期时间时，Harness Cookie 的签名过期时间和 Max-Age 都不会超过它；登录后继续按检查间隔复查，复查失败即撤销服务端会话并断开连接。浏览器轮询登录状态时会收到清除 Cookie 的响应，并回到登录页。如果仅通过接口的布尔值/业务码判断失效，识别延迟受检查间隔和请求超时限制。浏览器离线时服务端无法主动删除浏览器文件中的 Cookie，但已撤销会话不能再用于访问，恢复请求时会清除 Cookie。

浏览器在后台监听 Token 替换或移除；普通用户没有本地改密和退出按钮，应由业务系统更新/清除其 Token。`localStorage` 可在同源标签页共享；`sessionStorage` 仅属于当前标签页，新开标签页不会自动继承。隐私设置阻止存储读取时，页面显示错误并保留本地管理员登录入口。

例如用户对象为 `data`，接口返回 `data.roles: ["member", "admin"]`，配置角色字段 `roles`、管理员角色 `["admin"]`，该用户即可看到“用户与认证”面板并管理认证与插件。Token 管理员沿用接口用户 ID，仍只访问自己的会话和工作区，不复用本地 admin 的身份。密码由业务系统管理，不显示本地改密功能；本地管理员账号和 `login?admin=1` 恢复入口保持可用。

定期复查发现管理员身份改变（包括角色被撤销或新获管理员权限）时，会撤销旧会话并断开连接，浏览器清除 Cookie 后重新验证，以新权限进入。不会等待旧 Cookie 自然过期。

Token 会话不持久化；重启或切换配置后，需要从浏览器存储重新验证。无活动的内存会话会清理。浏览器同源脚本本来就能读取这些存储，因此同源部署中的各应用必须互信。

## 日常管理

“允许普通用户登录”关闭后仅允许管理员登录，不开放匿名访问。它与停用整个插件是两个独立操作。

本地密码只保存 scrypt 哈希。普通用户自助修改密码需要验证当前密码，新密码至少十二位；成功后旧 Cookie 和已有连接失效，返回登录页使用新密码登录。忘记当前密码时由管理员重置。静态配置中的账号仍在原配置中管理，不显示自助改密入口。

管理员可点击侧栏底部“修改密码”，验证当前密码后设置至少十二位的新密码。成功后旧管理员 Cookie 和连接失效，初始密码文件删除，新密码只保存哈希；更换认证模式不影响此入口。

管理员 Cookie 默认七天，Local/HTTP 普通用户默认七天，可调整 `cookieMaxAgeDays`。正常访问不续期，重新登录重新计时。退出登录清除当前浏览器的插件 Cookie 和原生 Cookie；其他设备不会因一次退出自动注销。管理员重置或用户修改密码则会使该用户旧登录凭据失效。

## 普通用户工作目录

管理员可在面板设置“普通用户工作目录根目录”。填写运行 Harness 的服务器上可读写的绝对路径；留空使用默认 `<DSH_HOME>/web-users`。例如 `/srv/harness-users` 只是一个可替换的路径示例，不是安装要求。

每个用户在根目录下拥有 `u-<base64url(userId)>` 子目录。保存前校验目录权限、敏感目录边界和根目录嵌套关系；保存后立即生效并重启保留。

切换根目录不会自动搬迁旧文件，也不会修改管理员工作目录。历史根目录记录在 `workspaceRootHistory`，旧会话和工作区继续按用户归属隔离可用。需要移动文件时，请单独安排数据迁移。

## 原生插件面板与隔离范围

管理员和普通用户使用 Harness 原生插件面板。普通用户可以查看、安装、启停和卸载其他插件；认证插件及基础服务的修改受限制，账号和认证管理面板仅管理员可用。普通用户安装前需解析出真实包名，不能替换认证包或基础包；Git/压缩包等无法确认包名的来源由管理员安装。

插件操作影响整个实例。安装插件可加载服务器端代码，因此此权限仅适合受信任用户。

会话与工作区采用应用层权限隔离，管理员也不能通过插件权限直接读取其他用户的会话。它不是操作系统隔离：能够运行任意代码或读取同一系统账号文件的用户，可能读取密钥或改动配置。需要隔离不可信用户时，应采用独立系统账号或容器等边界。

## 安全停用与卸载

管理员在原生插件详情或“用户与认证”中使用“安全停用 / 卸载认证插件”：

1. 确认本地账号登录、用户隔离和管理面板将停止，改由具有全实例权限的 Harness 原生管理员接管。
2. 点击“准备并验证原生登录”。插件通过 Harness 自身接口给当前浏览器建立原生 HttpOnly Cookie，不显示或返回启动 token。
3. 浏览器通过独立请求回传并验证 Cookie，成功后才能选择“停用并继续访问”或“卸载并继续访问”。
4. 完成后跳回原入口。若宿主要求重启，会明确提示。

直接使用原生总开关或停用接口会提示先完成安全流程。交接要求管理员登录、同源、CSRF 和影响确认；普通用户不能使用。Cookie 被拒绝、Host 不可信或宿主接口不兼容时，不执行停用。

原生凭据只对完成交接的浏览器有效，有效期由 Harness 配置决定；清除 Cookie、过期或换设备后仍需 Harness 启动输出的原生登录链接。取消停用会保留插件运行。

## 数据与配置

以下为默认位置，均相对于该实例的 `DSH_HOME`；`stateDir`、`local.usersFile` 和工作目录可另行配置。

| 相对路径 | 用途 |
|---|---|
| `web-admin/credentials.json` | 管理员账号和密码哈希 |
| `web-admin/initial-password.txt` | 首次生成的管理员密码；管理员修改密码后删除 |
| `web-admin/secret` | 管理员 Cookie 签名密钥 |
| `web-admin/auth-settings.json` | 面板保存的认证、有效期、目录设置及历史根目录；权限 0600 |
| `web-user-auth/users.json` | 本地普通用户、密码哈希和密码变更时间 |
| `web-user-auth/secret` | 普通用户 Cookie 签名密钥 |
| `web-users/` | 默认工作目录父目录 |

面板保存的设置优先于 profile 对应字段。配置定义见 `lib/config.js` 和 `lib/plugin.js` 的 `normalizeConfig()`；内部保存的历史归属信息不应随意删除。

## 管理员忘记密码：服务器端重置

此操作不需要旧密码或浏览器登录，但需要服务器文件权限。请使用拥有该实例数据文件的系统账号执行，需要 Python 3（仅使用标准库）。

1. 停止对应的 Harness 实例，避免旧连接继续使用，同时避免与界面改密并发。
2. 在插件安装目录执行：

   ```sh
   python3 scripts/reset-admin-password.py
   ```

   默认使用 `DSH_HOME`；未设置时使用当前系统账号的 `~/.deepseek-harness`。自定义应用数据目录时显式指定：

   ```sh
   python3 /absolute/path/to/plugin/scripts/reset-admin-password.py \
     --home /absolute/path/to/harness-data
   ```

3. 根据终端提示输入两次新密码，至少十二位。输入不会回显；不要把密码写进命令行参数。
4. 重新启动对应实例，通过 `<BASE_URL>login` 使用原管理员用户名和新密码登录。

脚本先备份管理员凭据，使用 scrypt 保存新密码哈希，原子替换文件并设置权限 0600；更新密码变更时间以拒绝旧插件管理员 Cookie，删除过时的初始密码文件。不会打印新密码，也不会修改普通用户、工作目录、认证模式、原生 token 或签名密钥。备份含旧密码哈希，需按敏感配置文件保管；不要直接回滚旧凭据文件，以免恢复旧密码及旧会话有效性。

重置作用于所选 `DSH_HOME` 的插件管理员：多个 profile 共享该数据目录时，也共享该管理员凭据。脚本不会自动启用已停用的插件；如需恢复插件登录入口，再按下文运行配置恢复脚本并重启。如果使用 Header 模式且被外层代理拦截，还需处理代理层的访问问题。

自动化可显式使用 `--password-stdin` 从受保护的标准输入读取密码；交互使用推荐默认的隐藏输入方式。

## 应急恢复

如果已经停用插件，请先使用 Harness 启动输出的原生登录链接访问。不要通过关闭宿主认证来恢复。

若插件仍安装但错误配置导致无法登录，可以在服务器上运行安装包中的恢复脚本：

```sh
# 以下占位路径、应用数据目录和 profile 均须替换为自己的实际值。
python3 /absolute/path/to/plugin/scripts/recover-auth.py \
  --home /absolute/path/to/harness-data \
  --profile web
```

脚本会先备份配置，重新选中已安装的认证插件，并恢复“仅本地管理员登录”。它不安装依赖、不移动工作文件、不重置密码。随后按自己的进程管理方式重启对应实例。执行恢复的系统账号需拥有该实例配置目录的读写权限。

## 源码与测试

`index.js` 是宿主入口，`lib/client.js` 通过 Harness 插槽提供原生界面；测试保存在源码目录的 `test/` 中，不包含在精简安装包中。

在源码目录执行：

```sh
node --test test/unit.test.js
```

## 许可证与贡献

本项目采用 [MIT License](LICENSE)。开发与测试方式见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全边界和私密漏洞报告方式见 [SECURITY.md](SECURITY.md)。
