# OptikLink-M

> OptikLink 面板的自动签到 + 服务器保活，跑在 GitHub Actions 上，躺平不用管。

## 它做什么

每 3 天一次（`cron: '0 1 */3 * *'`，UTC 01:00），这个 workflow 自动：

1. **通过 Discord OAuth 登录 OptikLink 面板** — 用你的 Discord 令牌完成授权
2. **过 Cloudflare Turnstile 验证** — OptikLink 新增的 Quick Verification 步骤（随机数学题 + Turnstile 复选框），用真实有头浏览器过掉
3. **签到确认** — 检查 Dashboard 页面，提取登录状态、用户名、到期时间
4. **服务器保活** — 面板服务器（Pterodactyl）处于离线状态时自动发送启动指令
5. **推送报告** — 登录结果通过 Telegram Bot 推送给你

## 代理出口（sing-box）

出口从 xray 换成了 **sing-box**（xray 不支持 AnyTLS，换节点的时候被卡住过）。

- 启动前自动下载最新版 sing-box，并校验 `>= 1.12.0`（anytls outbound 的最低要求）
- 生成的配置先过 `sing-box check` 再启动，配置错了会当场报错而不是静默连不上
- 支持的节点链接：
  - `anytls://<密码>@服务器:端口/?sni=..&insecure=1`
  - `vless://<uuid>@服务器:端口?security=tls|reality&type=ws|grpc|httpupgrade|tcp&...`
- **出口预检**：启动后先请求一次 `optiklink.net/home`，如果出口 IP 被站点的 Cloudflare 整段拉黑（403），当场报错并提示换节点 —— 不再是莫名其妙的「Dashboard 未识别为登录状态」

## 文件结构

| 文件 | 用途 |
|---|---|
| `optiklink_login.py` | 主脚本：登录、过 Turnstile、签到、服务器保活、TG 推送 |
| `generate_singbox_config.py` | 从节点分享链接（anytls / vless）生成 sing-box 配置 |
| `test_discord.py` | 调试工具：测试 Discord API 授权参数是否有效 |
| `time.txt` | 每次运行自动更新时间戳，保持仓库活跃 |
| `.github/workflows/optiklink.yml` | GitHub Actions 工作流定义 |

## 部署

### 1. Fork 这个仓库

点右上角 Fork。

### 2. 配置 Secrets

去 Settings → Secrets and variables → Actions → New repository secret，添加以下内容：

| Secret | 说明 |
|---|---|
| `DISCORD_TOKEN` | 你的 Discord 用户令牌（`Authorization` header 值，`mfa.xxx` 格式） |
| `BOT_TOKEN` | Telegram Bot Token（从 [@BotFather](https://t.me/BotFather) 获取） |
| `CHAT_ID` | 接收推送的 Telegram 用户/群组 ID |
| `PROXY_LINK` | 代理节点分享链接（**anytls 节点填这个**；旧的 `VLESS_NODE` 变量名仍然兼容） |
| `PANEL_API_KEY` | （可选）Pterodactyl 面板 API Key，用于服务器保活 |
| `PANEL_SERVER_ID` | （可选）指定服务器 ID，不填则自动取第一个 |
| `EXPIRE_DATE` | （可选）手动指定到期日期作为后备 |
| `DISCORD_CLIENT_ID` | （可选）Discord OAuth client_id，脚本会从站点登录流自动探测 |
| `DISCORD_REDIRECT_URI` | （可选）Discord OAuth 回调地址 |

> 节点出口 IP 如果被 OptikLink 的 Cloudflare 拉黑（运行日志会明确写出来），换一个节点更新 `PROXY_LINK` 即可。

### 3. 启动 Workflow

- 默认每 3 天运行一次（`cron: '0 1 */3 * *'`）
- 也可以手动触发：Actions → OptikLink 每日自动登录+服务器保活 → Run workflow

## 依赖

全部由 workflow 自动安装，本地不用装：

- Python 3.12+
- `requests` — 第一阶段的 HTTP 登录（不用 cloudscraper：本站 CF 认得它的指纹反而 403，普通 requests + 浏览器 UA 能过盾）
- `seleniumbase` — 第二阶段浏览器过 Turnstile（UC 模式，内含 undetected-chromedriver）
- `xvfb` + Chrome 运行库（`libnss3` `libdrm2` `libxkbcommon0` `libgbm1` `libasound2t64` 等）— 给有头 Chrome 一个虚拟显示
- `sing-box` — 代理出口（workflow 里现下载二进制，要求 ≥ 1.12.0）

## 已知问题

- **Turnstile 令牌偶发拿不到就直接失败，没有重试。** Cloudflare 的风险评分每次不同，偶尔一次拿不到令牌就整次运行失败（`Turnstile 令牌未获取`），等 cron 下次补。
- **出口 IP 被站点拉黑时只能换节点。** OptikLink 的 Cloudflare 按 IP 段拦截，脚本层面无解；现在会预检并明确报错，而不是走到最后一步才报「Dashboard 未识别」。

## 免责声明

这个项目仅供学习和个人自动化使用。使用 Discord 用户令牌进行 OAuth 授权可能违反 Discord 服务条款，请自行评估风险。
