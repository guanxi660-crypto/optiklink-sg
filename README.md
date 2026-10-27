# OptikLink-M

> OptikLink 面板的自动签到 + 服务器保活，跑在 GitHub Actions 上，躺平不用管。

## 它做什么

每 3 天一次（`cron: '0 1 */3 * *'`，UTC 01:00），这个 workflow 自动：

1. **通过 Discord OAuth 登录 OptikLink 面板** — 用你的 Discord 令牌完成授权
2. **过 Cloudflare Turnstile 验证** — OptikLink 新增的 Quick Verification 步骤（随机数学题 + Turnstile 复选框），用真实有头浏览器过掉
3. **签到确认** — 检查 Dashboard 页面，提取登录状态、用户名、到期时间
4. **服务器保活** — 面板服务器（Pterodactyl）处于离线状态时自动发送启动指令
5. **推送报告** — 登录结果通过 Telegram Bot 推送给你

## 出口选择（直连优先）

**先试直连，直连不行才用代理。** GitHub 运行器在 Azure 美国，`optiklink.net` 对美/欧出口
基本都返回 200 —— 大部分情况下根本不需要代理，少一层就少一个故障点。

直连不通时，把 `PROXY_LINK` / `PROXY_LINK_BACKUP` 里的节点（**都支持多行，一行一个**）
逐个试，第一个全过的胜出。

支持的节点链接：

| 协议 | 格式 |
|---|---|
| anytls | `anytls://<密码>@host:port/?sni=..&insecure=1` |
| hysteria2 | `hysteria2://<密码>@host:port/?sni=..&insecure=1&obfs=salamander&obfs-password=..`（`hy2://` 也认） |
| vless | `vless://<uuid>@host:port?security=tls\|reality&type=ws\|grpc\|httpupgrade\|tcp&...` |

每个节点依次检查：

1. **端口探测**
   - TCP 类（anytls / vless）：`tcp_probe.py`，`REFUSED` = 服务没在监听，`TIMEOUT` = SYN 被丢
   - **UDP 类（hysteria2）：跳过 TCP 探测** —— hy2 走 QUIC/UDP，本来就不监听 TCP，
     拿 TCP 去探必然「不通」，会把好节点误杀。直接进下一步做端到端验证
2. **出站 + 站点**（`site_probe.py`）— 真发一个请求，同时拿到出口 IP 和站点响应分型：
   - `OK` / `CHALLENGE` → 可用（盾页交给有头浏览器过）
   - `WAF_BLOCK` → 出口 IP 在 Cloudflare 黑名单里，换下一个
   - `UNREACHABLE` → 链路不通（密码 / SNI / TLS 参数不对）

全部不可用时**仍然直连跑一次**（curl 被拦 ≠ 浏览器被拦），只打 warning 不把 job 标红。

> **xhttp 传输用不了。** 它是 Xray 专属的，sing-box 不支持，链接里 `type=xhttp` 会被明确拒掉。

### ⚠️ 选节点看地区：香港、俄罗斯的 IP 被站点 WAF 拦

实测（check-host.net 多国探针）`optiklink.net/home`：

| 地区 | 结果 |
|---|---|
| 美 / 德 / 荷 / 意 / 西 / 葡 / 瑞典 / 乌克兰 / 伊朗 / 新加坡 / 土耳其 … | 200 |
| **香港** | **403 WAF 硬拦** |
| **俄罗斯** | **403 WAF 硬拦** |

所以节点别选香港和俄罗斯的机房，白费。

> ⚠️ **别在自己机器上验证节点死活。** 本机开着 TUN/系统代理时，任何 TCP 连接测试都会被
> 本地代理**假成功**——连 `192.0.2.1:443`（保留段，必然不可达）都能 14ms 握手成功。
> 判节点死活要么看 Actions 日志，要么用外部探针。



## 文件结构

| 文件 | 用途 |
|---|---|
| `optiklink_login.py` | 主脚本：登录、过 Turnstile、签到、服务器保活、TG 推送 |
| `generate_singbox_config.py` | 从节点分享链接（anytls / vless）生成 sing-box 配置，支持多候选（`--count` / `--list` / `--index N`） |
| `tcp_probe.py` | 节点端口 TCP 探针，区分 `REFUSED` / `TIMEOUT` / `OK` |
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
| `PROXY_LINK` | 代理节点分享链接（**anytls 节点填这个**；旧的 `VLESS_NODE` 变量名仍然兼容）。**可以多行**，一行一个节点 |
| `PROXY_LINK_BACKUP` | （可选）备用节点，同样支持多行。和 `PROXY_LINK` 合并去重后一起参与自动选优 |
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
- `sing-box` — 代理出口（workflow 里现下载二进制，要求 ≥ 1.12.0；官方 release 自带 QUIC 支持，hysteria2 可直接用）

## 已知问题

- **Turnstile 令牌偶发拿不到就直接失败，没有重试。** Cloudflare 的风险评分每次不同，偶尔一次拿不到令牌就整次运行失败（`Turnstile 令牌未获取`），等 cron 下次补。
- **出口 IP 被站点拉黑时只能换节点。** OptikLink 的 Cloudflare 按 IP 段拦截，脚本层面无解；现在会在选节点阶段就自动跳过这种节点（不会白跑一整轮）。
- **节点端口会悄悄消失。** 免费节点的 anytls 端口经常直接关掉，症状是 sing-box 报
  `failed to create session: dial tcp x.x.x.x:PORT: connect: connection refused`。
  这不是配置错，是服务端没在监听。多填几个 `PROXY_LINK_BACKUP` 就能自愈。

## 排查速查表

| 日志现象 | 含义 | 怎么办 |
|---|---|---|
| `① TCP: REFUSED` | 节点端口没有服务在监听 | 换节点（端口变了或节点下线） |
| `① TCP: TIMEOUT` | SYN 被丢，防火墙/路由不通 | 换节点 |
| `① TCP: 跳过` | hysteria2 节点，走 UDP | 正常，看下一步结果 |
| `判定: UNREACHABLE` | TCP 通但握手/转发失败 | 检查密码 / sni / insecure 参数 |
| `判定: WAF_BLOCK` | 出口 IP 在 Cloudflare 黑名单里 | 换地区（别用香港、俄罗斯） |
| `判定: CHALLENGE` | Cloudflare JS 盾页 | 正常，交给浏览器过 |
| `不支持的协议` | 链接协议不在 anytls / hysteria2 / vless 里 | 换节点 |
| `xhttp 是 Xray 专属传输` | sing-box 不支持 xhttp | 换节点（ws / grpc / httpupgrade） |
| `没有可用出口` | 直连 + 全部节点都没过探测 | 换节点；仍会用直连跑一次 |

## 免责声明

这个项目仅供学习和个人自动化使用。使用 Discord 用户令牌进行 OAuth 授权可能违反 Discord 服务条款，请自行评估风险。
