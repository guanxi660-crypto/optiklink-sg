#!/usr/bin/env python3
"""
OptikLink 自动登录脚本 v4.3-fixed（仅必要修复版）
- 修复 Discord 授权参数（使用硬编码后备值）
- 增加 /error/vpn 检测
- 增加 Quick Verification 处理（SeleniumBase UC 模式浏览器过 Turnstile）
- 保持原始 Dashboard 判断逻辑不变
- 到期时间自动从页面提取
"""

import os
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode

import requests as _req

# 不用 cloudscraper：实测本站 Cloudflare 认得它的指纹、见到就 403，
# 而普通 requests + 浏览器 UA 走正常节点能直接过盾

# ─────────────────────────────────────────────────────────────
# 配置（环境变量）
# ─────────────────────────────────────────────────────────────
def env(name: str, default: str = "") -> str:
    """读环境变量。**空串视为未设置**。

    旧写法 os.environ.get(name, default) 在 Actions 里给 Secret 赋空值时会拿到 ""
    而不是 default，导致后面的默认值永远不生效。
    """
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()

DISCORD_TOKEN       = env("DISCORD_TOKEN")
TG_BOT_TOKEN        = env("BOT_TOKEN")
TG_CHAT_ID          = env("CHAT_ID")
EXPIRE_DATE_RAW     = env("EXPIRE_DATE")
# 下面两个默认值是从站点真实登录流实测抓的（GET /login → 302 discordapp.com/...），
# 旧默认 1005764586547838976 / optiklink.net/callback 是错的
DISCORD_CLIENT_ID   = env("DISCORD_CLIENT_ID", "933437142254887052")
DISCORD_REDIRECT_URI = env("DISCORD_REDIRECT_URI", "https://optiklink.com/login")
DASHBOARD_URL       = env("DASHBOARD_URL", "https://optiklink.net/")
PANEL_URL           = env("PANEL_URL", "https://control.optiklink.net")
PANEL_API_KEY       = env("PANEL_API_KEY")
PANEL_SERVER_ID     = env("PANEL_SERVER_ID")
SERVER_START_WAIT   = int(env("SERVER_START_WAIT", "60"))
PROXY_URL           = env("PROXY_URL")
# workflow 里选路步骤写进 $GITHUB_ENV 的结果：direct / #2 / none
PROXY_NODE          = env("PROXY_NODE", "none")

# 硬编码后备参数（从成功的登录链接中提取）
FALLBACK_CLIENT_ID = "933437142254887052"
FALLBACK_REDIRECT_URI = "https://optiklink.com/login"
FALLBACK_SCOPE = "guilds guilds.join identify email"

HEADERS_BROWSER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
}

# ─────────────────────────────────────────────────────────────
# 工具函数
# ─────────────────────────────────────────────────────────────
def mask(value: str, keep: int = 4) -> str:
    if not value:
        return "***"
    if len(value) <= keep * 2:
        return "***"
    return value[:keep] + "***" + value[-keep:]

def mask_url(url: str) -> str:
    return re.sub(r'(code|token|access_token|refresh_token)=[^&]+', r'\1=***', url)

def url_host(url: str) -> str:
    return urlparse(url).netloc.lower()

def is_optiklink_host(url: str) -> bool:
    host = url_host(url)
    return host.endswith("optiklink.net") or host.endswith("optiklink.com")

# Cloudflare 两种拦截要区分对待：
#   硬拦（1020 WAF，IP 被拉黑）→ 等多久都没用，立刻失败并提示换节点
#   盾页（Just a moment）→ UC 模式大概率能自动过，等待重试
CF_HARD_BLOCK_MARKERS = (
    "sorry, you have been blocked",
    "attention required",
)
CF_CHALLENGE_MARKERS = (
    "just a moment",
    "enable javascript and cookies to continue",
    "checking your browser",
    "verify you are human",
)

def classify_cf_page(html: str) -> str:
    """返回 'hard' / 'challenge' / '' """
    low = (html or "").lower()
    if any(m in low for m in CF_HARD_BLOCK_MARKERS):
        return "hard"
    if any(m in low for m in CF_CHALLENGE_MARKERS):
        return "challenge"
    return ""

def create_session():
    """普通 requests 会话 + 代理 + 浏览器 UA。

    不用 cloudscraper（实测会被本站 Cloudflare 识别成 403），
    节点正常时普通 requests 直接过盾。
    """
    sess = _req.Session()
    if PROXY_URL:
        sess.proxies = {"http": PROXY_URL, "https": PROXY_URL}
        print(f"[信息] 使用代理: {PROXY_URL}（选路结果 {PROXY_NODE}）")
    else:
        print(f"[信息] 直连（无代理，选路结果 {PROXY_NODE}）")
    sess.headers.update(HEADERS_BROWSER)
    return sess

_tg_session = None

def tg_send(title: str, content: str):
    """发送 Telegram 消息（Markdown），带自动重试（3次）"""
    global _tg_session
    if _tg_session is None:
        _tg_session = _req.Session()
        _tg_session.headers.update({"Content-Type": "application/json"})

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    text = f"*{title}*\n\n{content}"
    payload = {"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "Markdown", "disable_web_page_preview": True}

    for attempt in range(3):
        try:
            resp = _tg_session.post(url, json=payload, timeout=15)
            result = resp.json()
            if result.get("ok"):
                print(f"[Telegram] 推送成功 | chat_id={mask(TG_CHAT_ID)}")
                return
            print(f"[Telegram] 推送失败: {result.get('description', 'unknown')}")
        except Exception as e:
            print(f"[Telegram] 请求异常 (第{attempt+1}次): {e}")
        if attempt < 2:
            time.sleep(2)
    print("[Telegram] 推送最终失败（重试耗尽）")

# ─────────────────────────────────────────────────────────────
# 登录核心流程
# ─────────────────────────────────────────────────────────────
def discover_oauth_params(session):
    """从站点真实登录流探测 OAuth 参数。

    旧版探测 GET /auth —— 那是个纯营销页，根本没有 Discord 链接，所以探测从来
    没成功过，全靠硬编码兜底。真实入口是 /login：它 302 到 login?action=login，
    再 302 到 discord 的 authorize URL（client_id/redirect_uri/scope 全在里面）。
    这里手动跟跳（最多 5 跳），停在第一个 discord 授权 URL 上解析参数。
    """
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "guilds guilds.join identify email",
        "prompt": "none",
    }
    print("[A] 探测 OAuth 参数（走真实登录流 /login）...")
    url = "https://optiklink.net/login"
    discord_url = ""
    try:
        for hop in range(5):
            r = session.get(url, timeout=15, headers=HEADERS_BROWSER, allow_redirects=False)
            print(f"    [{hop}] {mask_url(url)} -> {r.status_code}")
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                nxt = r.headers["Location"]
                if not nxt.startswith("http"):
                    from urllib.parse import urljoin
                    nxt = urljoin(url, nxt)
                if "discordapp.com" in nxt or "discord.com" in nxt:
                    discord_url = nxt
                    break
                url = nxt
                continue
            # 非跳转响应：看看页面里有没有现成的 discord 授权链接（万一以后改版）
            m = re.search(r'https?://(?:discordapp\.com|discord\.com)/api?/?oauth2/authorize[^\s\'"<>\\]+', r.text)
            if m:
                discord_url = m.group(0).replace("&amp;", "&")
            break
    except Exception as e:
        print(f"    ⚠️ 探测失败（{e}），用默认参数兜底")

    if discord_url:
        qs = parse_qs(urlparse(discord_url).query)
        for k in ("client_id", "redirect_uri", "scope", "state", "prompt"):
            if qs.get(k):
                params[k] = qs[k][0]
        print(f"    ✅ 探测成功 client_id={mask(params['client_id'])} redirect_uri={params['redirect_uri']}")
        # client_id 真的变了才写输出，供后续步骤感知（别再把没变化的也写一遍）
        if params["client_id"] != DISCORD_CLIENT_ID:
            print(f"    client_id 变更: {mask(DISCORD_CLIENT_ID)} → {mask(params['client_id'])}")
            github_output = os.environ.get("GITHUB_OUTPUT")
            if github_output:
                with open(github_output, "a") as f:
                    f.write(f"new_client_id={params['client_id']}\n")
    else:
        print(f"    ⚠️ 未能探测到，使用默认参数 client_id={mask(params['client_id'])}")
    return params

def discord_authorize(session, oauth_params):
    """Discord授权 - 使用探测参数或硬编码后备值"""
    print("[B] Discord 授权...")
    
    # 优先使用探测到的参数，如果无效则使用硬编码后备值
    client_id = oauth_params.get("client_id") or FALLBACK_CLIENT_ID
    redirect_uri = oauth_params.get("redirect_uri") or FALLBACK_REDIRECT_URI
    scope = oauth_params.get("scope") or FALLBACK_SCOPE
    
    if oauth_params.get("client_id"):
        print(f"    [来源: 自动探测]")
    else:
        print(f"    [来源: 硬编码后备]")
    
    print(f"    client_id: {mask(client_id)}")
    print(f"    redirect_uri: {redirect_uri}")
    
    post_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
    }
    if "state" in oauth_params:
        post_params["state"] = oauth_params["state"]
    
    headers = {
        "Authorization": DISCORD_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": HEADERS_BROWSER["User-Agent"],
        "Referer": "https://discord.com/oauth2/authorize?" + urlencode(post_params),
        "X-Super-Properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIn0=",
    }

    # 401/5xx 偶发出现（Discord 风控抖动，实测同一 token 同参数隔 2 小时重试就 200），
    # 之前一次失败直接把整轮跑废，这里加重试
    r = None
    for attempt in range(1, 4):
        try:
            r = session.post("https://discord.com/api/v10/oauth2/authorize",
                             params=post_params,
                             json={"authorize": True, "permissions": "0"},
                             headers=headers, timeout=15, allow_redirects=False)
        except Exception as e:
            print(f"    Discord 请求异常 (第{attempt}次): {e}")
            r = None
        status = r.status_code if r is not None else 0
        print(f"    Discord 状态: {status}" + (f" (第{attempt}次)" if attempt > 1 else ""))

        if status == 200:
            try:
                data = r.json()
                if "location" in data:
                    return data["location"]
            except Exception:
                pass
        if status in (301, 302, 303, 307, 308) and "Location" in r.headers:
            return r.headers["Location"]
        if status == 401:
            print("    ⚠️ 401 通常是 Discord 临时风控（token 未失效），稍后重试")
        if status not in (401, 429) and status < 500:
            break                      # 参数类错误重试也没用，直接失败
        if attempt < 3:
            time.sleep(3)

    raise RuntimeError(f"Discord 授权失败 HTTP {r.status_code if r is not None else 0}")

# ─────────────────────────────────────────────────────────────
# 浏览器登录 + Quick Verification
# ─────────────────────────────────────────────────────────────
# /login?code= 现在会先返回 Quick Verification 页面：随机数学题 + 真实
# Cloudflare Turnstile（managed 模式，服务端校验 cf-turnstile-response）。
# 纯 HTTP 造不出令牌；无头浏览器也会被拦（自动化指纹，实测令牌始终为空）。
# 必须真实有头浏览器 + OS 级鼠标点击，所以这一步用 SeleniumBase UC 模式。
# math_answer 和 cf-turnstile-response 都正确才会放行。
# 算式是多操作数链（实测 "2 + 2 + 1"），只取前两个数会把答案算错
VERIFY_STRONG_RE = re.compile(r'<strong[^>]*>([^<]*)</strong>', re.I)
VERIFY_TEXT_RE = re.compile(r'What\s+is\s+([0-9+\-×*/÷\s]+?)\s*\?', re.I)
MATH_TOKEN_RE = re.compile(r'\d+|[+\-×*/÷]')
TURNSTILE_TOKEN_JS = (
    'var e=document.querySelector(\'input[name="cf-turnstile-response"]\');'
    'return e ? String(e.value) : "";'
)
MATH_VALUE_JS = (
    'var e=document.querySelector(\'input[name="math_answer"]\');'
    'return e ? String(e.value) : "";'
)

def set_math_answer(sb, answer):
    """填数学答案并读回确认。
    update_text 偶尔填不进去，表面看不出——提交后才被服务端判成 wrong_answer。
    读回不一致就 JS 直设 value 兜底；仍不一致则抛真错误，别等到提交才知道。
    """
    want = str(answer)
    sb.update_text('input[name="math_answer"]', want)
    got = sb.execute_script(MATH_VALUE_JS)
    if got != want:
        js = (
            'var e=document.querySelector(\'input[name="math_answer"]\');'
            'e.value="' + want + '";'
            'e.dispatchEvent(new Event("input",{bubbles:true}));'
        )
        sb.execute_script(js)
        time.sleep(1)
        got = sb.execute_script(MATH_VALUE_JS)
    print(f"    答案填入读回: {got}")
    if got != want:
        raise RuntimeError(f"数学答案未填入（期望 {want}，实际 {got!r}）")

def sb_proxy():
    """requests 用的 socks5h:// 换成 Chrome --proxy-server 认识的 socks5://"""
    return PROXY_URL.replace("socks5h://", "socks5://") or None

def solve_math(a, op, b):
    a, b = int(a), int(b)
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op in ("*", "×"):
        return a * b
    if op in ("/", "÷"):
        return a // b   # 题面限制 0..100，整除即可
    raise ValueError(f"未知运算符 {op}")

def read_math_question(html):
    """取出算式原文。<strong> 整段优先，纯文本兜底。"""
    m = VERIFY_STRONG_RE.search(html) or VERIFY_TEXT_RE.search(re.sub(r'<[^>]+>', ' ', html))
    if not m:
        raise RuntimeError("验证页未找到数学题")
    return re.sub(r'\s+', ' ', m.group(1)).strip()

def solve_math_expr(expr):
    """按出现顺序左到右求值：'2 + 2 + 1' → 5。单步运算复用 solve_math。"""
    tokens = MATH_TOKEN_RE.findall(expr)
    if len(tokens) < 3 or not tokens[0].isdigit():
        raise ValueError(f"算式不完整: {expr!r}")
    acc = int(tokens[0])
    i = 1
    while i < len(tokens):
        if tokens[i].isdigit() or i + 1 >= len(tokens) or not tokens[i + 1].isdigit():
            raise ValueError(f"算式不完整: {expr!r}")
        acc = solve_math(acc, tokens[i], int(tokens[i + 1]))
        i += 2
    return acc

def browser_login(callback_url):
    """浏览器打开回调链接、解掉 Quick Verification，返回 (首页HTML, 最终URL)"""
    try:
        from seleniumbase import SB
    except ImportError:
        raise RuntimeError("缺少 seleniumbase：pip install seleniumbase（并需本机装有 Chrome）")
    print(f"[C] 浏览器登录: {mask_url(callback_url)}")

    # raise_test_failure=True：test 模式下 SB 默认吞掉块内异常（只打印 traceback），
    # 真错误会被换成 "cannot unpack non-iterable NoneType object"，TG 报告全是错的。
    kwargs = {"uc": True, "test": True, "locale": "en", "raise_test_failure": True}
    proxy = sb_proxy()
    if proxy:
        print(f"    代理: {proxy}")
        kwargs["proxy"] = proxy

    with SB(**kwargs) as sb:
        # ── 打开回调页，并确认页面真的加载了 ──
        # 上次失败的表象是「URL 一动不动、没有数学题」：浏览器被站点 Cloudflare 403
        # 拦死，老代码不做加载校验就静默落到 dashboard 检查，报了个误导性的错误。
        opened = False
        for attempt in range(1, 4):
            sb.uc_open_with_reconnect(callback_url, reconnect_time=5.0)
            time.sleep(3)
            cur = sb.get_current_url()
            kind = classify_cf_page(sb.get_page_source())
            if kind == "hard":
                raise RuntimeError(
                    "站点 Cloudflare 硬拦截（WAF 1020）：出口 IP 被拉黑，"
                    "脚本无解，换节点后更新 PROXY_LINK secret"
                )
            if is_optiklink_host(cur):
                opened = True
                break
            print(f"    ⚠️ 第 {attempt} 次打开未落到 OptikLink 页面: {mask_url(cur)}")
            if kind == "challenge":
                print("    Cloudflare 盾页，等 UC 过盾...")
                time.sleep(8)
        if not opened:
            raise RuntimeError(
                f"回调页打开失败（URL 未落到 OptikLink 域）: {mask_url(sb.get_current_url())}"
            )

        # ── Quick Verification（数学题 + Turnstile），令牌拿不到就重载重试 ──
        for attempt in range(1, 4):
            if not sb.is_element_present('input[name="math_answer"]'):
                break          # 没有验证页，登录已直接完成
            print(f"[C2] Quick Verification（第 {attempt} 次）...")

            expr = read_math_question(sb.get_page_source())
            answer = solve_math_expr(expr)
            print(f"    题目 {expr} = {answer}")

            set_math_answer(sb, answer)
            sb.execute_script("document.querySelector('.cf-turnstile').scrollIntoView({block:'center'})")
            time.sleep(1)
            sb.uc_gui_click_captcha()

            token = ""
            for _ in range(10):
                time.sleep(4)
                token = sb.execute_script(TURNSTILE_TOKEN_JS)
                if len(token) > 50:
                    break
            if len(token) <= 50:
                # README 已知问题：令牌偶发拿不到。重载验证页重试（题目会变，循环会重读）
                print("    ⚠️ Turnstile 令牌未获取，重载验证页重试")
                sb.uc_open_with_reconnect(sb.get_current_url(), reconnect_time=4.0)
                time.sleep(3)
                continue
            print(f"    Turnstile 令牌长度 {len(token)}，提交中...")
            # 错误页把「答案错」和「令牌被拒」混在同一页面，提交前再读一次答案好区分
            before = sb.execute_script(MATH_VALUE_JS)
            if before != str(answer):
                print(f"    ⚠️ 提交前答案已不是 {answer}: {before!r}")

            sb.click('button[type="submit"]')
            time.sleep(3)
        else:
            if sb.is_element_present('input[name="math_answer"]'):
                raise RuntimeError("Quick Verification 三次未通过（Turnstile 令牌/答案问题）")

        final_url = sb.get_current_url()
        print(f"    验证后URL: {mask_url(final_url)}")
        if '/error/vpn' in final_url:
            raise RuntimeError("访问被拦截 (VPN error page)")
        if '/error/' in final_url:
            raise RuntimeError(f"登录失败: {final_url}")
        # code 没被消费 = 登录没完成，别带着无效会话去做后面的 dashboard 判断
        if "/login" in final_url and "code=" in final_url:
            raise RuntimeError(
                "登录未完成：浏览器仍停在 /login?code= 回调页（code 交换失败或页面被拦截）"
            )

        sb.open(DASHBOARD_URL)
        sb.wait_for_ready_state_complete()
        time.sleep(2)
        return sb.get_page_source(), sb.get_current_url()

def check_dashboard_html(html, final_url):
    """登录态判断。

    老逻辑就一句 `"DASHBOARD" in html.upper()`，而未登录的营销首页本来就带
    "Go to Dashboard"，等于永远为真 —— 之前能"成功"纯属巧合。这里改成
    逐级信号：欢迎语 > 登出链接 > Dashboard 字样（且排除 Go to Dashboard），
    并记录命中的信号，误判时日志里能看到依据。
    """
    info = {
        "logged_in": False, "username": "N/A", "expire_date": EXPIRE_DATE_RAW,
        "running_servers": "N/A", "signal": "", "reason": "",
    }

    # 硬条件：最终页面必须落在 OptikLink 域名下（被 403 拦截时不是）
    if not is_optiklink_host(final_url):
        info["reason"] = f"最终页面不在 OptikLink 域名下: {url_host(final_url) or '(空)'}"
        print(f"    ❌ {info['reason']}")
        return info
    if "/error/" in final_url:
        info["reason"] = f"落在错误页: {mask_url(final_url)}"
        print(f"    ❌ {info['reason']}")
        return info

    # 信号 1：欢迎语（最具体，未登录页面不可能有）
    m = re.search(r'Welcome\s+<[^>]+>([^<]+)</[^>]+>\s+to your Dashboard', html, re.I)
    if m:
        info.update(logged_in=True, username=m.group(1), signal="欢迎语")
    else:
        # 信号 2：登出/退出链接（登录态才有）
        if re.search(r'\blog\s?out\b|\bsign\s?out\b|退出登录|登出', html, re.I):
            info.update(logged_in=True, signal="登出链接")
        else:
            # 信号 3：Dashboard 字样，但必须排除未登录首页那个 "Go to Dashboard"
            has_dash = "DASHBOARD" in html.upper()
            has_goto = re.search(r'Go\s+to\s+Dashboard', html, re.I)
            if has_dash and not has_goto:
                info.update(logged_in=True, signal="Dashboard 字样（无 Go to）")

    if info["logged_in"]:
        print(f"    ✅ 登录态确认（信号: {info['signal']}）")
        m2 = re.search(r'(\d+)\s+servers?', html, re.I)
        if m2:
            info["running_servers"] = m2.group(1)
        m3 = re.search(r'(\d{2}\.\d{2}\.\d{4})', html)
        if m3:
            info["expire_date"] = m3.group(1)
            print(f"    提取到期日期: {info['expire_date']}")
    else:
        # 都没命中，把页面实际内容记下来，别再让失败原因成谜
        title = re.search(r'<title[^>]*>([^<]*)</title>', html, re.I)
        title = title.group(1).strip() if title else "(无 title)"
        goto_note = "有 Go to Dashboard" if re.search(r'Go\s+to\s+Dashboard', html, re.I) else "无 Go to Dashboard"
        info["reason"] = (
            f"页面无登录信号（title={title!r}, {goto_note}, "
            f"url={mask_url(final_url)}）—— 大概率仍是未登录状态"
        )
        print(f"    ❌ {info['reason']}")
    return info

# ─────────────────────────────────────────────────────────────
# 服务器保活（Pterodactyl）
# ─────────────────────────────────────────────────────────────
def panel_headers():
    return {"Authorization": f"Bearer {PANEL_API_KEY}", "Accept": "application/json"}

def get_server_identifier(session):
    if PANEL_SERVER_ID:
        return PANEL_SERVER_ID
    r = session.get(f"{PANEL_URL}/api/client", headers=panel_headers(), timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"获取服务器列表失败 HTTP {r.status_code}")
    servers = r.json().get("data", [])
    if not servers:
        raise RuntimeError("无服务器")
    return servers[0]["attributes"]["identifier"]

def get_server_status(session, identifier):
    r = session.get(f"{PANEL_URL}/api/client/servers/{identifier}/resources",
                    headers=panel_headers(), timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"状态查询失败 HTTP {r.status_code}")
    return r.json()["attributes"]["current_state"]

def send_power_action(session, identifier, action):
    r = session.post(f"{PANEL_URL}/api/client/servers/{identifier}/power",
                     headers=panel_headers(), json={"signal": action}, timeout=15)
    if r.status_code not in (200,204):
        raise RuntimeError(f"电源指令失败 HTTP {r.status_code}")

def check_and_start_server(session):
    result = {"skipped": True, "server_id": "", "status_before": "unknown", "status_after": "unknown", "action_taken": "none"}
    if not PANEL_API_KEY:
        return result
    result["skipped"] = False
    try:
        identifier = get_server_identifier(session)
        result["server_id"] = identifier
        status = get_server_status(session, identifier)
        result["status_before"] = status
        if status.lower() == "offline":
            send_power_action(session, identifier, "start")
            result["action_taken"] = "start"
            deadline = time.time() + SERVER_START_WAIT
            while time.time() < deadline:
                time.sleep(5)
                new_status = get_server_status(session, identifier)
                if new_status.lower() in ("starting", "running"):
                    result["status_after"] = new_status
                    break
            else:
                result["status_after"] = get_server_status(session, identifier)
        else:
            result["status_after"] = status
    except Exception as e:
        result["error"] = str(e)
    return result

# ─────────────────────────────────────────────────────────────
# 构建简洁报告
# ─────────────────────────────────────────────────────────────
def build_report(info, server_result):
    now = datetime.now(timezone.utc)
    status = "✅ 登录成功" if info["logged_in"] else "❌ 登录失败"
    days_left = "N/A"
    try:
        expire = datetime.strptime(info["expire_date"], "%d.%m.%Y").replace(tzinfo=timezone.utc)
        days_left = str((expire - now).days)
    except:
        pass

    lines = [
        f"## OptikLink 自动登录报告",
        f"**状态**: {status}",
        f"**用户名**: {info['username']}",
        f"**运行服务器**: {info['running_servers']} 个",
        f"**服务到期**: {info['expire_date']}",
        f"**剩余天数**: {days_left} 天",
        f"**出口**: {PROXY_NODE if PROXY_URL else '直连'}",
        f"**执行时间**: {now.strftime('%Y-%m-%d %H:%M:%S')} UTC",
    ]
    if not server_result.get("skipped"):
        if "error" in server_result:
            lines.append(f"**服务器保活**: ❌ {server_result['error'][:100]}")
        else:
            lines.append(f"**服务器ID**: {server_result['server_id']}")
            lines.append(f"**启动前状态**: {server_result['status_before']}")
            lines.append(f"**启动后状态**: {server_result['status_after']}")
            if server_result['action_taken'] == 'start':
                lines.append("**操作**: ▶️ 已自动启动")
    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────
# 主函数（含重试逻辑）
# ─────────────────────────────────────────────────────────────
def main():
    print("="*55)
    print("OptikLink 自动登录 v6.1 (sing-box 代理 + 明确失败原因)")
    print("="*55)

    print("\n========== 开始执行 ==========")
    session = create_session()
    info = {"logged_in": False, "username": "N/A", "expire_date": EXPIRE_DATE_RAW, "running_servers": "N/A", "signal": "", "reason": ""}
    server_result = {"skipped": True}

    try:
        oauth_params = discover_oauth_params(session)
        callback_url = discord_authorize(session, oauth_params)
        html, final_url = browser_login(callback_url)
        print(f"[D] Dashboard... 最终URL: {mask_url(final_url)}")
        info = check_dashboard_html(html, final_url)
        server_result = check_and_start_server(session)

        if not info["logged_in"]:
            # 带上具体原因，别再报一句干巴巴的「未识别为登录状态」
            raise RuntimeError(f"登录态未确认: {info.get('reason') or '页面无登录信号'}")
    except Exception as e:
        error_msg = str(e)
        print(f"❌ 执行失败: {error_msg}")
        report = build_report(info, server_result)
        tg_send("❌ OptikLink 签到失败", report)
        print("\n❌ 最终失败，退出。")
        sys.exit(1)

    print("✅ 执行成功！")
    report = build_report(info, server_result)
    tg_send("✅ OptikLink 签到成功", report)

if __name__ == "__main__":
    main()
