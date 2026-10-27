#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
出口可用性探针 —— 回答「这个出口能不能访问 optiklink.net」。

为什么不用 curl 只看状态码：
    站点被 Cloudflare 挡下来时，两种 403 长得一样、含义完全不同：
      · WAF 硬拦（"Sorry, you have been blocked"）→ 出口 IP 进黑名单，换出口，无解
      · JS 盾页（"Just a moment..."）            → 有头浏览器能过，不该判死刑
    老代码只看 HTTP 状态码，把第二种也当成「IP 被整段拉黑」直接 abort，
    等于自己把能跑的路堵死了。这里读 body 分型。

用法:
    python3 site_probe.py [--proxy socks5h://127.0.0.1:10808] [--timeout 25] [--url URL] [--out probe.json]

输出:
    stdout 一行人类可读摘要（直接进 Actions 日志）
    --out 指定时，把结构化结果写成 JSON 文件（workflow 用，**不依赖 jq**）

JSON 结构:
    {"exit_ip":"1.2.3.4","code":200,"verdict":"OK","detail":"..."}

verdict:
    OK            站点正常返回（2xx/3xx）
    CHALLENGE     Cloudflare JS 盾页，浏览器有机会过 —— **可用**
    WAF_BLOCK     WAF 硬拦截，出口 IP 被拉黑 —— 不可用
    BLOCKED       其他 4xx/5xx —— 不可用
    UNREACHABLE   连不上（代理没起来 / 网络不通）—— 不可用

退出码: 0 = 可用（OK / CHALLENGE），1 = 不可用
"""

import argparse
import json
import re
import sys

import requests

DEFAULT_URL = "https://optiklink.net/home"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# 硬拦：命中就说明 IP 在 CF 黑名单里，等多久都没用
WAF_MARKERS = (
    "sorry, you have been blocked",
    "you are unable to access",
    "attention required",
    "error code 1020",
    "error code: 1020",
)
# 盾页：有头浏览器 + Turnstile 有机会过
CHALLENGE_MARKERS = (
    "just a moment",
    "enable javascript and cookies to continue",
    "checking your browser",
    "challenge-platform",
    "cf-chl",
)


def classify(code: int, body: str) -> str:
    low = (body or "").lower()
    if any(m in low for m in WAF_MARKERS):
        return "WAF_BLOCK"
    if any(m in low for m in CHALLENGE_MARKERS):
        return "CHALLENGE"
    if 200 <= code < 400:
        return "OK"
    return "BLOCKED"


def emit(out: dict, path: str) -> None:
    """stdout 给日志看，--out 给脚本读。"""
    if path:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False)
        except OSError as e:
            print(f"   （写 {path} 失败: {e}）")
    line = f"出口 IP: {out['exit_ip'] or '?'} | 目标站点 -> HTTP {out['code']} | 判定: {out['verdict']}"
    if out["detail"]:
        line += f" | {out['detail']}"
    print(line)


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--proxy", default="", help="socks5h://host:port 或 http://host:port，留空=直连")
    ap.add_argument("--timeout", type=float, default=25)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--ip-url", default="https://api.ipify.org")
    ap.add_argument("--out", default="", help="把 JSON 结果写到这个文件")
    args = ap.parse_args()

    sess = requests.Session()
    sess.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    if args.proxy:
        sess.proxies = {"http": args.proxy, "https": args.proxy}

    out = {"exit_ip": "", "code": 0, "verdict": "UNREACHABLE", "detail": ""}

    # ① 出口 IP（顺便验证代理链路本身通不通）
    try:
        r = sess.get(args.ip_url, timeout=args.timeout)
        if r.status_code == 200 and r.text.strip():
            out["exit_ip"] = r.text.strip()[:64]
    except Exception as e:
        out["detail"] = f"出口 IP 探测失败: {type(e).__name__}: {e}"
        emit(out, args.out)
        return 1

    # ② 目标站点
    try:
        r = sess.get(args.url, timeout=args.timeout, allow_redirects=True)
    except Exception as e:
        out["detail"] = f"目标站点请求失败: {type(e).__name__}: {e}"
        emit(out, args.out)
        return 1

    out["code"] = r.status_code
    out["verdict"] = classify(r.status_code, r.text)

    if out["verdict"] == "WAF_BLOCK":
        ray = r.headers.get("cf-ray", "")
        m = re.search(r"Cloudflare Ray ID:\s*<[^>]*>?([0-9a-f]{8,})", r.text)
        out["detail"] = "Cloudflare WAF 硬拦（IP 在黑名单里）" + (
            f" ray={ray or (m.group(1) if m else '')}")
    elif out["verdict"] == "CHALLENGE":
        out["detail"] = "Cloudflare JS 盾页（有头浏览器有机会过）"
    elif out["verdict"] == "BLOCKED":
        out["detail"] = f"HTTP {r.status_code}，非盾页"

    emit(out, args.out)
    return 0 if out["verdict"] in ("OK", "CHALLENGE") else 1


if __name__ == "__main__":
    sys.exit(main())
