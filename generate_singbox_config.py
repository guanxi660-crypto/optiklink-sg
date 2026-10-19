#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sing-box 客户端配置生成器（替代原 generate_xray_config.py，xray → sing-box）。

为什么换：xray-core 不支持 AnyTLS 协议；sing-box 自 1.12.0 起支持 anytls outbound，
一份配置同时覆盖 VLESS / AnyTLS 节点。

支持的分享链接：
    vless://<uuid>@host:port?security=tls&type=ws&host=..&path=..&sni=..&fp=..&flow=..
    anytls://<password>@host:port/?sni=real.example.com&insecure=1

输出一份完整的 sing-box 配置到 stdout：
    本地 socks5 入口 127.0.0.1:10808 -> 指定的代理出站

环境变量（二选一，优先 PROXY_LINK）：
    PROXY_LINK   任意上述协议的分享链接（推荐；anytls 节点填这个）
    VLESS_NODE   VLESS 分享链接（旧变量名，保持向后兼容）
"""

import os
import sys
import json
import ipaddress
from urllib.parse import urlsplit, unquote

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 10808

DEFAULT_FINGERPRINT = "chrome"
DEFAULT_PATH = "/"


def die(msg: str) -> "None":
    print(f"❌ {msg}", file=sys.stderr)
    sys.exit(1)


def env_link() -> str:
    """PROXY_LINK 优先，回退旧的 VLESS_NODE。空串视为未设置。"""
    for key in ("PROXY_LINK", "VLESS_NODE"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def split_netloc(url: str):
    """拆出 netloc，兼容 IPv6 字面量与未编码的 '@'。

    urlsplit 自己会处理 [] 和 userinfo，但 password 里带未编码 '@' 时 .username/.password
    会按第一个 '@' 切，导致截断；这里按最后一个 '@' 手工切，更贴近用户实际粘贴的链接。
    """
    rest = url.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        idx = rest.find(sep)
        if idx != -1:
            rest = rest[:idx]
            break
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
    else:
        userinfo, hostport = "", rest

    host, port = hostport, None
    if host.startswith("["):                       # [2409:8a71::615]:8964
        end = host.find("]")
        if end == -1:
            die(f"IPv6 地址缺少右方括号: {hostport}")
        addr = host[1:end]
        tail = host[end + 1:]
        if tail.startswith(":"):
            port = tail[1:]
        host = addr                                # sing-box server 字段填裸 IPv6
    elif ":" in host:
        host, port = host.rsplit(":", 1)

    if port is not None:
        if not port.isdigit():
            die(f"端口不是数字: {port}")
        port = int(port)
    return unquote(userinfo), host, port


def parse_query(url: str) -> dict:
    parts = urlsplit(url)
    params = {}
    for kv in parts.query.split("&"):
        if not kv or "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        params[k] = unquote(v)
    return params


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def truthy(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


# ─────────────────────────────────────────────────────────────
# 协议解析
# ─────────────────────────────────────────────────────────────
def parse_anytls(url: str) -> dict:
    """anytls://<password>@host[:port]/?sni=..&insecure=1"""
    password, host, port = split_netloc(url)
    if not password:
        die("anytls 链接缺少密码（应为 anytls://密码@服务器:端口/）")
    if not host:
        die("anytls 链接缺少服务器地址")
    params = parse_query(url)

    sni = params.get("sni", "") or params.get("peer", "")
    if sni and is_ip_literal(sni):
        sni = ""                                  # RFC 6066：SNI 不允许填 IP 字面量

    tls = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if truthy(params.get("insecure", 0)):
        tls["insecure"] = True
    if params.get("alpn"):
        tls["alpn"] = [a for a in params["alpn"].split(",") if a]

    outbound = {
        "type": "anytls",
        "tag": "proxy-out",
        "server": host,
        "server_port": port or 443,               # anytls URI 规范：端口缺省 443
        "password": password,
        "tls": tls,
    }
    for key in ("idle_session_check_interval", "idle_session_timeout"):
        if params.get(key):
            outbound[key] = params[key]
    if params.get("min_idle_session"):
        outbound["min_idle_session"] = int(params["min_idle_session"])
    return outbound


def parse_vless(url: str) -> dict:
    """vless://<uuid>@host:port?..."""
    uuid, host, port = split_netloc(url)
    if not uuid:
        die("vless 链接缺少 UUID")
    if not host:
        die("vless 链接缺少服务器地址")
    p = parse_query(url)

    network = (p.get("type") or p.get("network") or "tcp").lower()
    path = p.get("path") or DEFAULT_PATH
    host_hdr = p.get("host") or p.get("Host") or ""
    security = (p.get("security") or "none").lower()
    sni = p.get("sni", "") or host_hdr or host
    fingerprint = p.get("fp") or p.get("fingerprint") or DEFAULT_FINGERPRINT

    # 传输层：sing-box 用 transport，不是 xray 的 streamSettings
    transport = None
    if network == "ws":
        transport = {"type": "ws", "path": path}
        if host_hdr:
            transport["headers"] = {"Host": host_hdr}
    elif network == "httpupgrade":
        transport = {"type": "httpupgrade", "path": path}
        if host_hdr:
            transport["host"] = host_hdr
    elif network == "grpc":
        service = p.get("serviceName") or p.get("servicename") or path.lstrip("/")
        transport = {"type": "grpc", "service_name": service}
    elif network == "http":
        transport = {"type": "http", "path": path}
        if host_hdr:
            transport["host"] = [host_hdr]
    elif network != "tcp":
        die(f"暂不支持的传输类型: {network}（支持 tcp/ws/httpupgrade/grpc）")

    # 安全层
    tls = None
    if security == "tls":
        tls = {"enabled": True, "server_name": sni}
        if fingerprint:
            tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    elif security == "reality":
        pbk = p.get("pbk") or p.get("publicKey")
        if not pbk:
            die("security=reality 但缺少 pbk（publicKey）参数")
        tls = {
            "enabled": True,
            "server_name": sni,
            "utls": {"enabled": True, "fingerprint": fingerprint},
            "reality": {
                "enabled": True,
                "public_key": pbk,
                "short_id": p.get("sid") or p.get("shortId") or "",
            },
        }

    outbound = {
        "type": "vless",
        "tag": "proxy-out",
        "server": host,
        "server_port": port or 443,
        "uuid": uuid,
    }
    if p.get("flow"):
        outbound["flow"] = p["flow"]
    if tls:
        outbound["tls"] = tls
    if transport:
        outbound["transport"] = transport
    return outbound


# ─────────────────────────────────────────────────────────────
# 配置组装
# ─────────────────────────────────────────────────────────────
def build_config(link: str) -> dict:
    scheme = link.split("://", 1)[0].lower()
    if scheme == "anytls":
        outbound = parse_anytls(link)
    elif scheme == "vless":
        outbound = parse_vless(link)
    else:
        die(f"不支持的协议: {scheme}（当前支持 anytls / vless）")

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": LISTEN_HOST,
                "listen_port": LISTEN_PORT,
            }
        ],
        "outbounds": [outbound],
    }


def main():
    link = env_link()
    if not link:
        die("未设置 PROXY_LINK / VLESS_NODE 环境变量")

    # 打日志时只露协议和地址，密码/UUID 不打
    scheme = link.split("://", 1)[0].lower()
    try:
        _, host, port = split_netloc(link)
        where = f"{scheme}://{host}" + (f":{port}" if port else "")
    except SystemExit:
        where = scheme
    print(f"🔎 正在解析代理链接: {where}", file=sys.stderr)

    try:
        config = build_config(link)
    except SystemExit:
        raise
    except Exception as e:
        die(f"生成配置失败: {e}")

    print(json.dumps(config, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
