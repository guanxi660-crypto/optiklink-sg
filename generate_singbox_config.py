#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sing-box 客户端配置生成器（替代原 generate_xray_config.py，xray → sing-box）。

为什么换：xray-core 不支持 AnyTLS 协议；sing-box 自 1.12.0 起支持 anytls outbound，
一份配置同时覆盖 VLESS / AnyTLS 节点。

支持的分享链接：
    vless://<uuid>@host:port?security=tls&type=ws&host=..&path=..&sni=..&fp=..&flow=..
    anytls://<password>@host:port/?sni=real.example.com&insecure=1
    hysteria2://<password>@host:port/?sni=..&insecure=1&obfs=salamander&obfs-password=..
    （hysteria2 也认 hy2:// 前缀）

输出一份完整的 sing-box 配置到 stdout：
    本地 socks5 入口 127.0.0.1:10808 -> 指定的代理出站

环境变量（按顺序合并成候选列表）：
    PROXY_LINK         任意上述协议的分享链接（推荐；anytls 节点填这个）
    PROXY_LINK_BACKUP  备用节点，**可以多行**，一行一个
    VLESS_NODE         VLESS 分享链接（旧变量名，保持向后兼容）

每个变量都支持**多行**：一行一个节点链接，按出现顺序去重后组成候选池。
workflow 会逐个试，第一个「TCP 通 + 出站通 + 目标站点不 403」的胜出。

命令行参数：
    --count        只打印候选节点数量（0 也算成功退出）
    --list         打印候选节点列表（已脱敏，不含密码/UUID）
    --describe     打印选中节点的 `type server port`（空格分隔，给 shell 读，不依赖 jq）
    --index N      取第 N 个候选（1 起）；也认环境变量 PROXY_INDEX
"""

import os
import re
import sys
import json
import ipaddress
from urllib.parse import urlsplit, unquote

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 10808

DEFAULT_FINGERPRINT = "chrome"
DEFAULT_PATH = "/"

# 走 UDP/QUIC 的出站类型 —— workflow 会据此跳过 TCP 端口探测
UDP_TYPES = {"hysteria2", "tuic"}


def die(msg: str) -> "None":
    print(f"❌ {msg}", file=sys.stderr)
    sys.exit(1)


def env_links() -> list:
    """收集所有候选节点链接（去重、保序）。

    只按换行切分 —— 密码/UUID 里可能出现 '|' 或空格，按空白切会把链接切坏。
    多节点请用多行 Secret 提供，不要用分隔符拼。
    """
    blobs = []
    for key in ("PROXY_LINK", "PROXY_LINK_BACKUP", "VLESS_NODE"):
        value = os.environ.get(key, "")
        if value and value.strip():
            blobs.append(value)

    links, seen = [], set()
    for blob in blobs:
        for line in blob.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            links.append(line)
    return links


def mask_link(link: str) -> str:
    """脱敏：只露协议 + 主机 + 端口，不打印密码/UUID。"""
    scheme = link.split("://", 1)[0].lower() if "://" in link else "?"
    try:
        _, host, port = split_netloc(link)
    except SystemExit:
        return f"{scheme}://(解析失败)"
    return f"{scheme}://{host}" + (f":{port}" if port else "")


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


def parse_hysteria2(url: str) -> dict:
    """hysteria2://<密码>@host[:port]/?sni=..&insecure=1&obfs=salamander&obfs-password=..

    ⚠️ hysteria2 是 **QUIC over UDP**，不是 TCP。
    · 所以 TCP 探测对它毫无意义（端口不监听 TCP 也完全正常），workflow 会跳过
    · sing-box 的 hysteria2 outbound 必须带 tls，且默认 alpn=h3
    """
    password, host, port = split_netloc(url)
    if not host:
        die("hysteria2 链接缺少服务器地址")
    p = parse_query(url)

    # 认证：标准格式是 anytls 那种「密码@主机」，但有些订阅把 auth 放在 query 里
    if not password:
        password = p.get("auth", "") or p.get("password", "")
    if not password:
        die("hysteria2 链接缺少密码（应为 hysteria2://密码@服务器:端口/）")

    sni = p.get("sni", "") or p.get("peer", "")
    if sni and is_ip_literal(sni):
        sni = ""                                  # RFC 6066：SNI 不允许填 IP 字面量

    tls = {"enabled": True}
    if sni:
        tls["server_name"] = sni
    if truthy(p.get("insecure", 0)):
        tls["insecure"] = True
    alpn = p.get("alpn")
    tls["alpn"] = [a for a in alpn.split(",") if a] if alpn else ["h3"]

    if p.get("pinsha256") or p.get("pinSHA256"):
        print("⚠️ 忽略 pinSHA256：sing-box 的 hysteria2 outbound 不支持证书固定",
              file=sys.stderr)

    outbound = {
        "type": "hysteria2",
        "tag": "proxy-out",
        "server": host,
        "server_port": port or 443,
        "password": password,
        "tls": tls,
    }

    # 混淆（salamander）
    obfs = (p.get("obfs") or "").strip()
    if obfs and obfs.lower() != "none":
        obfs_pw = (p.get("obfs-password") or p.get("obfs_password")
                   or p.get("obfsParam") or "")
        if obfs_pw:
            outbound["obfs"] = {"type": obfs, "password": obfs_pw}

    # 带宽（可选，只影响拥塞控制的表现，不填也能用）
    for key, aliases in (("up_mbps", ("up", "upmbps", "up_mbps")),
                         ("down_mbps", ("down", "downmbps", "down_mbps"))):
        for a in aliases:
            if p.get(a):
                try:
                    outbound[key] = int(float(p[a]))
                except ValueError:
                    pass
                break
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
    elif network == "xhttp":
        die("xhttp 是 Xray 专属传输，sing-box 不支持 —— 这个节点在 sing-box 下用不了，"
            "换个节点（ws / grpc / httpupgrade / tcp）或换 anytls / hysteria2 节点")
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
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme == "anytls":
        outbound = parse_anytls(link)
    elif scheme in ("hysteria2", "hy2"):
        outbound = parse_hysteria2(link)
    elif scheme == "vless":
        outbound = parse_vless(link)
    else:
        die(f"不支持的协议: {scheme or '(空)'}（当前支持 anytls / hysteria2 / vless）")

    return {
        # info 级别：出站拨号失败时能看到具体错误（目标/原因），便于诊断节点问题
        "log": {"level": "info", "timestamp": True},
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


def parse_args(argv):
    """极简参数解析：只认 --count / --list / --index N。"""
    opts = {"count": False, "list": False, "describe": False, "index": None}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--count":
            opts["count"] = True
        elif a == "--list":
            opts["list"] = True
        elif a == "--describe":
            opts["describe"] = True
        elif a == "--index":
            if i + 1 >= len(argv):
                die("--index 需要一个数字")
            opts["index"] = argv[i + 1]
            i += 1
        elif a.startswith("--index="):
            opts["index"] = a.split("=", 1)[1]
        elif a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        else:
            die(f"未知参数: {a}")
        i += 1

    if opts["index"] is None:
        opts["index"] = os.environ.get("PROXY_INDEX", "").strip() or None
    if opts["index"] is not None:
        try:
            opts["index"] = int(opts["index"])
        except ValueError:
            die(f"PROXY_INDEX / --index 不是数字: {opts['index']!r}")
        if opts["index"] < 1:
            die(f"节点序号从 1 开始，收到 {opts['index']}")
    return opts


def main():
    opts = parse_args(sys.argv[1:])
    links = env_links()

    if opts["count"]:
        print(len(links))
        return

    if opts["list"]:
        for n, link in enumerate(links, 1):
            print(f"{n}\t{mask_link(link)}")
        return

    if not links:
        die("未设置 PROXY_LINK / PROXY_LINK_BACKUP / VLESS_NODE（可多行，一行一个节点）")

    idx = opts["index"] or 1
    if idx > len(links):
        die(f"节点序号越界：只有 {len(links)} 个候选，请求第 {idx} 个")
    link = links[idx - 1]

    # 打日志时只露协议和地址，密码/UUID 不打
    print(f"🔎 正在解析代理链接（#{idx}/{len(links)}）: {mask_link(link)}", file=sys.stderr)

    try:
        config = build_config(link)
    except SystemExit:
        raise
    except Exception as e:
        die(f"生成配置失败: {e}")

    if opts["describe"]:
        ob = config["outbounds"][0]
        # 第 4 个字段告诉 workflow 该用 TCP 还是 UDP 探测 —— hysteria2 走 QUIC/UDP，
        # 拿 TCP 去探它必然「不通」，会把好节点误杀
        net = "udp" if ob["type"] in UDP_TYPES else "tcp"
        print(f"{ob['type']} {ob['server']} {ob['server_port']} {net}")
        return

    print(json.dumps(config, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
