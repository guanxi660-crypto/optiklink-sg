#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点端口 TCP 探针 —— 只回答一个问题：这个 server:port 现在到底开没开。

为什么单独写一个：
    上一版把「节点死了」和「sing-box 配置错了」混在同一句
    「代理出口测试失败（出站拨号不通），节点不可用或配置有误」里，
    导致排查时完全分不清是代码问题还是节点问题。TCP 层能先定性：
        REFUSED  → 端口上没有服务在监听（端口变了 / 节点下线）
        TIMEOUT  → SYN 被 DROP（防火墙丢包 / 路由不通）
        OK       → 端口活着，问题一定在协议层或上游站点

用法:
    python3 tcp_probe.py <host> <port> [超时秒数, 默认 8]

输出（一行，便于 workflow 直接贴日志）:
    OK 42ms | REFUSED | TIMEOUT 8s | ERROR <原因>

退出码:
    0 = 通  2 = 超时  3 = 被拒  4 = 其他错误  64 = 参数错误
"""

import socket
import sys
import time


def main() -> int:
    if len(sys.argv) < 3:
        print("用法: tcp_probe.py <host> <port> [timeout]", file=sys.stderr)
        return 64

    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(f"ERROR 端口不是数字: {sys.argv[2]}", file=sys.stderr)
        return 64
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0

    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        print(f"OK {int((time.time() - t0) * 1000)}ms")
        return 0
    except socket.timeout:
        print(f"TIMEOUT {timeout:g}s")
        return 2
    except ConnectionRefusedError:
        print("REFUSED")
        return 3
    except socket.gaierror as e:
        print(f"ERROR 域名解析失败 ({e})")
        return 4
    except OSError as e:
        print(f"ERROR {e}")
        return 4


if __name__ == "__main__":
    sys.exit(main())
