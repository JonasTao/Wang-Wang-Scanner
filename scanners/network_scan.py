"""网络信息扫描：DNS、路由、SSL 等。"""
import subprocess
import platform
from typing import Any, Dict, List

import dns.resolver
import requests

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host, ssl_info, url_to_host


class NetworkScanScanner(BaseScanner):
    name = "network"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "网络信息扫描", summary="请填写目标")

        modules = options.get("modules", ["DNS", "Traceroute", "SSL", "HTTP头"])
        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        host = url_to_host(target) if "://" in target else target
        ip = resolve_host(host) or host

        self.log(f"[*] 网络扫描: {host} ({ip})")
        step = 0
        total = len(modules)

        if "DNS" in modules:
            step += 1
            self._dns_scan(host, data, logs, options)
            self.progress(int(step / total * 80))

        if self.cancelled:
            return ScanResult(False, "网络信息扫描", data=data, logs=logs, summary="已取消")

        if "Traceroute" in modules:
            step += 1
            self._traceroute(ip, data, logs, options)
            self.progress(int(step / total * 85))

        if "SSL" in modules:
            step += 1
            self._ssl_scan(host, data, logs)
            self.progress(int(step / total * 92))

        if "HTTP头" in modules:
            step += 1
            self._http_headers(host, data, logs, options)
            self.progress(98)

        if "反向解析" in modules:
            self._reverse_dns(ip, data, logs)

        self.progress(100, "完成")
        return ScanResult(
            True, "网络信息扫描",
            data=data, logs=logs,
            summary=f"完成 {len(data)} 条网络信息",
        )

    def _dns_scan(self, host: str, data: list, logs: list, options: dict) -> None:
        types = options.get("dns_types", "A,AAAA,MX,NS,TXT,CNAME,SOA").split(",")
        for rtype in types:
            if self.cancelled:
                return
            rtype = rtype.strip().upper()
            try:
                ans = dns.resolver.resolve(host, rtype)
                for r in ans:
                    val = str(r).strip(".")
                    logs.append(f"[DNS {rtype}] {val}")
                    data.append({"类别": "DNS", "类型": rtype, "值": val})
            except Exception as exc:
                logs.append(f"[DNS {rtype}] 无记录或失败")

    def _traceroute(self, host: str, data: list, logs: list, options: dict) -> None:
        max_hops = int(options.get("max_hops", 20))
        cmd = ["tracert", "-d", "-h", str(max_hops), host] if platform.system().lower() == "windows" else [
            "traceroute", "-m", str(max_hops), host
        ]
        self.log(f"[*] 执行路由跟踪 (最多 {max_hops} 跳)...")
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
            )
            for line in out.stdout.splitlines()[:max_hops + 5]:
                line = line.strip()
                if line:
                    logs.append(f"[路由] {line}")
                    data.append({"类别": "Traceroute", "类型": "跳", "值": line[:120]})
        except Exception as exc:
            logs.append(f"[!] Traceroute 失败: {exc}")

    def _ssl_scan(self, host: str, data: list, logs: list) -> None:
        info = ssl_info(host, 443)
        for k, v in info.items():
            logs.append(f"[SSL] {k}: {v}")
            data.append({"类别": "SSL", "类型": k, "值": str(v)})

    def _http_headers(self, host: str, data: list, logs: list, options: dict) -> None:
        check_list = options.get("security_headers", True)
        for scheme in ("https", "http"):
            if self.cancelled:
                return
            url = f"{scheme}://{host}"
            try:
                resp = requests.get(url, timeout=8, verify=False)
                for h in ("Server", "X-Frame-Options", "X-Content-Type-Options",
                          "Strict-Transport-Security", "Content-Security-Policy"):
                    val = resp.headers.get(h, "缺失" if check_list else "-")
                    data.append({"类别": "HTTP", "类型": h, "值": val})
                    logs.append(f"[HTTP] {h}: {val}")
                return
            except requests.RequestException as exc:
                logs.append(f"[HTTP] {url} 失败")

    def _reverse_dns(self, ip: str, data: list, logs: list) -> None:
        import socket
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            data.append({"类别": "反向DNS", "类型": "PTR", "值": name})
            logs.append(f"[PTR] {ip} -> {name}")
        except socket.herror:
            logs.append(f"[PTR] {ip} 无反向记录")
