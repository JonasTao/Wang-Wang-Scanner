"""网络资产发现与管理。"""
import socket
from typing import Any, Dict, List

import dns.resolver
import requests

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import (
    expand_ip_range,
    normalize_target,
    parallel_map,
    parse_targets,
    resolve_host,
    tcp_probe,
)


class AssetScanner(BaseScanner):
    name = "assets"

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
        "vpn", "portal", "cdn", "static", "blog", "shop", "m", "mobile",
        "oa", "crm", "git", "jenkins", "grafana", "monitor", "db",
    ]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "网络资产管理", summary="请填写目标域名或 IP 段")

        mode = options.get("mode", "综合发现")
        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        self.log(f"[*] 资产扫描: {target} 模式={mode}")

        if mode in ("综合发现", "子域名枚举"):
            self._subdomain_enum(target, data, logs, options)
        if self.cancelled:
            return ScanResult(False, "网络资产管理", data=data, logs=logs, summary="已取消")

        if mode in ("综合发现", "IP段探测"):
            self._ip_range_scan(target, data, logs, options)
        if self.cancelled:
            return ScanResult(False, "网络资产管理", data=data, logs=logs, summary="已取消")

        if mode in ("综合发现", "服务指纹识别"):
            self._service_fingerprint(target, data, logs, options)

        self.progress(100, "完成")
        summary = f"发现 {len(data)} 项资产"
        return ScanResult(True, "网络资产管理", data=data, logs=logs, summary=summary)

    def _subdomain_enum(self, domain: str, data: list, logs: list, options: dict) -> None:
        wordlist = options.get("custom_subdomains", "")
        subs = list(self.COMMON_SUBDOMAINS)
        if wordlist:
            subs.extend(s.strip() for s in wordlist.split(",") if s.strip())
        subs = list(dict.fromkeys(subs))

        use_bruteforce = options.get("bruteforce", True)
        use_cert_search = options.get("cert_search", False)

        if not use_bruteforce:
            subs = subs[:5]

        total = len(subs)
        for i, sub in enumerate(subs):
            if self.cancelled:
                return
            fqdn = f"{sub}.{domain}" if "." not in sub or not sub.endswith(domain) else sub
            if "." not in sub:
                fqdn = f"{sub}.{domain}"
            ip = resolve_host(fqdn)
            if ip:
                logs.append(f"[子域] {fqdn} -> {ip}")
                data.append({
                    "资产类型": "子域名",
                    "标识": fqdn,
                    "IP": ip,
                    "状态": "解析成功",
                })
            self.progress(int(30 * (i + 1) / total))

        if use_cert_search:
            self.log("[*] 尝试 crt.sh 证书透明度查询...")
            try:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    entries = resp.json()
                    seen = set()
                    for entry in entries[:100]:
                        name = entry.get("name_value", "")
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            if n.endswith(domain) and n not in seen and "*" not in n:
                                seen.add(n)
                                ip = resolve_host(n)
                                data.append({
                                    "资产类型": "证书子域",
                                    "标识": n,
                                    "IP": ip or "-",
                                    "状态": "CT日志",
                                })
                    logs.append(f"[CT] 从证书透明度获取 {len(seen)} 个子域")
            except Exception as exc:
                logs.append(f"[CT] 查询失败: {exc}")

    def _ip_range_scan(self, target: str, data: list, logs: list, options: dict) -> None:
        ip_spec = options.get("ip_range", target)
        hosts = expand_ip_range(ip_spec)
        if not hosts:
            hosts = [resolve_host(target) or target]

        ports = [int(p) for p in options.get("probe_ports", "80,443,22,3389").split(",")]
        timeout = float(options.get("timeout", 1.0))
        workers = int(options.get("threads", 30))
        max_hosts = int(options.get("max_hosts", 256))
        hosts = hosts[:max_hosts]

        self.log(f"[*] 探测 {len(hosts)} 个主机，端口 {ports}")

        def probe_one(host: str):
            alive_ports = []
            for port in ports:
                if tcp_probe(host, port, timeout):
                    alive_ports.append(port)
            return host, alive_ports

        results = parallel_map(
            hosts, probe_one, workers=workers,
            cancel_check=lambda: self.cancelled,
        )
        for host, result in results:
            if isinstance(result, Exception):
                continue
            h, ports_open = result
            if ports_open:
                logs.append(f"[主机] {h} 开放: {ports_open}")
                data.append({
                    "资产类型": "存活主机",
                    "标识": h,
                    "IP": h,
                    "状态": f"端口 {','.join(map(str, ports_open))}",
                })
        self.progress(70)

    def _service_fingerprint(self, target: str, data: list, logs: list, options: dict) -> None:
        host = resolve_host(target) or target
        ports = [int(p) for p in options.get("fp_ports", "21,22,80,443,3306,6379,8080").split(",")]
        from scanners.utils import grab_banner

        for port in ports:
            if self.cancelled:
                return
            if tcp_probe(host, port, 1.5):
                banner = grab_banner(host, port)
                logs.append(f"[指纹] {host}:{port} {banner[:80]}")
                data.append({
                    "资产类型": "服务",
                    "标识": f"{host}:{port}",
                    "IP": host,
                    "状态": banner or "开放无Banner",
                })
        self.progress(95)
