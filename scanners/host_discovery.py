"""存活主机探测。"""
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import (
    expand_ip_range,
    normalize_target,
    parallel_map,
    ping_host,
    resolve_host,
    tcp_probe,
)


class HostDiscoveryScanner(BaseScanner):
    name = "host"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        ip_range = options.get("ip_range", target)
        hosts = expand_ip_range(ip_range)
        if not hosts:
            ip = resolve_host(target)
            hosts = [ip] if ip else [target]

        method = options.get("method", "ICMP Ping")
        tcp_ports = [int(p) for p in options.get("tcp_ports", "80,443,22").split(",")]
        timeout = float(options.get("timeout", 1.0))
        ping_timeout = int(options.get("ping_timeout_ms", 1000))
        threads = int(options.get("threads", 50))
        max_hosts = int(options.get("max_hosts", 512))
        hosts = hosts[:max_hosts]

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] 探测 {len(hosts)} 主机，方式: {method}")

        def probe(host: str):
            if self.cancelled:
                return host, False, ""
            if method == "ICMP Ping":
                alive = ping_host(host, ping_timeout)
                detail = "icmp"
            elif method == "TCP Ping":
                alive = any(tcp_probe(host, p, timeout) for p in tcp_ports)
                detail = f"tcp:{tcp_ports}"
            elif method == "ARP (同网段)":
                alive = ping_host(host, ping_timeout)
                detail = "arp/icmp"
            else:  # 组合探测
                alive = ping_host(host, ping_timeout) or any(
                    tcp_probe(host, p, timeout) for p in tcp_ports
                )
                detail = "icmp+tcp"
            return host, alive, detail

        total = len(hosts)
        results = parallel_map(
            hosts, probe, workers=threads,
            cancel_check=lambda: self.cancelled,
        )
        alive_count = 0
        for i, (_, result) in enumerate(results):
            if isinstance(result, Exception):
                continue
            host, alive, detail = result
            if alive:
                alive_count += 1
                logs.append(f"[ALIVE] {host} ({detail})")
                data.append({
                    "主机": host,
                    "状态": "存活",
                    "探测方式": detail,
                    "备注": "",
                })
            if (i + 1) % max(1, total // 20) == 0:
                self.progress(int(95 * (i + 1) / total))

        self.progress(100, "完成")
        summary = f"共 {total} 主机，存活 {alive_count}"
        return ScanResult(True, "存活主机探测", data=data, logs=logs, summary=summary)
