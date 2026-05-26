"""C 段 / 旁站资产发现。"""
from typing import Any, Dict, List
import ipaddress

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import (
    normalize_target, resolve_host, parallel_map, tcp_probe, http_get,
)


class CSegmentScanner(BaseScanner):
    name = "csegment"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "C 段旁站探测", summary="请填写 IP 或域名")

        ip = resolve_host(target) or target
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ScanResult(False, "C 段旁站探测", summary="无法解析为 IP")

        cidr = options.get("cidr", "")
        if cidr:
            network = ipaddress.ip_network(cidr, strict=False)
        else:
            network = ipaddress.ip_network(f"{addr}/24", strict=False)

        ports = [int(p) for p in options.get("ports", "80,443").split(",")]
        threads = int(options.get("threads", 40))
        max_hosts = int(options.get("max_hosts", 254))
        check_http = options.get("check_http", True)

        hosts = [str(h) for h in list(network.hosts())[:max_hosts]]
        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] C 段 {network} 共 {len(hosts)} 主机")

        def probe(h: str):
            open_ports = [p for p in ports if tcp_probe(h, p, 0.8)]
            title = ""
            if check_http and 80 in open_ports:
                r = http_get(f"http://{h}", timeout=3, verify_ssl=False)
                if r:
                    import re
                    m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I)
                    title = m.group(1).strip()[:60] if m else ""
            elif check_http and 443 in open_ports:
                r = http_get(f"https://{h}", timeout=3, verify_ssl=False)
                if r:
                    import re
                    m = re.search(r"<title[^>]*>([^<]+)</title>", r.text, re.I)
                    title = m.group(1).strip()[:60] if m else ""
            return h, open_ports, title

        results = parallel_map(hosts, probe, workers=threads, cancel_check=lambda: self.cancelled)
        for i, (_, res) in enumerate(results):
            if isinstance(res, Exception):
                continue
            h, open_ports, title = res
            if open_ports:
                data.append({
                    "IP": h,
                    "开放端口": ",".join(map(str, open_ports)),
                    "页面标题": title or "-",
                    "备注": "同 C 段" if h != str(addr) else "目标",
                })
                logs.append(f"[+] {h} {open_ports} {title}")
            self.progress(int(95 * (i + 1) / max(len(results), 1)))

        self.progress(100, "完成")
        return ScanResult(
            True, "C 段旁站探测", data=data, logs=logs,
            summary=f"C 段 {network} 发现 {len(data)} 个存活",
        )
