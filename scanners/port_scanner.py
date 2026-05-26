"""端口扫描 — 支持多种扫描方式与 nmap 集成。"""
import socket
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import (
    grab_banner,
    normalize_target,
    parallel_map,
    resolve_host,
    tcp_probe,
)

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False


class PortScanner(BaseScanner):
    name = "port"

    PRESET_PORTS = {
        "Top 20": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,6379,8080",
        "Top 100": ",".join(str(p) for p in [
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
            135, 139, 143, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544,
            548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110,
            1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
            3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666,
            5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
            9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
        ]),
        "全端口(采样)": ",".join(str(p) for p in range(1, 1025)),
        "Web 常用": "80,443,8000,8080,8081,8443,8888,9000",
        "数据库": "1433,1521,3306,5432,6379,27017,9200",
    }

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "端口扫描", summary="请填写目标 IP 或域名")

        host = resolve_host(target) or target
        scan_type = options.get("scan_type", "TCP Connect")
        port_preset = options.get("port_preset", "Top 100")
        custom_ports = options.get("custom_ports", "")
        timeout = float(options.get("timeout", 1.0))
        threads = int(options.get("threads", 100))
        grab_banners = options.get("grab_banner", True)
        service_detect = options.get("service_detect", False)

        if custom_ports:
            port_list = [int(p.strip()) for p in custom_ports.replace("-", ",").split(",") if p.strip().isdigit()]
        elif port_preset in self.PRESET_PORTS:
            port_list = [int(p) for p in self.PRESET_PORTS[port_preset].split(",")]
        else:
            port_list = list(range(1, 1025))

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] 目标 {host} | 方式 {scan_type} | 端口数 {len(port_list)}")

        if scan_type.startswith("Nmap") and HAS_NMAP:
            self._nmap_scan(host, scan_type, port_list, data, logs, options)
        elif scan_type == "UDP (基础)":
            self._udp_scan(host, port_list[:20], data, logs, timeout)
        else:
            self._tcp_connect_scan(host, port_list, data, logs, timeout, threads, grab_banners)

        if service_detect and not self.cancelled:
            self._guess_services(data, logs)

        self.progress(100, "完成")
        open_count = len(data)
        summary = f"{host} 发现 {open_count} 个开放端口"
        return ScanResult(True, "端口扫描", data=data, logs=logs, summary=summary)

    def _tcp_connect_scan(
        self, host: str, ports: list, data: list, logs: list,
        timeout: float, threads: int, grab_banners: bool,
    ) -> None:
        total = len(ports)
        done = [0]

        def scan_port(port: int):
            if self.cancelled:
                return port, False, ""
            open_ = tcp_probe(host, port, timeout)
            banner = grab_banner(host, port) if open_ and grab_banners else ""
            return port, open_, banner

        def on_done(port, open_, banner):
            done[0] += 1
            if open_:
                logs.append(f"[OPEN] {host}:{port} {banner}")
                data.append({
                    "端口": port,
                    "状态": "open",
                    "服务": self._port_service(port),
                    "Banner": banner[:100] if banner else "-",
                })
            self.progress(int(95 * done[0] / total))

        results = parallel_map(
            ports, scan_port, workers=threads,
            cancel_check=lambda: self.cancelled,
        )
        for _, result in results:
            if isinstance(result, Exception):
                continue
            on_done(*result)

    def _udp_scan(self, host: str, ports: list, data: list, logs: list, timeout: float) -> None:
        for i, port in enumerate(ports):
            if self.cancelled:
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b"\x00", (host, port))
                sock.recvfrom(1024)
                status = "open|filtered"
            except socket.timeout:
                status = "open|filtered"
            except OSError:
                status = "closed"
            if "open" in status:
                data.append({"端口": port, "状态": status, "服务": "udp", "Banner": "-"})
                logs.append(f"[UDP] {host}:{port} {status}")
            self.progress(int(90 * (i + 1) / len(ports)))
            sock.close()

    def _nmap_scan(
        self, host: str, scan_type: str, ports: list,
        data: list, logs: list, options: dict,
    ) -> None:
        nm = nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports[:500])
        args_map = {
            "Nmap SYN": "-sS",
            "Nmap ACK": "-sA",
            "Nmap FIN": "-sF",
            "Nmap 综合": "-sV -sC",
        }
        extra = args_map.get(scan_type, "-sT")
        timing = options.get("nmap_timing", "T3")
        extra += f" -{timing}"

        self.log(f"[*] 调用 nmap {extra} -p {port_str[:50]}...")
        try:
            nm.scan(host, port_str, arguments=extra)
        except nmap.PortScannerError as exc:
            logs.append(f"[!] nmap 失败: {exc}，回退 TCP Connect")
            self._tcp_connect_scan(host, ports, data, logs, 1.0, 80, True)
            return

        for proto in nm.all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port]["state"]
                if state == "open":
                    svc = nm[host][proto][port].get("name", "")
                    product = nm[host][proto][port].get("product", "")
                    ver = nm[host][proto][port].get("version", "")
                    banner = f"{product} {ver}".strip()
                    data.append({
                        "端口": port,
                        "状态": state,
                        "服务": svc,
                        "Banner": banner or "-",
                    })
                    logs.append(f"[nmap] {port}/{proto} {state} {svc}")
        self.progress(95)

    def _guess_services(self, data: list, logs: list) -> None:
        for row in data:
            port = row.get("端口", 0)
            if row.get("服务") in ("", "-", "unknown"):
                row["服务"] = self._port_service(port)

    @staticmethod
    def _port_service(port: int) -> str:
        common = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
            8080: "http-proxy", 27017: "mongodb",
        }
        return common.get(port, "unknown")
