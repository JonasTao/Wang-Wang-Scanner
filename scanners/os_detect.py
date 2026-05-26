"""目标操作系统 / 服务环境检测。"""
import platform
import re
import subprocess
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import grab_banner, normalize_target, resolve_host, tcp_probe

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False


class OSDetectScanner(BaseScanner):
    name = "os"

    TTL_HINTS = {
        (0, 64): "Linux/Unix",
        (65, 128): "Windows",
        (129, 255): "网络设备/其他",
    }

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "系统检测", summary="请填写目标")

        host = resolve_host(target) or target
        methods = options.get("methods", ["TTL", "Banner", "Nmap OS"])
        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        self.log(f"[*] 检测目标: {host}")
        self.progress(10)

        if "TTL" in methods:
            ttl_result = self._ttl_detect(host)
            logs.append(f"[TTL] {ttl_result}")
            data.append({"检测项": "TTL指纹", "结果": ttl_result, "置信度": "中"})

        if self.cancelled:
            return ScanResult(False, "系统检测", data=data, logs=logs, summary="已取消")

        if "Banner" in methods:
            self.progress(40)
            banners = self._banner_detect(host, options)
            for b in banners:
                data.append({"检测项": "服务Banner", "结果": b, "置信度": "高"})
                logs.append(f"[Banner] {b}")

        if "Nmap OS" in methods and HAS_NMAP:
            self.progress(60)
            nmap_os = self._nmap_os(host, options)
            if nmap_os:
                data.append({"检测项": "Nmap OS", "结果": nmap_os, "置信度": "高"})
                logs.append(f"[Nmap] {nmap_os}")

        if "HTTP头" in methods:
            self.progress(80)
            http_info = self._http_fingerprint(host)
            for k, v in http_info.items():
                data.append({"检测项": k, "结果": v, "置信度": "中"})
                logs.append(f"[HTTP] {k}: {v}")

        self.progress(100, "完成")
        return ScanResult(
            True, "目标系统检测",
            data=data, logs=logs,
            summary=f"完成 {len(data)} 项检测",
        )

    def _ttl_detect(self, host: str) -> str:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            out = subprocess.run(
                ["ping", param, "1", host],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
            )
            m = re.search(r"TTL[=\s]+(\d+)", out.stdout, re.I)
            if m:
                ttl = int(m.group(1))
                hint = "未知"
                for (lo, hi), name in self.TTL_HINTS.items():
                    if lo <= ttl <= hi:
                        hint = name
                        break
                return f"TTL={ttl} 推测: {hint}"
        except Exception as exc:
            return f"TTL检测失败: {exc}"
        return "无法获取TTL"

    def _banner_detect(self, host: str, options: dict) -> List[str]:
        ports = [int(p) for p in options.get("banner_ports", "22,80,443").split(",")]
        results = []
        for port in ports:
            if self.cancelled:
                break
            if tcp_probe(host, port, 2.0):
                banner = grab_banner(host, port)
                if banner:
                    results.append(f"{host}:{port} -> {banner[:120]}")
        return results

    def _nmap_os(self, host: str, options: dict) -> str:
        try:
            nm = nmap.PortScanner()
            nm.scan(host, arguments="-O --osscan-limit")
            if host in nm.all_hosts():
                matches = nm[host].get("osmatch", [])
                if matches:
                    return matches[0].get("name", "未知")
                for d in nm[host].get("osclass", []):
                    return f"{d.get('osfamily', '')} {d.get('osgen', '')}".strip()
        except Exception as exc:
            return f"nmap失败: {exc}"
        return ""

    def _http_fingerprint(self, host: str) -> dict:
        import requests
        info = {}
        for scheme in ("https", "http"):
            try:
                resp = requests.get(
                    f"{scheme}://{host}", timeout=6, verify=False,
                    headers={"User-Agent": "SecurityScanner/1.0"},
                )
                info["Server"] = resp.headers.get("Server", "-")
                info["X-Powered-By"] = resp.headers.get("X-Powered-By", "-")
                info["状态码"] = str(resp.status_code)
                break
            except requests.RequestException:
                pass
        return info
