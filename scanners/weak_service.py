"""常见服务弱配置 / 未授权检测。"""
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host, tcp_probe, http_get


class WeakServiceScanner(BaseScanner):
    name = "weak"

    CHECKS = {
        "Redis 未授权": (6379, "redis"),
        "MongoDB": (27017, "mongo"),
        "Elasticsearch": (9200, "elastic"),
        "Memcached": (11211, "memcache"),
        "Docker API": (2375, "docker"),
        "FTP": (21, "ftp"),
    }

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "弱配置检测", summary="请填写目标")

        host = resolve_host(target) or target
        enabled = options.get("checks", list(self.CHECKS.keys()))
        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        self.log(f"[*] 弱配置检测 {host}")
        total = len(enabled)
        for i, name in enumerate(enabled):
            if self.cancelled:
                break
            if name not in self.CHECKS:
                continue
            port, svc = self.CHECKS[name]
            if not tcp_probe(host, port, 2.0):
                self.progress(int(95 * (i + 1) / total))
                continue

            result = self._probe_service(host, port, svc)
            if result:
                data.append({
                    "服务": name, "端口": port, "结果": result,
                    "风险": "高" if "未授权" in result or "匿名" in result else "中",
                })
                logs.append(f"[!] {name}: {result}")
            self.progress(int(95 * (i + 1) / total))

        self.progress(100, "完成")
        return ScanResult(
            True, "弱配置检测", data=data, logs=logs,
            summary=f"发现 {len(data)} 个风险项",
        )

    def _probe_service(self, host: str, port: int, svc: str) -> str:
        import socket
        if svc == "redis":
            try:
                s = socket.create_connection((host, port), timeout=3)
                s.send(b"PING\r\n")
                r = s.recv(64).decode(errors="replace")
                s.close()
                if "PONG" in r or "+PONG" in r:
                    s2 = socket.create_connection((host, port), timeout=3)
                    s2.send(b"INFO\r\n")
                    info = s2.recv(200).decode(errors="replace")
                    s2.close()
                    return "Redis 未授权访问" if "redis_version" in info else "Redis 响应异常"
            except OSError:
                pass
        elif svc == "elastic":
            r = http_get(f"http://{host}:{port}/", timeout=4, verify_ssl=False)
            if r and r.status_code == 200 and "cluster_name" in r.text:
                return "Elasticsearch 未授权"
        elif svc == "docker":
            r = http_get(f"http://{host}:{port}/version", timeout=4, verify_ssl=False)
            if r and r.status_code == 200:
                return "Docker API 暴露"
        elif svc == "mongo":
            try:
                s = socket.create_connection((host, port), timeout=3)
                s.close()
                return "MongoDB 端口开放 (需专用工具深度检测)"
            except OSError:
                pass
        elif svc == "ftp":
            try:
                s = socket.create_connection((host, port), timeout=3)
                banner = s.recv(256).decode(errors="replace")
                s.close()
                if "220" in banner:
                    return f"FTP Banner: {banner[:60]}"
            except OSError:
                pass
        return ""
