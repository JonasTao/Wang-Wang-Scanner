"""SSL/TLS 深度证书与加密套件检测。"""
import ssl
import socket
from typing import Any, Dict, List
from datetime import datetime

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host, url_to_host


class SslDeepScanner(BaseScanner):
    name = "ssl"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "SSL/TLS 检测", summary="请填写主机或 URL")

        host = url_to_host(target) if "://" in target else target
        host = resolve_host(host) or host
        port = int(options.get("port", 443))

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] SSL 检测 {host}:{port}")

        ctx = ssl.create_default_context()
        if options.get("allow_weak", False):
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    data.append({"项目": "协议版本", "值": version or "-", "状态": "信息"})
                    if cipher:
                        data.append({"项目": "加密套件", "值": f"{cipher[0]} {cipher[1]}bit", "状态": "信息"})
                        logs.append(f"[Cipher] {cipher}")

                    if cert:
                        self._parse_cert(cert, data, logs, options)

                    if options.get("check_expiry", True):
                        self._check_expiry(cert, data, logs)

        except ssl.SSLError as exc:
            data.append({"项目": "SSL错误", "值": str(exc), "状态": "高"})
            logs.append(f"[!] SSL: {exc}")
        except OSError as exc:
            return ScanResult(False, "SSL/TLS 检测", logs=[str(exc)], summary="连接失败")

        if options.get("test_versions", False):
            self._test_protocols(host, port, data, logs)

        self.progress(100, "完成")
        return ScanResult(True, "SSL/TLS 检测", data=data, logs=logs, summary=f"{len(data)} 项 SSL 信息")

    def _parse_cert(self, cert: dict, data: list, logs: list, options: dict) -> None:
        subj = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        data.append({"项目": "主题 CN", "值": subj.get("commonName", "-"), "状态": "信息"})
        data.append({"项目": "颁发者", "值": issuer.get("organizationName", issuer.get("commonName", "-")), "状态": "信息"})
        sans = [v for _, v in cert.get("subjectAltName", ())]
        if sans:
            data.append({"项目": "SAN", "值": ", ".join(sans[:10]), "状态": "信息"})
        logs.append(f"[Cert] CN={subj.get('commonName')}")

    def _check_expiry(self, cert: dict, data: list, logs: list) -> None:
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                status = "高" if days < 0 else ("中" if days < 30 else "信息")
                data.append({"项目": "证书过期", "值": f"{not_after} ({days}天)", "状态": status})
                logs.append(f"[过期] 剩余 {days} 天")
            except ValueError:
                data.append({"项目": "证书过期", "值": not_after, "状态": "信息"})

    def _test_protocols(self, host: str, port: int, data: list, logs: list) -> None:
        for proto_name, proto in [("TLSv1", ssl.PROTOCOL_TLS_CLIENT)]:
            try:
                ctx = ssl.SSLContext(proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=3) as s:
                    with ctx.wrap_socket(s) as ss:
                        data.append({"项目": "协议探测", "值": ss.version() or proto_name, "状态": "信息"})
            except Exception:
                pass
