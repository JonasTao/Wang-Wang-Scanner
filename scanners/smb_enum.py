"""SMB / NetBIOS 信息枚举。"""
import socket
import struct
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host, tcp_probe


class SmbEnumScanner(BaseScanner):
    name = "smb"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "SMB 枚举", summary="请填写目标 IP 或主机名")

        host = resolve_host(target) or target
        port = int(options.get("port", 445))
        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        self.log(f"[*] SMB 探测 {host}:{port}")

        if not tcp_probe(host, port, 2.0):
            if tcp_probe(host, 139, 2.0):
                port = 139
                logs.append("[*] 139 端口开放，445 关闭")
            else:
                return ScanResult(True, "SMB 枚举", summary="SMB 端口未开放", logs=["[!] 445/139 均未开放"])

        data.append({"项目": "端口", "结果": f"{port} 开放", "详情": ""})
        logs.append(f"[+] {host}:{port} 开放")

        if options.get("nbns", True):
            self.progress(30)
            nb = self._netbios_query(host)
            if nb:
                for k, v in nb.items():
                    data.append({"项目": f"NetBIOS-{k}", "结果": v, "详情": ""})
                    logs.append(f"[NBNS] {k}: {v}")

        if options.get("null_session", False):
            self.progress(60)
            logs.append("[*] 空会话探测需 nmap/scripts，已记录端口状态")

        if options.get("os_hint", True):
            self.progress(80)
            banner = self._smb_banner(host, port)
            if banner:
                data.append({"项目": "SMB Banner", "结果": banner[:120], "详情": ""})
                logs.append(f"[Banner] {banner[:80]}")

        self.progress(100, "完成")
        return ScanResult(True, "SMB 枚举", data=data, logs=logs, summary=f"完成 {len(data)} 项")

    def _netbios_query(self, host: str) -> dict:
        result = {}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            name = (host.split(".")[0] if "." in host else host)[:15].upper().ljust(16)
            enc = "".join(chr((ord(c) >> 4) + 0x41) + chr((ord(c) & 0xF) + 0x41) for c in name[:16].ljust(16))
            # 简化 NBSTAT 请求
            pkt = struct.pack("!HHHH", 0, 0x0010, 1, 0) + struct.pack("!6s", b"\x00" * 6)
            pkt += struct.pack("!H", 0x20) + struct.pack("!H", 32)
            pkt += b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
            sock.sendto(pkt, (host if host.replace(".", "").isdigit() else socket.gethostbyname(host), 137))
            data, _ = sock.recvfrom(4096)
            if len(data) > 56:
                result["响应长度"] = str(len(data))
                result["状态"] = "NetBIOS 有响应"
            sock.close()
        except Exception as exc:
            result["错误"] = str(exc)[:80]
        return result

    def _smb_banner(self, host: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            # SMB2 negotiate protocol
            pkt = bytes.fromhex(
                "00000054ff534d42"  # header
                "7200020041000000"  # negotiate
                "0000000000000000"
                "0000000000000000"
                "0000000000000000"
                "0000000000000000"
                "2400050001000000"
                "0000000000000000"
                "0000000000000000"
                "0000000000000000"
                "0202000002000000"
                "0000000000000000"
            )
            sock.send(pkt[:64] if len(pkt) > 64 else pkt)
            data = sock.recv(256)
            sock.close()
            return data.hex()[:60] if data else ""
        except Exception:
            return ""
