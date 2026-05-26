"""SNMP 团体字探测与信息收集。"""
import socket
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host


class SnmpScanner(BaseScanner):
    name = "snmp"

    DEFAULT_COMMUNITIES = [
        "public", "private", "community", "manager", "snmp", "cisco",
        "admin", "default", "read", "write", "public123", "private123",
    ]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        target = normalize_target(options.get("target", ""))
        if not target:
            return ScanResult(False, "SNMP 探测", summary="请填写目标 IP")

        host = resolve_host(target) or target
        port = int(options.get("port", 161))
        communities = options.get("communities", "").split(",") if options.get("communities") else self.DEFAULT_COMMUNITIES
        communities = [c.strip() for c in communities if c.strip()]
        version = options.get("version", "v2c")

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] SNMP 探测 {host}:{port}")

        if not self._udp_open(host, port):
            logs.append("[!] UDP 161 无响应 (可能被过滤)")
            data.append({"团体字": "-", "状态": "端口无响应", "信息": "UDP 161 filtered"})

        for i, comm in enumerate(communities):
            if self.cancelled:
                break
            ok, info = self._try_community(host, port, comm, version)
            if ok:
                data.append({"团体字": comm, "状态": "有效", "信息": info})
                logs.append(f"[!] 有效团体字: {comm} -> {info}")
            self.progress(int(95 * (i + 1) / len(communities)))

        self.progress(100, "完成")
        summary = f"发现 {len([d for d in data if d.get('状态') == '有效'])} 个有效团体字"
        return ScanResult(True, "SNMP 探测", data=data, logs=logs, summary=summary)

    def _udp_open(self, host: str, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            # SNMPv2c get-request sysDescr.0
            comm = b"public"
            oid = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            pkt = self._build_snmp_get(comm, oid)
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(4096)
            return len(data) > 0
        except socket.timeout:
            return False
        except OSError:
            return False
        finally:
            sock.close()

    def _try_community(self, host: str, port: int, community: str, version: str) -> tuple:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            oid = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            pkt = self._build_snmp_get(community.encode(), oid)
            sock.sendto(pkt, (host, port))
            data, _ = sock.recvfrom(4096)
            if len(data) > 20 and data[0] == 0x30:
                return True, f"响应 {len(data)} 字节"
        except (socket.timeout, OSError):
            pass
        finally:
            sock.close()
        return False, ""

    def _build_snmp_get(self, community: bytes, oid: bytes) -> bytes:
        # 简化 SNMPv2c GET PDU
        comm_tlv = b"\x04" + bytes([len(community)]) + community
        comm_seq = b"\x04" + bytes([len(comm_tlv)]) + comm_tlv
        oid_tlv = b"\x06" + bytes([len(oid)]) + oid
        null_tlv = b"\x05\x00"
        varbind = b"\x30" + bytes([len(oid_tlv + null_tlv)]) + oid_tlv + null_tlv
        varbind_list = b"\x30" + bytes([len(varbind)]) + varbind
        req_id = b"\x02\x01\x01"
        err = b"\x02\x01\x00\x02\x01\x00\x02\x01\x00"
        pdu_content = req_id + err + varbind_list
        get_pdu = b"\xa0" + bytes([len(pdu_content)]) + pdu_content
        version = b"\x02\x01\x01"
        outer = version + comm_seq + get_pdu
        return b"\x30" + bytes([len(outer)]) + outer
