"""WHOIS 域名注册信息查询。"""
from typing import Any, Dict, List

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target


class WhoisScanner(BaseScanner):
    name = "whois"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        domain = normalize_target(options.get("domain", ""))
        if not domain:
            return ScanResult(False, "WHOIS 查询", summary="请填写域名")

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] WHOIS 查询: {domain}")

        try:
            import whois
            w = whois.whois(domain)
        except Exception as exc:
            return ScanResult(False, "WHOIS 查询", logs=[f"[!] {exc}"], summary="查询失败")

        fields = options.get("fields", "全部")
        mapping = {
            "域名": w.domain_name,
            "注册商": w.registrar,
            "创建时间": w.creation_date,
            "过期时间": w.expiration_date,
            "更新时间": w.updated_date,
            "DNS 服务器": w.name_servers,
            "注册人": w.name,
            "组织": w.org,
            "国家": w.country,
            "邮箱": w.emails,
            "状态": w.status,
        }

        for key, val in mapping.items():
            if self.cancelled:
                break
            if val is None:
                continue
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            else:
                val = str(val)
            if fields != "全部" and key not in fields.split(","):
                continue
            data.append({"字段": key, "值": val[:300]})
            logs.append(f"[WHOIS] {key}: {val[:120]}")

        self.progress(100, "完成")
        return ScanResult(True, "WHOIS 查询", data=data, logs=logs, summary=f"获取 {len(data)} 项 WHOIS 信息")
