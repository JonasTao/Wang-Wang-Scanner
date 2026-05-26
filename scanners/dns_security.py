"""DNS 安全与邮件安全记录检测。"""
from typing import Any, Dict, List

import dns.resolver

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host


class DnsSecurityScanner(BaseScanner):
    name = "dns_security"

    def run(self, options: Dict[str, Any]) -> ScanResult:
        domain = normalize_target(options.get("domain", ""))
        if not domain:
            return ScanResult(False, "DNS 安全检测", summary="请填写域名")

        checks = options.get("checks", ["SPF", "DMARC", "DKIM", "DNSSEC", "区域传送"])
        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        self.log(f"[*] DNS 安全: {domain}")
        step, total = 0, max(len(checks), 1)

        if "SPF" in checks:
            step += 1
            self._txt_record(domain, "v=spf1", "SPF", data, logs)
            self.progress(int(step / total * 80))

        if "DMARC" in checks:
            step += 1
            self._txt_record(f"_dmarc.{domain}", "v=DMARC1", "DMARC", data, logs)

        if "DKIM" in checks:
            step += 1
            selectors = options.get("dkim_selectors", "default,google,domainkey,selector1,selector2").split(",")
            for sel in selectors:
                if self.cancelled:
                    break
                self._txt_record(f"{sel.strip()}._domainkey.{domain}", "v=DKIM1", f"DKIM({sel})", data, logs)

        if "DNSSEC" in checks:
            step += 1
            try:
                dns.resolver.resolve(domain, "DNSKEY")
                data.append({"检测项": "DNSSEC", "结果": "存在 DNSKEY", "风险": "信息"})
                logs.append("[DNSSEC] 检测到 DNSKEY")
            except Exception:
                data.append({"检测项": "DNSSEC", "结果": "未检测到或未启用", "风险": "低"})
                logs.append("[DNSSEC] 未启用或未公开")

        if "区域传送" in checks:
            step += 1
            self._zone_transfer(domain, data, logs)

        if "CAA" in checks:
            try:
                ans = dns.resolver.resolve(domain, "CAA")
                for r in ans:
                    data.append({"检测项": "CAA", "结果": str(r), "风险": "信息"})
            except Exception:
                data.append({"检测项": "CAA", "结果": "无 CAA 记录", "风险": "低"})

        self.progress(100, "完成")
        return ScanResult(True, "DNS 安全检测", data=data, logs=logs, summary=f"完成 {len(data)} 项检测")

    def _txt_record(self, name: str, prefix: str, label: str, data: list, logs: list) -> None:
        try:
            ans = dns.resolver.resolve(name, "TXT")
            for r in ans:
                txt = str(r).strip('"')
                if prefix.lower() in txt.lower() or label.startswith("DKIM"):
                    data.append({"检测项": label, "结果": txt[:200], "风险": "信息"})
                    logs.append(f"[{label}] {txt[:100]}")
                    return
            data.append({"检测项": label, "结果": "有 TXT 但格式异常", "风险": "中"})
        except Exception:
            data.append({"检测项": label, "结果": "未配置", "风险": "中" if label in ("SPF", "DMARC") else "低"})
            logs.append(f"[{label}] 未找到记录")

    def _zone_transfer(self, domain: str, data: list, logs: list) -> None:
        try:
            import dns.query
            import dns.zone
            ns = dns.resolver.resolve(domain, "NS")
            for ns_rr in ns:
                ns_host = str(ns_rr).strip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, lifetime=5))
                    if zone:
                        data.append({"检测项": "区域传送", "结果": f"{ns_host} 允许 AXFR!", "风险": "高"})
                        logs.append(f"[!] 区域传送成功: {ns_host}")
                        return
                except Exception:
                    pass
            data.append({"检测项": "区域传送", "结果": "未成功 (正常)", "风险": "信息"})
            logs.append("[AXFR] 区域传送被拒绝")
        except Exception as exc:
            logs.append(f"[AXFR] {exc}")
