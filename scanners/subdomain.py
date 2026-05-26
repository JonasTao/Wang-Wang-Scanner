"""子域名专项枚举。"""
from typing import Any, Dict, List

import requests

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host, parallel_map


class SubdomainScanner(BaseScanner):
    name = "subdomain"

    WORDLIST = [
        "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "beta",
        "vpn", "portal", "cdn", "static", "blog", "shop", "m", "mobile", "wap",
        "oa", "crm", "erp", "git", "gitlab", "jenkins", "grafana", "kibana",
        "monitor", "zabbix", "nas", "cloud", "docs", "help", "support", "img",
        "image", "video", "download", "upload", "files", "db", "mysql", "redis",
        "mq", "kafka", "elastic", "es", "solr", "tomcat", "nginx", "proxy",
    ]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        domain = normalize_target(options.get("domain", ""))
        if not domain:
            return ScanResult(False, "子域名枚举", summary="请填写主域名")

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        methods = options.get("methods", ["字典爆破", "证书透明度"])

        custom = options.get("wordlist", "")
        subs = list(self.WORDLIST)
        if custom:
            subs.extend(s.strip() for s in custom.replace("\n", ",").split(",") if s.strip())
        subs = list(dict.fromkeys(subs))

        if "字典爆破" in methods:
            self._bruteforce(domain, subs, data, logs, options)
        if self.cancelled:
            return ScanResult(False, "子域名枚举", data=data, logs=logs, summary="已取消")

        if "证书透明度" in methods:
            self._crtsh(domain, data, logs)

        if "搜索引擎" in methods:
            self._search_hint(domain, data, logs)

        self.progress(100, "完成")
        return ScanResult(
            True, "子域名枚举", data=data, logs=logs,
            summary=f"发现 {len(data)} 个有效子域",
        )

    def _bruteforce(self, domain: str, subs: list, data: list, logs: list, options: dict) -> None:
        threads = int(options.get("threads", 40))
        total = len(subs)

        def check(sub: str):
            fqdn = f"{sub}.{domain}" if not sub.endswith(domain) else sub
            ip = resolve_host(fqdn)
            return fqdn, ip

        results = parallel_map(subs, check, workers=threads, cancel_check=lambda: self.cancelled)
        for i, (_, res) in enumerate(results):
            if isinstance(res, Exception):
                continue
            fqdn, ip = res
            if ip:
                logs.append(f"[+] {fqdn} -> {ip}")
                data.append({"子域名": fqdn, "IP": ip, "来源": "字典"})
            self.progress(int(60 * (i + 1) / total))

    def _crtsh(self, domain: str, data: list, logs: list) -> None:
        self.log("[*] 查询 crt.sh ...")
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json", timeout=20,
            )
            if resp.status_code != 200:
                return
            seen = set()
            for entry in resp.json()[:150]:
                for n in entry.get("name_value", "").split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith(domain) and n not in seen and "*" not in n:
                        seen.add(n)
                        ip = resolve_host(n)
                        if ip:
                            data.append({"子域名": n, "IP": ip, "来源": "CT证书"})
            logs.append(f"[CT] 证书透明度 {len(seen)} 条")
        except Exception as exc:
            logs.append(f"[CT] 失败: {exc}")
        self.progress(85)

    def _search_hint(self, domain: str, data: list, logs: list) -> None:
        logs.append(f"[提示] 可在搜索引擎使用: site:*.{domain}")
        data.append({"子域名": f"*.{domain}", "IP": "-", "来源": "搜索语法提示"})
