"""人员 / 组织公开信息搜集。"""
import re
import socket
from typing import Any, Dict, List

import dns.resolver
import requests

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, resolve_host


class PersonnelScanner(BaseScanner):
    name = "personnel"

    EMAIL_PREFIXES = [
        "admin", "info", "contact", "support", "sales", "hr",
        "security", "webmaster", "postmaster", "abuse", "help",
    ]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        domain = normalize_target(options.get("domain", ""))
        if not domain:
            return ScanResult(False, "人员信息搜集", summary="请填写目标域名")

        mode = options.get("mode", "综合")
        check_email = options.get("check_email", True)
        check_whois_dns = options.get("check_whois_dns", True)
        check_pages = options.get("check_pages", True)
        custom_prefixes = options.get("custom_prefixes", "")

        data: List[Dict[str, Any]] = []
        logs: List[str] = []

        self.log(f"[*] 目标域名: {domain}")
        self.progress(5, "解析域名...")

        ip = resolve_host(domain)
        if ip:
            logs.append(f"[DNS] {domain} -> {ip}")
            data.append({"类型": "DNS解析", "内容": ip, "来源": "A记录"})

        prefixes = list(self.EMAIL_PREFIXES)
        if custom_prefixes:
            prefixes.extend(p.strip() for p in custom_prefixes.split(",") if p.strip())
        prefixes = list(dict.fromkeys(prefixes))

        total_steps = 3
        step = 0

        if check_whois_dns and mode in ("综合", "DNS/WHOIS", "仅DNS"):
            step += 1
            self._dns_records(domain, data, logs)
            self.progress(int(step / total_steps * 60))

        if check_email and mode in ("综合", "邮箱探测"):
            step += 1
            self._email_probe(domain, prefixes, data, logs, options)
            self.progress(int(step / total_steps * 80))

        if check_pages and mode in ("综合", "页面信息"):
            step += 1
            self._page_meta(domain, data, logs)
            self.progress(90)

        if self.cancelled:
            return ScanResult(False, "人员信息搜集", data=data, logs=logs, summary="已取消")

        self.progress(100, "完成")
        summary = f"共收集 {len(data)} 条线索，域名 {domain}"
        return ScanResult(True, "人员信息搜集", data=data, logs=logs, summary=summary)

    def _dns_records(self, domain: str, data: list, logs: list) -> None:
        record_types = ["MX", "NS", "TXT", "SOA"]
        for rtype in record_types:
            if self.cancelled:
                return
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for r in answers:
                    val = str(r).strip(".")
                    logs.append(f"[{rtype}] {val}")
                    data.append({"类型": f"DNS-{rtype}", "内容": val, "来源": domain})
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception as exc:
                logs.append(f"[{rtype}] 查询失败: {exc}")

        try:
            answers = dns.resolver.resolve(domain, "A")
            for r in answers:
                data.append({"类型": "DNS-A", "内容": str(r), "来源": domain})
        except Exception:
            pass

    def _email_probe(self, domain: str, prefixes: list, data: list, logs: list, options: dict) -> None:
        verify_smtp = options.get("verify_smtp", False)
        for i, prefix in enumerate(prefixes):
            if self.cancelled:
                return
            email = f"{prefix}@{domain}"
            status = "推测"
            if verify_smtp:
                status = self._smtp_check(email, domain)
            logs.append(f"[邮箱] {email} ({status})")
            data.append({"类型": "邮箱", "内容": email, "来源": status})
            self.progress(20 + int(50 * (i + 1) / len(prefixes)))

    def _smtp_check(self, email: str, domain: str) -> str:
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            mx_host = str(mx_records[0].exchange).strip(".")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((mx_host, 25))
            sock.recv(1024)
            sock.send(b"HELO scanner.local\r\n")
            sock.recv(1024)
            sock.send(f"MAIL FROM:<probe@scanner.local>\r\n".encode())
            sock.recv(1024)
            sock.send(f"RCPT TO:<{email}>\r\n".encode())
            resp = sock.recv(1024).decode(errors="replace")
            sock.send(b"QUIT\r\n")
            sock.close()
            if "250" in resp or "251" in resp:
                return "SMTP可能有效"
            if "550" in resp:
                return "SMTP拒绝"
            return "SMTP未知"
        except Exception:
            return "SMTP不可达"

    def _page_meta(self, domain: str, data: list, logs: list) -> None:
        for scheme in ("https", "http"):
            if self.cancelled:
                return
            url = f"{scheme}://{domain}"
            try:
                resp = requests.get(
                    url, timeout=8, verify=False,
                    headers={"User-Agent": "SecurityScanner/1.0"},
                )
                text = resp.text[:50000]
                logs.append(f"[页面] {url} 状态码 {resp.status_code}")

                emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text))
                for em in emails:
                    data.append({"类型": "页面邮箱", "内容": em, "来源": url})

                titles = re.findall(r"<title[^>]*>([^<]+)</title>", text, re.I)
                for t in titles[:3]:
                    data.append({"类型": "页面标题", "内容": t.strip(), "来源": url})

                for tag, attr in (("meta", "name"),):
                    pass
                author = re.search(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)', text, re.I)
                if author:
                    data.append({"类型": "作者", "内容": author.group(1), "来源": url})
                break
            except requests.RequestException as exc:
                logs.append(f"[页面] {url} 失败: {exc}")
