"""网站漏洞 / 安全基线扫描（授权测试）。"""
import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import http_get, normalize_target, ssl_info


class WebVulnScanner(BaseScanner):
    name = "web"

    DIR_WORDLIST = [
        "admin", "login", "backup", "api", "test", "upload", "config",
        ".git", ".env", "robots.txt", "sitemap.xml", "wp-admin", "phpmyadmin",
        "console", "manager", "actuator", "swagger", "debug",
    ]

    SQLI_PAYLOADS = ["'", "\"", "1' OR '1'='1", "1 AND 1=1--"]
    XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        url = normalize_target(options.get("url", ""))
        if not url:
            return ScanResult(False, "网站漏洞扫描", summary="请填写目标 URL")

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        checks = options.get("checks", [
            "安全响应头", "SSL证书", "敏感目录", "SQL注入探测", "XSS探测", "信息泄露",
        ])
        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        severity_count = {"高": 0, "中": 0, "低": 0, "信息": 0}

        self.log(f"[*] Web 扫描: {url}")
        self.progress(5)

        if "安全响应头" in checks:
            self._check_headers(url, data, logs, severity_count)
        if self.cancelled:
            return ScanResult(False, "网站漏洞扫描", data=data, logs=logs, summary="已取消")

        if "SSL证书" in checks:
            self.progress(25)
            self._check_ssl(url, data, logs, severity_count)

        if "敏感目录" in checks:
            self.progress(40)
            self._dir_bruteforce(url, data, logs, options, severity_count)

        if "SQL注入探测" in checks and options.get("sqli", True):
            self.progress(60)
            self._sqli_probe(url, data, logs, options, severity_count)

        if "XSS探测" in checks and options.get("xss", True):
            self.progress(75)
            self._xss_probe(url, data, logs, options, severity_count)

        if "信息泄露" in checks:
            self.progress(88)
            self._info_leak(url, data, logs, severity_count)

        if options.get("crawl_links", False):
            self._crawl_links(url, data, logs)

        self.progress(100, "完成")
        summary = (
            f"发现 {len(data)} 个问题 | "
            f"高:{severity_count['高']} 中:{severity_count['中']} "
            f"低:{severity_count['低']} 信息:{severity_count['信息']}"
        )
        return ScanResult(True, "网站漏洞扫描", data=data, logs=logs, summary=summary)

    def _add_finding(self, data, logs, severity_count, severity, vuln, detail, url):
        severity_count[severity] = severity_count.get(severity, 0) + 1
        data.append({"严重程度": severity, "漏洞类型": vuln, "详情": detail, "URL": url})
        logs.append(f"[{severity}] {vuln}: {detail}")

    def _check_headers(self, url, data, logs, sc):
        resp = http_get(url, verify_ssl=False)
        if not resp:
            logs.append("[!] 无法访问目标")
            return
        required = {
            "X-Frame-Options": ("中", "点击劫持防护缺失"),
            "X-Content-Type-Options": ("低", "MIME嗅探防护缺失"),
            "Strict-Transport-Security": ("中", "HSTS未启用"),
            "Content-Security-Policy": ("低", "CSP未配置"),
        }
        for header, (sev, msg) in required.items():
            if header not in resp.headers:
                self._add_finding(data, logs, sc, sev, "安全头缺失", f"{header} - {msg}", url)
        if "Server" in resp.headers:
            self._add_finding(
                data, logs, sc, "信息", "版本泄露",
                f"Server: {resp.headers['Server']}", url,
            )

    def _check_ssl(self, url, data, logs, sc):
        parsed = urlparse(url)
        if parsed.scheme != "https":
            self._add_finding(data, logs, sc, "中", "传输安全", "站点未强制 HTTPS", url)
            return
        info = ssl_info(parsed.hostname or "", parsed.port or 443)
        if "error" in info:
            self._add_finding(data, logs, sc, "高", "SSL错误", info["error"], url)
        else:
            data.append({
                "严重程度": "信息", "漏洞类型": "SSL信息",
                "详情": f"协议 {info.get('protocol')} 加密 {info.get('cipher')}",
                "URL": url,
            })

    def _dir_bruteforce(self, url, data, logs, options, sc):
        words = self.DIR_WORDLIST
        custom = options.get("custom_paths", "")
        if custom:
            words = words + [w.strip() for w in custom.split(",") if w.strip()]
        max_paths = int(options.get("max_paths", 30))
        words = words[:max_paths]

        for i, path in enumerate(words):
            if self.cancelled:
                return
            test_url = urljoin(url.rstrip("/") + "/", path)
            resp = http_get(test_url, timeout=5, verify_ssl=False)
            if resp and resp.status_code in (200, 301, 302, 403):
                sev = "中" if resp.status_code == 200 else "低"
                self._add_finding(
                    data, logs, sc, sev, "敏感路径",
                    f"{path} 状态码 {resp.status_code}", test_url,
                )
            self.progress(40 + int(20 * (i + 1) / len(words)))

    def _sqli_probe(self, url, data, logs, options, sc):
        resp = http_get(url, verify_ssl=False)
        if not resp:
            return
        parsed = urlparse(url)
        if not parsed.query:
            logs.append("[*] URL 无参数，跳过主动 SQLi（可对表单扩展）")
            return
        base = url.split("?")[0]
        params = parsed.query.split("&")
        for param in params[:5]:
            if self.cancelled:
                return
            key = param.split("=")[0]
            for payload in self.SQLI_PAYLOADS[: int(options.get("sqli_depth", 2))]:
                test = f"{base}?{key}={payload}"
                r = http_get(test, timeout=6, verify_ssl=False)
                if r and self._sql_error(r.text):
                    self._add_finding(
                        data, logs, sc, "高", "SQL注入",
                        f"参数 {key} 可能存在注入 (payload: {payload})", test,
                    )

    def _xss_probe(self, url, data, logs, options, sc):
        parsed = urlparse(url)
        if not parsed.query:
            return
        base = url.split("?")[0]
        for param in parsed.query.split("&")[:3]:
            key = param.split("=")[0]
            for payload in self.XSS_PAYLOADS[:1]:
                if self.cancelled:
                    return
                test = f"{base}?{key}={payload}"
                r = http_get(test, timeout=6, verify_ssl=False)
                if r and payload in r.text:
                    self._add_finding(
                        data, logs, sc, "高", "反射型XSS",
                        f"参数 {key} 回显 payload", test,
                    )

    def _info_leak(self, url, data, logs, sc):
        resp = http_get(url, verify_ssl=False)
        if not resp:
            return
        patterns = [
            (r"api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9]{16,}", "API密钥泄露"),
            (r"password\s*[:=]\s*['\"][^'\"]+['\"]", "密码硬编码"),
            (r"BEGIN (RSA )?PRIVATE KEY", "私钥泄露"),
        ]
        for pat, name in patterns:
            if re.search(pat, resp.text, re.I):
                self._add_finding(data, logs, sc, "高", name, "页面源码中发现敏感模式", url)

        comments = re.findall(r"<!--(.*?)-->", resp.text, re.S)
        for c in comments[:5]:
            if len(c.strip()) > 20:
                self._add_finding(data, logs, sc, "低", "HTML注释泄露", c.strip()[:80], url)

    def _crawl_links(self, url, data, logs):
        resp = http_get(url, verify_ssl=False)
        if not resp:
            return
        soup = BeautifulSoup(resp.text, "lxml")
        links = set(a.get("href", "") for a in soup.find_all("a", href=True))
        for link in list(links)[:20]:
            logs.append(f"[链接] {link}")
            data.append({"严重程度": "信息", "漏洞类型": "爬取链接", "详情": link, "URL": url})

    @staticmethod
    def _sql_error(text: str) -> bool:
        errors = [
            "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL",
            "SQLite/JDBCDriver", "unclosed quotation", "ODBC SQL Server",
        ]
        t = text.lower()
        return any(e.lower() in t for e in errors)
