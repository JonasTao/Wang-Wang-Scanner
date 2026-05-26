"""Web 指纹：技术栈 / WAF / CDN 识别。"""
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, http_get


class WebFingerprintScanner(BaseScanner):
    name = "web_fingerprint"

    WAF_SIGNS = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "阿里云 WAF": ["aliyungf", "acw_tc"],
        "腾讯云 WAF": ["tencent-waf", "x-waf"],
        "AWS WAF": ["awselb", "x-amzn"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Safe3": ["safe3waf"],
    }

    CDN_SIGNS = {
        "Cloudflare": ["cloudflare"],
        "Akamai": ["akamai"],
        "Fastly": ["fastly"],
        "阿里云 CDN": ["alicdn", "aliyuncs"],
        "腾讯云 CDN": ["cdn.myqcloud", "tencentcdn"],
        "百度云 CDN": ["bdstatic", "baiduyun"],
    }

    CMS_SIGNS = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["drupal", "sites/default"],
        "Joomla": ["joomla", "/components/com_"],
        "ThinkPHP": ["thinkphp", "think\\"],
        "Spring": ["whitelabel", "spring", "actuator"],
        "Vue": ["vue.js", "__vue__"],
        "React": ["react", "_next/static"],
        "Django": ["csrfmiddlewaretoken", "django"],
    }

    def run(self, options: Dict[str, Any]) -> ScanResult:
        url = normalize_target(options.get("url", ""))
        if not url:
            return ScanResult(False, "Web 指纹识别", summary="请填写 URL")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        self.log(f"[*] 指纹扫描: {url}")

        resp = http_get(url, timeout=10, verify_ssl=options.get("verify_ssl", False))
        if not resp:
            return ScanResult(False, "Web 指纹识别", summary="无法访问目标")

        checks = options.get("checks", ["响应头", "WAF", "CDN", "CMS", "Cookie", "页面特征"])

        if "响应头" in checks:
            for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
                v = resp.headers.get(h, "")
                if v:
                    data.append({"类别": "响应头", "名称": h, "值": v})
                    logs.append(f"[头] {h}: {v}")

        body_lower = resp.text.lower()
        headers_str = str(resp.headers).lower()

        if "WAF" in checks:
            for name, signs in self.WAF_SIGNS.items():
                if any(s in headers_str or s in body_lower for s in signs):
                    data.append({"类别": "WAF", "名称": name, "值": "疑似存在"})
                    logs.append(f"[WAF] 检测到 {name}")

        if "CDN" in checks:
            for name, signs in self.CDN_SIGNS.items():
                if any(s in headers_str for s in signs):
                    data.append({"类别": "CDN", "名称": name, "值": "疑似使用"})
                    logs.append(f"[CDN] {name}")

        if "CMS" in checks:
            for name, signs in self.CMS_SIGNS.items():
                if any(s in body_lower for s in signs):
                    data.append({"类别": "CMS/框架", "名称": name, "值": "页面特征匹配"})
                    logs.append(f"[CMS] {name}")

        if "Cookie" in checks:
            for c in resp.cookies:
                data.append({"类别": "Cookie", "名称": c.name, "值": c.value[:80]})

        if "页面特征" in checks:
            title = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
            if title:
                data.append({"类别": "页面", "名称": "Title", "值": title.group(1).strip()[:100]})
            fav = re.search(r'rel=["\']icon["\'][^>]+href=["\']([^"\']+)', resp.text, re.I)
            if fav:
                data.append({"类别": "页面", "名称": "Favicon", "值": fav.group(1)[:100]})

        if options.get("probe_paths", True):
            self._probe_tech_paths(url, data, logs)

        self.progress(100, "完成")
        return ScanResult(True, "Web 指纹识别", data=data, logs=logs, summary=f"识别 {len(data)} 项特征")

    def _probe_tech_paths(self, base: str, data: list, logs: list) -> None:
        paths = {
            "/robots.txt": "robots",
            "/sitemap.xml": "sitemap",
            "/.well-known/security.txt": "security.txt",
            "/actuator/health": "Spring Actuator",
            "/swagger-ui.html": "Swagger",
            "/api": "API",
        }
        parsed = urlparse(base)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path, name in paths.items():
            if self.cancelled:
                return
            r = http_get(origin + path, timeout=5, verify_ssl=False)
            if r and r.status_code in (200, 301, 302, 401, 403):
                data.append({"类别": "路径探测", "名称": name, "值": f"{path} [{r.status_code}]"})
                logs.append(f"[路径] {path} -> {r.status_code}")
