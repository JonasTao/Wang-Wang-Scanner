"""API / 接口端点发现。"""
import json
import re
from typing import Any, Dict, List
from urllib.parse import urljoin

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, http_get


class ApiDiscoveryScanner(BaseScanner):
    name = "api"

    API_PATHS = [
        ("/api", "REST API 根"),
        ("/api/v1", "API v1"),
        ("/api/v2", "API v2"),
        ("/swagger", "Swagger"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/swagger/index.html", "Swagger Index"),
        ("/v2/api-docs", "Swagger JSON"),
        ("/v3/api-docs", "OpenAPI 3"),
        ("/openapi.json", "OpenAPI"),
        ("/graphql", "GraphQL"),
        ("/graphiql", "GraphiQL"),
        ("/actuator", "Spring Actuator"),
        ("/actuator/env", "Actuator Env"),
        ("/actuator/heapdump", "Heapdump"),
        ("/druid/index.html", "Druid 监控"),
        ("/api-docs", "API Docs"),
        ("/.well-known/openapi", "OpenAPI Well-known"),
        ("/ws", "WebSocket"),
        ("/socket.io", "Socket.IO"),
    ]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        url = normalize_target(options.get("url", ""))
        if not url:
            return ScanResult(False, "API 接口发现", summary="请填写 URL")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        paths = list(self.API_PATHS)
        custom = options.get("custom_paths", "")
        if custom:
            for p in custom.split(","):
                p = p.strip()
                if p:
                    paths.append((p, "自定义"))

        parse_swagger = options.get("parse_swagger", True)
        max_n = int(options.get("max_paths", 25))
        paths = paths[:max_n]

        self.log(f"[*] API 发现 {url}")
        for i, (path, name) in enumerate(paths):
            if self.cancelled:
                return ScanResult(False, "API 接口发现", data=data, logs=logs, summary="已取消")
            test = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
            resp = http_get(test, timeout=6, verify_ssl=False)
            if resp and resp.status_code in (200, 301, 302, 401, 403, 405):
                ctype = resp.headers.get("Content-Type", "")
                endpoints = ""
                if parse_swagger and "json" in ctype and resp.status_code == 200:
                    endpoints = self._parse_openapi(resp.text)
                data.append({
                    "端点": path, "名称": name, "状态码": resp.status_code,
                    "类型": ctype[:40], "解析": endpoints[:120] or "-",
                })
                logs.append(f"[+] {path} -> {resp.status_code}")
            self.progress(int(95 * (i + 1) / len(paths)))

        if options.get("js_extract", True):
            self._extract_from_js(url, data, logs)

        self.progress(100, "完成")
        return ScanResult(True, "API 接口发现", data=data, logs=logs, summary=f"发现 {len(data)} 个接口")

    def _parse_openapi(self, text: str) -> str:
        try:
            doc = json.loads(text)
            paths = list(doc.get("paths", {}).keys())[:8]
            return ", ".join(paths)
        except json.JSONDecodeError:
            return ""

    def _extract_from_js(self, base: str, data: list, logs: list) -> None:
        resp = http_get(base, timeout=8, verify_ssl=False)
        if not resp:
            return
        apis = set(re.findall(r'["\'](/api[/a-zA-Z0-9_\-./{}]+)["\']', resp.text))
        for api in list(apis)[:15]:
            data.append({
                "端点": api, "名称": "JS 提取", "状态码": "-",
                "类型": "script", "解析": "页面脚本",
            })
            logs.append(f"[JS] {api}")
