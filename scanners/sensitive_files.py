"""敏感文件与源码泄露探测。"""
from typing import Any, Dict, List
from urllib.parse import urljoin

from core.scanner_base import BaseScanner, ScanResult
from scanners.utils import normalize_target, http_get


class SensitiveFileScanner(BaseScanner):
    name = "sensitive"

    PATHS = [
        (".git/HEAD", "Git 泄露", "高"),
        (".git/config", "Git 配置", "高"),
        (".env", "环境变量", "高"),
        (".env.bak", "环境变量备份", "高"),
        ("backup.zip", "备份压缩包", "高"),
        ("backup.sql", "数据库备份", "高"),
        ("web.config", "配置文件", "中"),
        ("config.php.bak", "PHP 配置备份", "高"),
        ("database.yml", "Rails 数据库配置", "高"),
        (".svn/entries", "SVN 泄露", "高"),
        (".DS_Store", "目录索引", "低"),
        ("phpinfo.php", "PHPInfo", "中"),
        ("server-status", "Apache 状态", "中"),
        ("crossdomain.xml", "Flash 跨域", "低"),
        ("package.json", "Node 依赖", "低"),
        ("composer.json", "PHP 依赖", "低"),
        ("WEB-INF/web.xml", "Java Web", "中"),
        ("id_rsa", "SSH 私钥", "高"),
        (".bash_history", "历史命令", "高"),
        ("dump.sql", "SQL 导出", "高"),
    ]

    def run(self, options: Dict[str, Any]) -> ScanResult:
        url = normalize_target(options.get("url", ""))
        if not url:
            return ScanResult(False, "敏感文件探测", summary="请填写 URL")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        data: List[Dict[str, Any]] = []
        logs: List[str] = []
        paths = list(self.PATHS)
        custom = options.get("custom_paths", "")
        if custom:
            for p in custom.split(","):
                p = p.strip()
                if p:
                    paths.append((p, "自定义", "中"))

        max_n = int(options.get("max_paths", 40))
        paths = paths[:max_n]
        check_content = options.get("verify_content", True)

        self.log(f"[*] 探测 {len(paths)} 个敏感路径")
        for i, (path, name, sev) in enumerate(paths):
            if self.cancelled:
                return ScanResult(False, "敏感文件探测", data=data, logs=logs, summary="已取消")
            test_url = urljoin(url.rstrip("/") + "/", path)
            resp = http_get(test_url, timeout=6, verify_ssl=False)
            if resp and resp.status_code in (200, 206):
                hit = True
                if check_content and resp.status_code == 200:
                    body = resp.text[:500]
                    if path.endswith("HEAD") and "ref:" not in body:
                        hit = len(body) > 0 and "html" not in body.lower()[:50]
                    elif path == ".env" and "=" not in body:
                        hit = False
                if hit:
                    data.append({
                        "路径": path, "名称": name, "状态码": resp.status_code,
                        "严重程度": sev, "URL": test_url,
                    })
                    logs.append(f"[!] 发现 {path} [{resp.status_code}]")
            self.progress(int(95 * (i + 1) / len(paths)))

        self.progress(100, "完成")
        return ScanResult(
            True, "敏感文件探测", data=data, logs=logs,
            summary=f"发现 {len(data)} 个可疑文件",
        )
