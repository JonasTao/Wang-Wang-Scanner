"""通用网络与解析工具。"""
import ipaddress
import re
import socket
import ssl
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests


def normalize_target(raw: str) -> str:
    return raw.strip().strip("/")


def parse_targets(text: str) -> List[str]:
    items = []
    for line in re.split(r"[\n,;]+", text):
        t = normalize_target(line)
        if t:
            items.append(t)
    return items


def expand_ip_range(spec: str) -> List[str]:
    spec = spec.strip()
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(h) for h in net.hosts()]
        except ValueError:
            return []
    if "-" in spec:
        parts = spec.split("-", 1)
        try:
            start = ipaddress.ip_address(parts[0].strip())
            end_part = parts[1].strip()
            if "." not in end_part:
                end = ipaddress.ip_address(
                    ".".join(parts[0].strip().split(".")[:-1] + [end_part])
                )
            else:
                end = ipaddress.ip_address(end_part)
            hosts = []
            cur = int(start)
            end_i = int(end)
            while cur <= end_i:
                hosts.append(str(ipaddress.ip_address(cur)))
                cur += 1
            return hosts
        except ValueError:
            return []
    try:
        ipaddress.ip_address(spec)
        return [spec]
    except ValueError:
        return []


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def tcp_probe(host: str, port: int, timeout: float = 1.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return True
    except (socket.timeout, OSError):
        return False
    finally:
        sock.close()


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        try:
            sock.send(b"\r\n")
        except OSError:
            pass
        data = sock.recv(512)
        return data.decode("utf-8", errors="replace").strip()[:200]
    except (socket.timeout, OSError):
        return ""
    finally:
        sock.close()


def ping_host(host: str, timeout_ms: int = 1000) -> bool:
    param = "-n" if platform.system().lower() == "windows" else "-c"
    wait = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        out = subprocess.run(
            ["ping", param, "1", wait, str(timeout_ms), host],
            capture_output=True,
            text=True,
            timeout=(timeout_ms / 1000) + 2,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0,
        )
        return out.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def parallel_map(
    items: Iterable,
    func: Callable,
    workers: int = 50,
    cancel_check: Optional[Callable[[], bool]] = None,
) -> List[Tuple]:
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(func, item): item for item in items}
        for fut in as_completed(futures):
            if cancel_check and cancel_check():
                pool.shutdown(wait=False, cancel_futures=True)
                break
            try:
                results.append((futures[fut], fut.result()))
            except Exception as exc:
                results.append((futures[fut], exc))
    return results


def http_get(url: str, timeout: int = 8, verify_ssl: bool = True) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
            headers={"User-Agent": "SecurityScanner/1.0 (Authorized Test)"},
        )
    except requests.RequestException:
        return None


def ssl_info(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    info = {}
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["protocol"] = ssock.version()
                info["cipher"] = ssock.cipher()[0] if ssock.cipher() else ""
                if cert:
                    info["subject"] = dict(x[0] for x in cert.get("subject", ()))
                    info["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                    info["not_after"] = cert.get("notAfter", "")
    except OSError as exc:
        info["error"] = str(exc)
    return info


def url_to_host(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urlparse(url).netloc.split(":")[0]
