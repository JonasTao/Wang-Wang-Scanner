from .personnel import PersonnelScanner
from .assets import AssetScanner
from .port_scanner import PortScanner
from .host_discovery import HostDiscoveryScanner
from .os_detect import OSDetectScanner
from .network_scan import NetworkScanScanner
from .web_vuln import WebVulnScanner
from .whois_scan import WhoisScanner
from .subdomain import SubdomainScanner
from .dns_security import DnsSecurityScanner
from .web_fingerprint import WebFingerprintScanner
from .smb_enum import SmbEnumScanner
from .ssl_deep import SslDeepScanner
from .sensitive_files import SensitiveFileScanner
from .c_segment import CSegmentScanner
from .snmp_scan import SnmpScanner
from .api_discovery import ApiDiscoveryScanner
from .weak_service import WeakServiceScanner

SCANNER_REGISTRY = {
    "personnel": PersonnelScanner,
    "assets": AssetScanner,
    "subdomain": SubdomainScanner,
    "whois": WhoisScanner,
    "dns_security": DnsSecurityScanner,
    "port": PortScanner,
    "host": HostDiscoveryScanner,
    "os": OSDetectScanner,
    "network": NetworkScanScanner,
    "csegment": CSegmentScanner,
    "ssl": SslDeepScanner,
    "smb": SmbEnumScanner,
    "snmp": SnmpScanner,
    "web_fingerprint": WebFingerprintScanner,
    "web": WebVulnScanner,
    "sensitive": SensitiveFileScanner,
    "api": ApiDiscoveryScanner,
    "weak": WeakServiceScanner,
}

__all__ = ["SCANNER_REGISTRY"]
