from .personnel_panel import PersonnelPanel
from .asset_panel import AssetPanel
from .subdomain_panel import SubdomainPanel
from .whois_panel import WhoisPanel
from .dns_security_panel import DnsSecurityPanel
from .port_panel import PortPanel
from .host_panel import HostPanel
from .os_panel import OSPanel
from .network_panel import NetworkPanel
from .csegment_panel import CsegmentPanel
from .ssl_panel import SslPanel
from .smb_panel import SmbPanel
from .snmp_panel import SnmpPanel
from .web_fingerprint_panel import WebFingerprintPanel
from .web_panel import WebPanel
from .sensitive_panel import SensitivePanel
from .api_panel import ApiPanel
from .weak_panel import WeakPanel

PANELS = [
    PersonnelPanel,
    AssetPanel,
    SubdomainPanel,
    WhoisPanel,
    DnsSecurityPanel,
    PortPanel,
    HostPanel,
    OSPanel,
    NetworkPanel,
    CsegmentPanel,
    SslPanel,
    SmbPanel,
    SnmpPanel,
    WebFingerprintPanel,
    WebPanel,
    SensitivePanel,
    ApiPanel,
    WeakPanel,
]
