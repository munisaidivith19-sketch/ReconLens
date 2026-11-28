"""Ordered scanner registry. Scanners run concurrently unless they declare depends_on."""

from app.scanners.base import Scanner
from app.scanners.blocklists import BlocklistsScanner
from app.scanners.client_side import ClientSideScanner
from app.scanners.cve_lookup import CveLookupScanner
from app.scanners.dns_records import DnsRecordsScanner
from app.scanners.email_security import EmailSecurityScanner
from app.scanners.endpoints import EndpointsScanner
from app.scanners.exposed_services import ExposedServicesScanner
from app.scanners.favicon import FaviconScanner
from app.scanners.hsts_preload import HstsPreloadScanner
from app.scanners.ip_intel import IpIntelScanner
from app.scanners.lookalikes import LookalikesScanner
from app.scanners.origin_hints import OriginHintsScanner
from app.scanners.robots_sitemap import RobotsSitemapScanner
from app.scanners.security_headers import SecurityHeadersScanner
from app.scanners.security_txt import SecurityTxtScanner
from app.scanners.subdomains import SubdomainsScanner
from app.scanners.takeover import TakeoverScanner
from app.scanners.tech_stack import TechStackScanner
from app.scanners.tls_check import TlsCheckScanner
from app.scanners.virustotal import VirusTotalScanner
from app.scanners.whois_rdap import WhoisRdapScanner
from app.scanners.wordpress import WordPressScanner


def get_scanners() -> list[Scanner]:
    return [
        DnsRecordsScanner(),
        WhoisRdapScanner(),
        SubdomainsScanner(),
        TakeoverScanner(),  # depends on subdomains
        ExposedServicesScanner(),  # depends on dns_records
        RobotsSitemapScanner(),
        SecurityTxtScanner(),
        SecurityHeadersScanner(),
        TlsCheckScanner(),
        EmailSecurityScanner(),
        TechStackScanner(),
        CveLookupScanner(),  # depends on tech_stack
        VirusTotalScanner(),
        EndpointsScanner(),
        ClientSideScanner(),
        IpIntelScanner(),  # depends on dns_records, takeover
        OriginHintsScanner(),  # depends on dns_records, takeover, security_headers, ip_intel
        FaviconScanner(),
        LookalikesScanner(),  # depends on whois_rdap
        BlocklistsScanner(),  # depends on whois_rdap
        HstsPreloadScanner(),  # depends on whois_rdap, security_headers
        WordPressScanner(),  # depends on tech_stack
    ]


__all__ = ["Scanner", "get_scanners"]
