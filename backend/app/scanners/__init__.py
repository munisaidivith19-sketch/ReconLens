"""Ordered scanner registry. Scanners run concurrently unless they declare depends_on."""

from app.scanners.base import Scanner
from app.scanners.cve_lookup import CveLookupScanner
from app.scanners.dns_records import DnsRecordsScanner
from app.scanners.email_security import EmailSecurityScanner
from app.scanners.endpoints import EndpointsScanner
from app.scanners.robots_sitemap import RobotsSitemapScanner
from app.scanners.security_headers import SecurityHeadersScanner
from app.scanners.subdomains import SubdomainsScanner
from app.scanners.tech_stack import TechStackScanner
from app.scanners.tls_check import TlsCheckScanner
from app.scanners.virustotal import VirusTotalScanner
from app.scanners.whois_rdap import WhoisRdapScanner


def get_scanners() -> list[Scanner]:
    return [
        DnsRecordsScanner(),
        WhoisRdapScanner(),
        SubdomainsScanner(),
        RobotsSitemapScanner(),
        SecurityHeadersScanner(),
        TlsCheckScanner(),
        EmailSecurityScanner(),
        TechStackScanner(),
        CveLookupScanner(),  # depends on tech_stack
        VirusTotalScanner(),
        EndpointsScanner(),
    ]


__all__ = ["Scanner", "get_scanners"]
