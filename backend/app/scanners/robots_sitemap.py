"""robots.txt and sitemap.xml review (two requests a crawler would make anyway)."""

import re
from urllib.parse import urlsplit

from app.core.ssrf_guard import BlockedTargetError
from app.models.finding import Severity
from app.scanners.base import ScanContext, Scanner, ScannerResult

INTERESTING_KEYWORDS = (
    "admin",
    "backup",
    "bak",
    "config",
    "console",
    "cgi-bin",
    "debug",
    "dev",
    "staging",
    "test",
    "internal",
    "private",
    "secret",
    "login",
    "wp-admin",
    "phpmyadmin",
    "api",
    ".git",
    ".env",
    "old",
    "tmp",
    "upload",
    "install",
)
_LOC_RE = re.compile(rb"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    disallowed: list[str] = []
    sitemaps: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "disallow" and value and value != "/":
            disallowed.append(value[:300])
        elif key == "sitemap" and value:
            sitemaps.append(value[:500])
    return sorted(set(disallowed))[:300], list(dict.fromkeys(sitemaps))[:20]


def interesting_paths(paths: list[str]) -> list[str]:
    return [p for p in paths if any(k in p.lower() for k in INTERESTING_KEYWORDS)]


class RobotsSitemapScanner(Scanner):
    name = "robots_sitemap"
    label = "robots.txt & sitemap"
    category = "Information disclosure"
    timeout = 25.0

    async def run(self, ctx: ScanContext) -> ScannerResult:
        robots_text = None
        base_url = f"https://{ctx.domain}"
        for scheme in ("https", "http"):
            try:
                resp = await ctx.client.get(
                    f"{scheme}://{ctx.domain}/robots.txt", max_bytes=512 * 1024, allow_truncate=True
                )
            except BlockedTargetError:
                raise
            except Exception:  # noqa: BLE001, S112 - try the other scheme
                continue
            base_url = f"{scheme}://{ctx.domain}"
            ctype = resp.headers.get("content-type", "")
            if resp.status_code == 200 and "html" not in ctype.lower():
                robots_text = resp.text
            break

        disallowed, sitemaps = parse_robots(robots_text or "")
        sitemap_count = None
        sitemap_url = None
        candidates = [s for s in sitemaps if urlsplit(s).scheme in ("http", "https")] or [
            f"{base_url}/sitemap.xml"
        ]
        try:
            sm = await ctx.client.get(candidates[0], max_bytes=2 * 1024 * 1024, allow_truncate=True)
            if sm.status_code == 200 and b"<loc>" in sm.content.lower():
                sitemap_url = candidates[0]
                sitemap_count = len(_LOC_RE.findall(sm.content))
        except BlockedTargetError:
            sitemap_count = None  # a sitemap on a disallowed host is simply skipped
        except Exception:  # noqa: BLE001
            sitemap_count = None

        interesting = interesting_paths(disallowed)
        data = {
            "robots_found": robots_text is not None,
            "disallowed": disallowed,
            "sitemaps": sitemaps or ([sitemap_url] if sitemap_url else []),
            "sitemap_url_count": sitemap_count,
            "interesting": interesting[:50],
        }
        result = ScannerResult(data=data)
        if interesting:
            result.findings.append(
                self.finding(
                    "interesting_disallow",
                    "robots.txt points to potentially sensitive paths",
                    Severity.LOW,
                    evidence="Disallowed: " + ", ".join(interesting[:15]),
                    recommendation=(
                        "robots.txt is public and is often the first file an attacker reads. Protect sensitive "
                        "paths with authentication instead of hiding them via robots.txt."
                    ),
                )
            )
        if robots_text is None:
            result.findings.append(
                self.finding(
                    "no_robots",
                    "No robots.txt found",
                    Severity.INFO,
                    evidence="robots.txt is missing or not plain text.",
                    recommendation="Informational. A robots.txt is optional.",
                )
            )
        return result
