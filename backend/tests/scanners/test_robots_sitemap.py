import httpx
import respx

from app.scanners.robots_sitemap import RobotsSitemapScanner, parse_robots

IP = "93.184.216.34"

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /backup.zip   # old
Disallow: /blog/drafts
Allow: /
Sitemap: https://example.com/sitemap.xml
"""

SITEMAP = b"""<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url>
<url><loc>https://example.com/about</loc></url></urlset>"""


def test_parse_robots():
    disallowed, sitemaps = parse_robots(ROBOTS)
    assert disallowed == ["/admin/", "/backup.zip", "/blog/drafts"]
    assert sitemaps == ["https://example.com/sitemap.xml"]


@respx.mock
async def test_robots_and_sitemap(ctx):
    respx.get(f"https://{IP}/robots.txt").mock(
        return_value=httpx.Response(200, text=ROBOTS, headers={"Content-Type": "text/plain"})
    )
    respx.get(f"https://{IP}/sitemap.xml").mock(return_value=httpx.Response(200, content=SITEMAP))
    res = await RobotsSitemapScanner().run(ctx)
    assert res.data["robots_found"] is True
    assert res.data["sitemap_url_count"] == 2
    assert "/admin/" in res.data["interesting"]
    assert "/backup.zip" in res.data["interesting"]
    assert any(f.id == "robots_sitemap.interesting_disallow" for f in res.findings)


@respx.mock
async def test_missing_robots(ctx):
    respx.get(f"https://{IP}/robots.txt").mock(return_value=httpx.Response(404, text="nope"))
    respx.get(f"https://{IP}/sitemap.xml").mock(return_value=httpx.Response(404))
    res = await RobotsSitemapScanner().run(ctx)
    assert res.data["robots_found"] is False
    assert res.data["sitemap_url_count"] is None
    assert any(f.id == "robots_sitemap.no_robots" for f in res.findings)


@respx.mock
async def test_soft_404_html_robots_ignored(ctx):
    respx.get(f"https://{IP}/robots.txt").mock(
        return_value=httpx.Response(200, text="<html>home</html>", headers={"Content-Type": "text/html"})
    )
    respx.get(f"https://{IP}/sitemap.xml").mock(return_value=httpx.Response(200, text="<html></html>"))
    res = await RobotsSitemapScanner().run(ctx)
    assert res.data["robots_found"] is False
