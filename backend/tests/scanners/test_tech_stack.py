import httpx
import respx

from app.scanners.tech_stack import (
    TechStackScanner,
    detect,
    load_fingerprints,
    parse_pattern,
    resolve_version,
)

IP = "93.184.216.34"

HTML = """<!doctype html><html><head>
<meta name="generator" content="WordPress 6.4.2">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body><p>Hello</p></body></html>"""


def test_parse_pattern_with_version_and_confidence():
    p = parse_pattern("nginx(?:/([\\d.]+))?\\;version:\\1\\;confidence:50")
    assert p.raw == "nginx(?:/([\\d.]+))?"
    assert p.version == "\\1"
    assert p.confidence == 50
    m = p.regex.search("nginx/1.25.3")
    assert resolve_version(p.version, m) == "1.25.3"


def test_resolve_version_ternary():
    p = parse_pattern("foo(bar)?\\;version:\\1?2.0:1.0")
    assert resolve_version(p.version, p.regex.search("foobar")) == "2.0"
    assert resolve_version(p.version, p.regex.search("foo")) == "1.0"


def test_detect_real_fingerprints():
    techs = detect(
        load_fingerprints(),
        {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4.3"},
        {},
        HTML,
        "https://example.com/",
    )
    by_name = {t["name"]: t for t in techs}
    assert by_name["Nginx"]["version"] == "1.18.0"
    assert by_name["Nginx"]["cpe"].startswith("cpe:2.3:a:")
    assert by_name["PHP"]["version"] == "7.4.3"
    assert by_name["WordPress"]["version"] == "6.4.2"
    assert "MySQL" in by_name  # implied by WordPress
    assert by_name["MySQL"]["version"] == "unknown"


@respx.mock
async def test_tech_stack_scanner(ctx):
    respx.get(f"https://{IP}/").mock(
        return_value=httpx.Response(
            200, text=HTML, headers={"Content-Type": "text/html; charset=utf-8", "Server": "nginx/1.18.0"}
        )
    )
    res = await TechStackScanner().run(ctx)
    names = {t["name"] for t in res.data["technologies"]}
    assert {"Nginx", "WordPress"} <= names
    assert any(f.id == "tech_stack.versions_exposed" for f in res.findings)
