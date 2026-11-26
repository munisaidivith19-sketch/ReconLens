"""Lookup tables that turn raw DNS records into plain-language facts.

* MAIL_PROVIDERS: MX hostname suffix -> mail provider.
* TXT_TOKENS: TXT record prefix -> third-party service the organisation has verified.
* TAKEOVER_SERVICES: CNAME suffix -> cloud service where a dangling record (target returns
  NXDOMAIN) usually means someone else can claim the name. Only services that can be
  detected from DNS alone are listed, because ReconLens never requests discovered hosts.
  Background: https://github.com/EdOverflow/can-i-take-over-xyz (links only, no data copied).
"""

from __future__ import annotations

MAIL_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint Essentials"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("iphmx.com", "Cisco Secure Email"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.in", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("yandex.net", "Yandex Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonaws.com", "Amazon SES / WorkMail"),
    ("secureserver.net", "GoDaddy"),
    ("hostinger.com", "Hostinger"),
    ("titan.email", "Titan"),
    ("emailsrvr.com", "Rackspace"),
    ("icloud.com", "iCloud Mail"),
    ("fastmail.com", "Fastmail"),
    ("mxroute.com", "MXroute"),
    ("rediffmailpro.com", "Rediffmail Pro"),
)

TXT_TOKENS: tuple[tuple[str, str], ...] = (
    ("google-site-verification=", "Google (Search Console / Workspace)"),
    ("ms=", "Microsoft 365"),
    ("facebook-domain-verification=", "Meta (Facebook)"),
    ("apple-domain-verification=", "Apple"),
    ("atlassian-domain-verification=", "Atlassian"),
    ("docusign=", "DocuSign"),
    ("adobe-idp-site-verification=", "Adobe"),
    ("adobe-sign-verification=", "Adobe Sign"),
    ("zoom-domain-verification", "Zoom"),
    ("slack-domain-verification=", "Slack"),
    ("stripe-verification=", "Stripe"),
    ("hubspot-developer-verification=", "HubSpot"),
    ("dropbox-domain-verification=", "Dropbox"),
    ("citrix-verification-code=", "Citrix"),
    ("cisco-ci-domain-verification=", "Cisco Webex"),
    ("webexdomainverification", "Cisco Webex"),
    ("amazonses:", "Amazon SES"),
    ("_amazonses", "Amazon SES"),
    ("mailru-verification:", "Mail.ru"),
    ("yandex-verification:", "Yandex"),
    ("zoho-verification=", "Zoho"),
    ("brevo-code:", "Brevo"),
    ("sendinblue-code:", "Brevo (Sendinblue)"),
    ("mandrill_verify.", "Mailchimp Transactional"),
    ("mailchimp", "Mailchimp"),
    ("miro-verification=", "Miro"),
    ("notion-domain-verification=", "Notion"),
    ("figma-domain-verification=", "Figma"),
    ("github-verification", "GitHub"),
    ("gitlab-pages-verification-code=", "GitLab Pages"),
    ("heroku-domain-verification=", "Heroku"),
    ("cloudflare-verify", "Cloudflare"),
    ("teamviewer-sso-verification=", "TeamViewer"),
    ("onetrust-domain-verification=", "OneTrust"),
    ("knowbe4-site-verification=", "KnowBe4"),
    ("have-i-been-pwned-verification=", "Have I Been Pwned"),
    ("globalsign-domain-verification=", "GlobalSign"),
    ("_globalsign-domain-verification=", "GlobalSign"),
    ("sectigo", "Sectigo"),
    ("pardot", "Salesforce Pardot"),
    ("salesforce", "Salesforce"),
    ("wrike-verification=", "Wrike"),
    ("canva-site-verification=", "Canva"),
    ("openai-domain-verification=", "OpenAI"),
    ("anthropic-domain-verification", "Anthropic"),
    ("pinterest-site-verification=", "Pinterest"),
    ("twilio-domain-verification=", "Twilio"),
    ("klaviyo-site-verification=", "Klaviyo"),
    ("shopify-verification-code=", "Shopify"),
    ("bugcrowd-verification=", "Bugcrowd"),
    ("hackerone", "HackerOne"),
)

# (cname suffix, service name, reference)
TAKEOVER_SERVICES: tuple[tuple[str, str, str], ...] = (
    ("azurewebsites.net", "Azure App Service", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35"),
    ("cloudapp.net", "Azure Cloud Services", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35"),
    (
        "cloudapp.azure.com",
        "Azure VM DNS name",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
    ),
    (
        "trafficmanager.net",
        "Azure Traffic Manager",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
    ),
    (
        "blob.core.windows.net",
        "Azure Blob Storage",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
    ),
    ("azureedge.net", "Azure CDN", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35"),
    ("azure-api.net", "Azure API Management", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35"),
    (
        "azurecontainer.io",
        "Azure Container Instances",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
    ),
    (
        "azurestaticapps.net",
        "Azure Static Web Apps",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/35",
    ),
    (
        "elasticbeanstalk.com",
        "AWS Elastic Beanstalk",
        "https://github.com/EdOverflow/can-i-take-over-xyz/issues/194",
    ),
    ("s3-website", "AWS S3 website", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/36"),
    ("s3.amazonaws.com", "AWS S3", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/36"),
    ("cloudfront.net", "AWS CloudFront", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("herokuapp.com", "Heroku", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/38"),
    ("herokudns.com", "Heroku", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/38"),
    ("github.io", "GitHub Pages", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/37"),
    ("netlify.app", "Netlify", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/40"),
    ("netlify.com", "Netlify", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/40"),
    ("vercel.app", "Vercel", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("pantheonsite.io", "Pantheon", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/24"),
    ("myshopify.com", "Shopify", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/32"),
    ("wpengine.com", "WP Engine", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("ghost.io", "Ghost", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/89"),
    ("surge.sh", "Surge.sh", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("bitbucket.io", "Bitbucket", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("zendesk.com", "Zendesk", "https://github.com/EdOverflow/can-i-take-over-xyz/issues/23"),
    ("readme.io", "ReadMe", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("helpscoutdocs.com", "Help Scout", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("unbouncepages.com", "Unbounce", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("webflow.io", "Webflow", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("fly.dev", "Fly.io", "https://github.com/EdOverflow/can-i-take-over-xyz"),
    ("onrender.com", "Render", "https://github.com/EdOverflow/can-i-take-over-xyz"),
)


def _suffix_match(host: str, suffix: str) -> bool:
    host = host.lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix) or (suffix.startswith("s3-") and suffix in host)


def mail_providers(mx_records: list[str]) -> list[str]:
    """MX values look like '10 aspmx.l.google.com.'."""
    found: list[str] = []
    for rec in mx_records:
        host = rec.split()[-1].lower().rstrip(".") if rec.strip() else ""
        for suffix, name in MAIL_PROVIDERS:
            if _suffix_match(host, suffix):
                if name not in found:
                    found.append(name)
                break
    return found


def txt_services(txt_records: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for rec in txt_records:
        low = rec.strip().lower()
        for prefix, name in TXT_TOKENS:
            if low.startswith(prefix) and name not in seen:
                seen.add(name)
                out.append({"service": name, "record": rec[:120]})
                break
    return out


def takeover_service(cname: str) -> tuple[str, str] | None:
    for suffix, name, ref in TAKEOVER_SERVICES:
        if _suffix_match(cname, suffix):
            return name, ref
    return None
