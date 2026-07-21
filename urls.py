from urllib.parse import urlparse
import re

SUSPICIOUS_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "is.gd", "t.co", "rb.gy"}
HIGH_RISK_TLDS = {".xyz", ".top", ".zip", ".work", ".click", ".loan"}

def check_url_risk(url: str) -> dict:
    reasons = []
    
    # Ensure scheme for parsing
    formatted_url = url if url.startswith(("http://", "https://")) else f"http://{url}"
    parsed = urlparse(formatted_url)
    hostname = parsed.hostname or ""

    # Check 1: Raw IP address host
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        reasons.append("URL uses raw IP address instead of domain name")

    # Check 2: Known URL shorteners
    if hostname.lower() in SUSPICIOUS_SHORTENERS:
        reasons.append("URL uses a known shortener service")

    # Check 3: Suspicious TLDs
    if any(hostname.endswith(tld) for tld in HIGH_RISK_TLDS):
        reasons.append("URL uses a high-risk TLD")

    # Check 4: Excessive subdomains (phishing indicator)
    if hostname.count(".") > 3:
        reasons.append("Excessive subdomains detected")

    risk_level = "HIGH" if len(reasons) >= 2 else ("MEDIUM" if reasons else "LOW")

    return {
        "url": url,
        "risk_level": risk_level,
        "reasons": reasons
    }
