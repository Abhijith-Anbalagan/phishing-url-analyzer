# ============================================================
# analyzer/phishing_checks.py — Phishing Detection Engine
#
# PURPOSE: This is the CORE of the analyzer. Each function
# checks for ONE specific phishing indicator and returns:
#   - detected (bool): Was this indicator found?
#   - score (int):     How many risk points does it add?
#   - reason (str):    Human-readable explanation for the SOC report
#
# SOC RELEVANCE: These checks mirror real Indicator of Compromise
# (IoC) rules used in tools like Splunk, QRadar, and CrowdStrike.
# Each check = one detection rule. Score = risk weight.
# ============================================================

import re                      # For regex pattern matching
import socket                  # To resolve hostnames and detect IPs
from urllib.parse import urlparse
import config                  # Our settings file


# ─────────────────────────────────────────────────────────────
# CHECK 1: IP-Based URL
# ─────────────────────────────────────────────────────────────
def check_ip_based_url(url: str) -> dict:
    """
    Detect if the URL uses an IP address instead of a domain name.
    
    Legitimate services use domain names (google.com).
    Phishing sites often use raw IPs to avoid domain registration
    and make URLs harder to block by name.
    
    Example of IP-based phishing URL:
        http://192.168.1.254/paypal/login.html
    
    Risk Weight: 30 points — Strong phishing indicator
    """
    # Regex pattern matches IPv4 addresses like 192.168.1.1
    # Breakdown:
    #   \d{1,3}  → 1-3 digits
    #   \.       → literal dot
    #   × 3      → repeated three times
    #   \d{1,3}  → final octet
    ip_pattern = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")

    detected = bool(ip_pattern.search(url))  # True if IP found in URL

    return {
        "detected": detected,
        "score":    30 if detected else 0,
        "reason":   "URL uses a raw IP address instead of a domain name" if detected else None
    }


# ─────────────────────────────────────────────────────────────
# CHECK 2: Long URL
# ─────────────────────────────────────────────────────────────
def check_long_url(url: str) -> dict:
    """
    Detect unusually long URLs.
    
    Phishing URLs are often long because attackers:
    1. Add the target brand name in a subdomain (to look real)
    2. Add tracking parameters
    3. Obfuscate the real domain deep in a long path
    
    Example:
        http://secure-paypal-account-login-verify.com/update/user?id=12345
    
    Threshold: Configurable in config.py (default: 75 chars)
    Risk Weight: 20 points
    """
    url_length = len(url)
    detected   = url_length > config.LONG_URL_THRESHOLD

    return {
        "detected": detected,
        "score":    20 if detected else 0,
        "reason":   f"URL is unusually long ({url_length} characters)" if detected else None
    }


# ─────────────────────────────────────────────────────────────
# CHECK 3: Suspicious Keywords
# ─────────────────────────────────────────────────────────────
def check_suspicious_keywords(url: str) -> dict:
    """
    Scan the URL for keywords commonly used in phishing attacks.
    
    Attackers use trust-inducing words to convince victims the
    URL is legitimate. Words like 'secure', 'verify', 'login',
    'paypal', 'amazon' appear in fake brand impersonation pages.
    
    SOC RELEVANCE: This is exactly how signature-based IDS/IPS
    rules work — matching known bad patterns in traffic.
    
    Risk Weight: 15 points per keyword found (max 45)
    """
    url_lower       = url.lower()   # Convert to lowercase for case-insensitive matching
    found_keywords  = []            # List to collect all matched keywords

    for keyword in config.SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:    # Simple substring match
            found_keywords.append(keyword)

    detected = len(found_keywords) > 0

    # Cap score at 45 to prevent one check from dominating the total
    score = min(len(found_keywords) * 15, 45)

    return {
        "detected": detected,
        "score":    score,
        "reason":   f"Suspicious keywords found: {', '.join(found_keywords)}" if detected else None,
        "keywords": found_keywords  # Extra detail for the report
    }


# ─────────────────────────────────────────────────────────────
# CHECK 4: '@' Symbol in URL
# ─────────────────────────────────────────────────────────────
def check_at_symbol(url: str) -> dict:
    """
    Detect the '@' symbol in the URL.
    
    In a URL, everything before '@' is treated as credentials
    (username:password) and is IGNORED by the browser.
    Attackers use this to disguise the real destination:
    
        http://paypal.com@evil-site.com/steal
        ↑ Looks like paypal.com — actually goes to evil-site.com
    
    This is a well-known phishing technique documented in:
    - OWASP Top 10
    - RFC 3986 (URL standard)
    
    Risk Weight: 25 points — High confidence indicator
    """
    detected = "@" in url

    return {
        "detected": detected,
        "score":    25 if detected else 0,
        "reason":   "'@' symbol found in URL — real destination may be hidden after it" if detected else None
    }


# ─────────────────────────────────────────────────────────────
# CHECK 5: Hyphen-Heavy Domain
# ─────────────────────────────────────────────────────────────
def check_hyphen_in_domain(parts: dict) -> dict:
    """
    Check if the domain has multiple hyphens.
    
    Legitimate domains rarely use multiple hyphens.
    Phishing domains use them to string brand names together:
        secure-paypal-login-verify.com
        account-amazon-support-update.net
    
    Risk Weight: 20 points if 2+ hyphens in domain
    """
    domain   = parts.get("domain", "")
    count    = domain.count("-")          # Count hyphen characters
    detected = count >= 2                 # 2 or more hyphens = suspicious

    return {
        "detected": detected,
        "score":    20 if detected else 0,
        "reason":   f"Domain contains {count} hyphens ('{domain}') — common in fake brand domains" if detected else None
    }


# ─────────────────────────────────────────────────────────────
# CHECK 6: Suspicious TLD (Top-Level Domain)
# ─────────────────────────────────────────────────────────────
def check_suspicious_tld(parts: dict) -> dict:
    """
    Check if the domain uses a TLD commonly abused by phishers.
    
    While any TLD can host legitimate sites, certain TLDs are
    statistically more common in phishing and malware campaigns
    due to low cost and lax registration policies.
    
    Risk Weight: 20 points
    """
    # TLDs frequently seen in threat intelligence feeds
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                       ".top", ".click", ".link", ".work", ".date",
                       ".review", ".country", ".kim", ".science"]

    domain   = parts.get("domain", "")
    detected = any(domain.endswith(tld) for tld in suspicious_tlds)

    matched_tld = next((tld for tld in suspicious_tlds if domain.endswith(tld)), "")

    return {
        "detected": detected,
        "score":    20 if detected else 0,
        "reason":   f"Domain uses suspicious TLD '{matched_tld}' — frequently abused in phishing campaigns" if detected else None
    }


# ─────────────────────────────────────────────────────────────
# CHECK 7: HTTPS Check
# ─────────────────────────────────────────────────────────────
def check_no_https(parts: dict) -> dict:
    """
    Check if the URL uses HTTP instead of HTTPS.
    
    Modern legitimate websites use HTTPS.
    No HTTPS = data transmitted in plaintext = credential theft risk.
    Note: HTTPS alone does NOT mean safe — phishing sites also use
    HTTPS — but HTTP is still a risk signal worth flagging.
    
    Risk Weight: 10 points (minor indicator on its own)
    """
    scheme   = parts.get("scheme", "")
    detected = scheme == "http"    # True if using insecure HTTP

    return {
        "detected": detected,
        "score":    10 if detected else 0,
        "reason":   "URL uses HTTP instead of HTTPS — connection is unencrypted" if detected else None
    }


# ─────────────────────────────────────────────────────────────
# MASTER FUNCTION: Run All Checks
# ─────────────────────────────────────────────────────────────
def run_all_checks(url: str, parts: dict) -> list:
    """
    Run every phishing check and return results as a list.
    
    This is the function called by main.py.
    It collects all check results and returns them for
    the risk scorer to process.
    
    Returns: List of result dicts, one per check.
    """
    results = [
        check_ip_based_url(url),
        check_long_url(url),
        check_suspicious_keywords(url),
        check_at_symbol(url),
        check_hyphen_in_domain(parts),
        check_suspicious_tld(parts),
        check_no_https(parts),
    ]

    return results
