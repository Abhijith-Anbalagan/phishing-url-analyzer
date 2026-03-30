import validators
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url


def is_valid_url(url: str) -> bool:
    result = validators.url(url)
    return result is True


def extract_real_domain(netloc: str) -> str:
    """
    FIX: Handle '@' phishing trick
    Example:
    secure-login@evil.com → evil.com
    """
    if "@" in netloc:
        netloc = netloc.split("@")[-1]

    return netloc.lower()


def extract_url_parts(url: str) -> dict:
    parsed = urlparse(url)

    # 🔥 FIX APPLIED HERE
    domain = extract_real_domain(parsed.netloc)

    if domain.startswith("www."):
        domain = domain[4:]

    return {
        "scheme": parsed.scheme,
        "domain": domain,
        "path": parsed.path,
        "query": parsed.query,
        "full_url": url
    }


def validate_and_parse(raw_url: str) -> tuple:
    normalized = normalize_url(raw_url)
    valid = is_valid_url(normalized)
    parts = extract_url_parts(normalized) if valid else {}

    return valid, parts, normalized