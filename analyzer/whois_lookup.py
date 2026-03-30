# ============================================================
# analyzer/whois_lookup.py — WHOIS & Domain Age Analysis
#
# PURPOSE: Query WHOIS records to find out when a domain was
# registered. Freshly registered domains are a strong phishing
# signal — attackers register new domains per campaign to
# evade blocklists.
#
# SOC RELEVANCE: Domain age is a core enrichment step in
# phishing investigations. Tools like VirusTotal, Cisco Talos,
# and Palo Alto AutoFocus all surface domain age in their reports.
# A 2-day-old domain sending "PayPal security alerts" is an
# immediate red flag.
# ============================================================

import whois                         # python-whois library
from datetime import datetime, timezone


def get_whois_info(domain: str) -> dict:
    """
    Perform a WHOIS lookup on the given domain.
    
    Returns a dict with:
        domain        → The queried domain
        created_date  → When it was registered (datetime object)
        registrar     → Who registered it
        country       → Registrant country (if available)
        age_days      → How old the domain is in days
        is_new        → True if domain is less than 30 days old
        error         → Error message if lookup failed
    """
    result = {
        "domain":       domain,
        "created_date": None,
        "registrar":    None,
        "country":      None,
        "age_days":     None,
        "is_new":       False,
        "error":        None
    }

    try:
        # Perform the WHOIS query
        # python-whois handles parsing the raw WHOIS response
        w = whois.whois(domain)

        # Extract creation date — may be a list or single datetime
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]   # Take the first date if multiple returned

        if created:
            # Ensure the datetime is timezone-aware for safe comparison
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)

            now      = datetime.now(timezone.utc)
            age_days = (now - created).days   # Calculate domain age

            result["created_date"] = created.strftime("%Y-%m-%d")
            result["age_days"]     = age_days
            result["is_new"]       = age_days < 30   # Flag if less than 30 days old

        # Extract registrar info (who registered this domain)
        result["registrar"] = str(w.registrar) if w.registrar else "Unknown"

        # Extract country (not always available in WHOIS records)
        result["country"]   = str(w.country) if w.country else "Unknown"

    except Exception as e:
        # WHOIS can fail for many reasons:
        # - Domain doesn't exist
        # - WHOIS server is slow/blocked
        # - Privacy protection hiding records
        result["error"] = f"WHOIS lookup failed: {str(e)}"

    return result


def whois_risk_score(whois_data: dict) -> dict:
    """
    Generate a risk score contribution from WHOIS data.
    
    New domains (< 30 days) add 25 points to the overall risk score.
    Very new domains (< 7 days) add 35 points.
    
    Returns same dict format as phishing_checks.py for consistency.
    """
    if whois_data.get("error") or whois_data.get("age_days") is None:
        return {"detected": False, "score": 0, "reason": None}

    age   = whois_data["age_days"]
    score = 0
    reason = None

    if age < 7:
        score  = 35
        reason = f"Domain is only {age} days old — extremely new, very suspicious"
    elif age < 30:
        score  = 25
        reason = f"Domain is only {age} days old — recently registered, suspicious"
    elif age < 180:
        score  = 10
        reason = f"Domain is {age} days old — relatively new"

    return {
        "detected": score > 0,
        "score":    score,
        "reason":   reason
    }
