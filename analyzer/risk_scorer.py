# ============================================================
# analyzer/risk_scorer.py — Risk Scoring & Classification
#
# PURPOSE: Takes the raw results from phishing_checks.py and
# converts them into a final risk score + human-readable verdict.
#
# SOC RELEVANCE: This mirrors how SIEM tools like Splunk ES or
# IBM QRadar calculate "offense scores" — each rule that fires
# adds points, and the total determines severity level and
# response priority (P1/P2/P3 tickets).
# ============================================================

import config   # Threshold values from config.py


def calculate_score(check_results: list) -> int:
    """
    Sum up scores from all phishing checks.
    
    Each check returns a score of 0 (not detected) or N (detected).
    We add them all together for the total risk score.
    
    Example:
        IP-based URL detected:     +30
        Long URL detected:         +20
        Suspicious keyword found:  +15
        Total:                      65 → HIGH RISK
    """
    total = sum(result.get("score", 0) for result in check_results)
    return total


def classify_risk(score: int) -> dict:
    """
    Convert a numeric score into a risk level with color coding.
    
    Thresholds are defined in config.py so SOC teams can tune them.
    
    Returns a dict with:
        level  → "LOW" / "MEDIUM" / "HIGH"
        color  → ANSI color code for terminal output
        emoji  → Visual indicator for quick scanning
        action → Recommended SOC analyst action
    """
    if score <= config.LOW_RISK_MAX:
        return {
            "level":  "LOW",
            "color":  "\033[92m",   # Bright Green
            "emoji":  "✅",
            "action": "Likely safe. Monitor if recurring."
        }
    elif score <= config.MEDIUM_RISK_MAX:
        return {
            "level":  "MEDIUM",
            "color":  "\033[93m",   # Bright Yellow
            "emoji":  "⚠️ ",
            "action": "Suspicious. Investigate further. Check VirusTotal & WHOIS."
        }
    else:
        return {
            "level":  "HIGH",
            "color":  "\033[91m",   # Bright Red
            "emoji":  "🚨",
            "action": "High confidence phishing. Block immediately. Escalate if clicked."
        }


def collect_reasons(check_results: list) -> list:
    """
    Extract the human-readable 'reason' from each triggered check.
    
    Only includes reasons from checks that actually detected something
    (i.e., where detected=True and reason is not None).
    
    Returns a clean list of strings for the final report.
    """
    reasons = []
    for result in check_results:
        if result.get("detected") and result.get("reason"):
            reasons.append(result["reason"])
    return reasons


def generate_report(score: int, risk: dict, reasons: list, url: str) -> dict:
    """
    Bundle everything into a single report dictionary.
    
    This is the final output object passed to the display layer.
    Keeping data separate from display logic is good practice —
    it means you could later export this as JSON to a SIEM.
    """
    return {
        "url":     url,
        "score":   score,
        "risk":    risk,
        "reasons": reasons,
        "triggered_count": len(reasons)  # How many checks fired
    }
