# ============================================================
# config.py — Central configuration file
# Store your API keys and global settings here.
# NEVER upload this file to GitHub with real keys inside.
# Use environment variables or a .env file in production.
# ============================================================

# VirusTotal API Key
# Get yours free at: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY_HERE"

# VirusTotal API endpoint for URL scanning
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/url/report"

# Risk score thresholds
# These control how we classify the final score into Low/Medium/High
LOW_RISK_MAX    = 30   # Score 0–30   → Low Risk
MEDIUM_RISK_MAX = 60   # Score 31–60  → Medium Risk
                        # Score 61+    → High Risk

# Suspicious keywords commonly found in phishing URLs
# SOC context: attackers craft URLs that look legitimate by using
# trust-inducing words like "secure", "verify", "login", etc.
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "bank", "paypal", "password", "credential",
    "signin", "sign-in", "validate", "confirm", "ebay",
    "amazon", "apple", "microsoft", "support", "urgent",
    "suspended", "unusual", "activity", "free", "winner",
    "click", "alert", "access", "webscr", "submit"
]

# URL length threshold
# Phishing URLs are often intentionally long to hide the real domain
LONG_URL_THRESHOLD = 75  # characters
