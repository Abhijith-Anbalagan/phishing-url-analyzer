# ============================================================
# analyzer/virustotal.py — VirusTotal API Integration
#
# PURPOSE: Submit a URL to VirusTotal and retrieve scan results
# from 70+ antivirus engines and URL scanners.
#
# SOC RELEVANCE: VirusTotal is one of the most widely used
# threat intelligence platforms in SOC workflows. Analysts
# check URLs, file hashes, and IPs against VT daily.
# This module automates that lookup.
#
# HOW TO GET A FREE API KEY:
# 1. Go to https://www.virustotal.com/gui/join-us
# 2. Register a free account
# 3. Go to your profile → API Key
# 4. Paste it in config.py
#
# FREE TIER LIMIT: 4 requests/minute, 500/day
# ============================================================

import requests               # For HTTP API calls
import config                 # API key from config.py


def scan_url_virustotal(url: str) -> dict:
    """
    Query VirusTotal for scan results on the given URL.
    
    Uses the v2 API (free tier compatible).
    
    Returns a dict with:
        found         → True if VT has results for this URL
        positives     → Number of engines flagging it as malicious
        total         → Total engines that scanned it
        scan_date     → When it was last scanned
        permalink     → Direct link to VT report
        vt_risk_score → Points to add to overall risk score
        error         → Error message if API call failed
    """
    result = {
        "found":         False,
        "positives":     0,
        "total":         0,
        "scan_date":     None,
        "permalink":     None,
        "vt_risk_score": 0,
        "error":         None
    }

    # Don't attempt if no API key configured
    if config.VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        result["error"] = "VirusTotal API key not configured. Add it to config.py"
        return result

    try:
        # Build the API request
        params = {
            "apikey":   config.VIRUSTOTAL_API_KEY,
            "resource": url            # The URL to look up
        }

        # Make GET request to VirusTotal API
        response = requests.get(
            config.VIRUSTOTAL_URL,
            params=params,
            timeout=10                 # Don't wait more than 10 seconds
        )

        # Check if request was successful (HTTP 200)
        response.raise_for_status()

        # Parse the JSON response
        data = response.json()

        # response_code 1 means VT has this URL in its database
        if data.get("response_code") == 1:
            positives = data.get("positives", 0)
            total     = data.get("total", 0)

            result["found"]     = True
            result["positives"] = positives
            result["total"]     = total
            result["scan_date"] = data.get("scan_date", "Unknown")
            result["permalink"] = data.get("permalink", "")

            # Calculate risk score contribution from VT results
            # If ANY engine flags it → suspicious. If many → very high risk.
            if positives >= 10:
                result["vt_risk_score"] = 40   # High confidence malicious
            elif positives >= 3:
                result["vt_risk_score"] = 25   # Multiple detections
            elif positives >= 1:
                result["vt_risk_score"] = 15   # At least one detection
        else:
            # URL not found in VT database — could be brand new
            result["error"] = "URL not found in VirusTotal database (may be very new)"

    except requests.exceptions.Timeout:
        result["error"] = "VirusTotal API timed out after 10 seconds"
    except requests.exceptions.ConnectionError:
        result["error"] = "Cannot reach VirusTotal API — check internet connection"
    except Exception as e:
        result["error"] = f"VirusTotal API error: {str(e)}"

    return result
