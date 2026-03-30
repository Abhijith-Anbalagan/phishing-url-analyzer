#!/usr/bin/env python3
# ============================================================
# main.py — Phishing URL Analyzer | Entry Point
#
# AUTHOR:  [Your Name]
# PURPOSE: SOC-focused tool to analyze URLs for phishing
#          indicators, score risk, and produce a clear report.
#
# USAGE:
#   python main.py
#
# DEPENDENCIES: See requirements.txt
# ============================================================

# ── Standard Library ──────────────────────────────────────
import sys
import json
from datetime import datetime

# ── Third-Party ───────────────────────────────────────────
from colorama import init, Fore, Style   # Colored terminal output

# ── Our Modules ───────────────────────────────────────────
from analyzer.url_validator  import validate_and_parse
from analyzer.phishing_checks import run_all_checks
from analyzer.risk_scorer    import calculate_score, classify_risk, collect_reasons, generate_report
from analyzer.whois_lookup   import get_whois_info, whois_risk_score
from analyzer.virustotal     import scan_url_virustotal

# Initialize colorama (required on Windows for ANSI colors to work)
init(autoreset=True)

# ─────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────

def print_banner():
    """Print the tool banner / header."""
    print("\n" + "=" * 62)
    print(Fore.CYAN + Style.BRIGHT + """
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██║████╗  ██║██╔════╝ 
    ██████╔╝███████║██║███████╗███████║██║██╔██╗ ██║██║  ███╗
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║╚██╗██║██║   ██║
    ██║     ██║  ██║██║███████║██║  ██║██║██║ ╚████║╚██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
    """)
    print(Fore.WHITE + "         🛡️  SOC Phishing URL Analyzer  v1.0")
    print(Fore.WHITE + "         Detect · Score · Report")
    print("=" * 62 + "\n")


def print_section(title: str):
    """Print a section divider with a title."""
    print(f"\n{Fore.CYAN}{'─' * 50}")
    print(f"{Fore.CYAN}  {title}")
    print(f"{Fore.CYAN}{'─' * 50}")


def print_report(report: dict, whois_data: dict, vt_data: dict):
    """
    Display the final analysis report in a clean, SOC-readable format.
    
    Designed to mimic the output you'd see in a SOAR platform or
    a formatted SIEM alert — clear verdict, supporting evidence,
    and a recommended action.
    """
    risk    = report["risk"]
    color   = risk["color"]
    reset   = "\033[0m"

    # ── Header ────────────────────────────────────────────
    print_section("📋 ANALYSIS REPORT")
    print(f"  🔗 URL Analyzed : {Fore.WHITE}{report['url']}")
    print(f"  📅 Timestamp    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    # ── Risk Verdict ──────────────────────────────────────
    print_section("🎯 RISK VERDICT")
    print(f"  {risk['emoji']} Risk Level : {color}{Style.BRIGHT}{risk['level']}{reset}")
    print(f"  📊 Risk Score : {color}{Style.BRIGHT}{report['score']} / 170{reset}  "
          f"({report['triggered_count']} indicator(s) triggered)")
    print(f"\n  {Fore.YELLOW}Recommended Action:")
    print(f"  {Fore.WHITE}{risk['action']}")

    # ── Detection Reasons ─────────────────────────────────
    print_section("🔍 PHISHING INDICATORS DETECTED")
    if report["reasons"]:
        for i, reason in enumerate(report["reasons"], 1):
            print(f"  {Fore.RED}[!] {i}. {reason}")
    else:
        print(f"  {Fore.GREEN}[✓] No phishing indicators detected.")

    # ── WHOIS Information ─────────────────────────────────
    print_section("🌐 DOMAIN WHOIS INFO")
    if whois_data.get("error"):
        print(f"  {Fore.YELLOW}⚠ {whois_data['error']}")
    else:
        age_color = Fore.RED if whois_data.get("is_new") else Fore.GREEN
        print(f"  📌 Domain      : {whois_data.get('domain', 'N/A')}")
        print(f"  📅 Registered  : {whois_data.get('created_date', 'Unknown')}")
        print(f"  🕒 Domain Age  : {age_color}{whois_data.get('age_days', 'N/A')} days old")
        print(f"  🏢 Registrar   : {whois_data.get('registrar', 'Unknown')}")
        print(f"  🌍 Country     : {whois_data.get('country', 'Unknown')}")
        if whois_data.get("is_new"):
            print(f"  {Fore.RED}⚠ Newly registered domain — high phishing risk!")

    # ── VirusTotal Results ────────────────────────────────
    print_section("🦠 VIRUSTOTAL SCAN RESULTS")
    if vt_data.get("error"):
        print(f"  {Fore.YELLOW}⚠ {vt_data['error']}")
    elif vt_data.get("found"):
        pos       = vt_data["positives"]
        total     = vt_data["total"]
        vt_color  = Fore.RED if pos > 0 else Fore.GREEN
        print(f"  🔬 Detections  : {vt_color}{Style.BRIGHT}{pos} / {total} engines")
        print(f"  📅 Scan Date   : {vt_data.get('scan_date', 'N/A')}")
        if vt_data.get("permalink"):
            print(f"  🔗 Full Report : {vt_data['permalink']}")
    else:
        print(f"  ℹ URL not found in VirusTotal database.")

    print("\n" + "=" * 62)
    print(Fore.CYAN + "  Analysis complete. Stay secure! 🛡️")
    print("=" * 62 + "\n")


# ─────────────────────────────────────────────────────────────
# MAIN ANALYSIS PIPELINE
# ─────────────────────────────────────────────────────────────

def analyze_url(raw_url: str, use_vt: bool = False):
    """
    The core pipeline that orchestrates the entire analysis.
    
    Flow:
    1. Validate & parse URL
    2. Run phishing checks
    3. Run WHOIS lookup
    4. (Optional) Query VirusTotal
    5. Calculate risk score
    6. Generate & display report
    """

    # STEP 1: Validate and parse the URL
    print(f"\n{Fore.CYAN}[*] Validating URL...")
    valid, parts, url = validate_and_parse(raw_url)

    if not valid:
        print(f"{Fore.RED}[✗] Invalid URL: '{raw_url}'")
        print(f"{Fore.YELLOW}    Please enter a valid URL (e.g., http://example.com)")
        return

    print(f"{Fore.GREEN}[✓] URL is valid. Starting analysis...")
    print(f"{Fore.WHITE}    Domain: {parts.get('domain')}")

    # STEP 2: Run all phishing indicator checks
    print(f"{Fore.CYAN}[*] Running phishing checks...")
    check_results = run_all_checks(url, parts)

    # STEP 3: WHOIS domain age lookup
    print(f"{Fore.CYAN}[*] Performing WHOIS lookup...")
    whois_data    = get_whois_info(parts.get("domain", ""))
    whois_result  = whois_risk_score(whois_data)
    check_results.append(whois_result)   # Add WHOIS score to the pool

    # STEP 4: VirusTotal lookup (optional)
    vt_data = {"error": "VirusTotal scan skipped (use --vt flag to enable)"}
    if use_vt:
        print(f"{Fore.CYAN}[*] Querying VirusTotal API...")
        vt_data = scan_url_virustotal(url)
        if vt_data.get("vt_risk_score", 0) > 0:
            check_results.append({
                "detected": True,
                "score":    vt_data["vt_risk_score"],
                "reason":   f"VirusTotal: {vt_data['positives']}/{vt_data['total']} engines flagged this URL"
            })

    # STEP 5: Calculate total risk score and classify
    score   = calculate_score(check_results)
    risk    = classify_risk(score)
    reasons = collect_reasons(check_results)

    # STEP 6: Generate report dictionary
    report = generate_report(score, risk, reasons, url)

    # STEP 7: Display the report
    print_report(report, whois_data, vt_data)

    # STEP 8: Optionally export as JSON for SIEM integration
    return report


# ─────────────────────────────────────────────────────────────
# INTERACTIVE LOOP
# ─────────────────────────────────────────────────────────────

def main():
    """
    Main interactive loop.
    
    Keeps running until the user types 'exit' or 'quit'.
    A real SOC tool would take URLs from a queue, API, or log file.
    This interactive mode is ideal for learning and manual triage.
    """
    print_banner()

    # Check if VirusTotal should be enabled
    # Usage: python main.py --vt
    use_vt = "--vt" in sys.argv

    if use_vt:
        print(f"{Fore.CYAN}[ℹ] VirusTotal integration: {Fore.GREEN}ENABLED")
    else:
        print(f"{Fore.YELLOW}[ℹ] VirusTotal integration disabled. Run with --vt to enable.")

    print(f"{Fore.WHITE}    Type 'exit' or 'quit' to stop.\n")

    # ── Analysis Loop ─────────────────────────────────────
    while True:
        try:
            raw_input = input(f"{Fore.GREEN}[?] Enter URL to analyze: {Style.RESET_ALL}").strip()

            if raw_input.lower() in ("exit", "quit", "q"):
                print(f"\n{Fore.CYAN}[*] Exiting Phishing URL Analyzer. Stay secure! 🛡️\n")
                break

            if not raw_input:
                print(f"{Fore.YELLOW}[!] No URL entered. Please try again.\n")
                continue

            # Run the full analysis pipeline
            analyze_url(raw_input, use_vt=use_vt)

            # Ask if user wants to analyze another
            again = input(f"{Fore.CYAN}[?] Analyze another URL? (y/n): {Style.RESET_ALL}").strip().lower()
            if again != "y":
                print(f"\n{Fore.CYAN}[*] Exiting. Stay secure! 🛡️\n")
                break

        except KeyboardInterrupt:
            # Handle Ctrl+C gracefully
            print(f"\n\n{Fore.YELLOW}[!] Interrupted by user. Exiting...\n")
            break


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # This block runs only when script is executed directly
    # (not when imported as a module)
    main()
