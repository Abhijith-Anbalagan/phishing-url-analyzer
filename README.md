# 🛡️ Phishing URL Analyzer

> A SOC-focused Python tool for detecting and scoring phishing URLs using multiple detection techniques, WHOIS lookups, and optional VirusTotal API integration.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![SOC](https://img.shields.io/badge/Use%20Case-SOC%20%7C%20Blue%20Team-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📌 Project Overview

**Phishing URL Analyzer** is a command-line security tool built for Security Operations Center (SOC) analysts to quickly triage suspicious URLs. It automates the manual URL investigation process by checking multiple phishing indicators, assigning a risk score, and providing a clear verdict with supporting evidence.

This tool simulates real-world SOC workflows including URL enrichment, threat scoring, and WHOIS-based domain age analysis — all core skills for Tier 1 and Tier 2 analysts.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **7 Phishing Checks** | IP-based URLs, long URLs, suspicious keywords, `@` symbol, hyphen-heavy domains, suspicious TLDs, HTTP usage |
| 📊 **Risk Scoring Engine** | Weighted score from 0–170 mapped to LOW / MEDIUM / HIGH risk |
| 🌐 **WHOIS Lookup** | Detects newly registered domains (< 30 days) — a key phishing signal |
| 🦠 **VirusTotal Integration** | Optional API scan against 70+ AV engines |
| 🎨 **Color-Coded Output** | Green / Yellow / Red terminal output for quick visual triage |
| 🔁 **Interactive Loop** | Analyze multiple URLs in one session |
| 📋 **SOC Report Format** | Structured output ready for incident tickets or SOAR integration |

---

## 📁 Project Structure

```
phishing-url-analyzer/
│
├── analyzer/
│   ├── __init__.py           # Package initializer
│   ├── url_validator.py      # URL validation and parsing
│   ├── phishing_checks.py    # 7 detection checks
│   ├── risk_scorer.py        # Scoring and classification engine
│   ├── whois_lookup.py       # WHOIS domain age analysis
│   └── virustotal.py         # VirusTotal API integration
│
├── main.py                   # Entry point — run this
├── config.py                 # API keys and thresholds
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.8 or higher
- pip (comes with Python)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/phishing-url-analyzer.git
cd phishing-url-analyzer

# 2. Create a virtual environment (recommended)
python -m venv venv

# 3. Activate the virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Mode (no API key needed)

```bash
python main.py
```

### With VirusTotal Integration

```bash
python main.py --vt
```

> Add your free VirusTotal API key to `config.py` before using `--vt`.
> Get your key at: https://www.virustotal.com/gui/join-us

---

## 📸 Example Output

```
==============================================================
         🛡️  SOC Phishing URL Analyzer  v1.0
         Detect · Score · Report
==============================================================

[?] Enter URL to analyze: http://secure-paypal-login.tk/verify@account

[*] Validating URL...
[✓] URL is valid. Starting analysis...
    Domain: secure-paypal-login.tk
[*] Running phishing checks...
[*] Performing WHOIS lookup...

──────────────────────────────────────────────────
  📋 ANALYSIS REPORT
──────────────────────────────────────────────────
  🔗 URL Analyzed : http://secure-paypal-login.tk/verify@account
  📅 Timestamp    : 2025-01-15 14:32:07 UTC

──────────────────────────────────────────────────
  🎯 RISK VERDICT
──────────────────────────────────────────────────
  🚨 Risk Level : HIGH
  📊 Risk Score : 130 / 170  (6 indicator(s) triggered)

  Recommended Action:
  High confidence phishing. Block immediately. Escalate if clicked.

──────────────────────────────────────────────────
  🔍 PHISHING INDICATORS DETECTED
──────────────────────────────────────────────────
  [!] 1. Suspicious keywords found: secure, paypal, login, verify
  [!] 2. URL uses suspicious TLD '.tk' — frequently abused in phishing
  [!] 3. '@' symbol found — real destination may be hidden after it
  [!] 4. Domain contains 2 hyphens — common in fake brand domains
  [!] 5. URL is unusually long (52 characters)

──────────────────────────────────────────────────
  🌐 DOMAIN WHOIS INFO
──────────────────────────────────────────────────
  📌 Domain      : secure-paypal-login.tk
  📅 Registered  : 2025-01-13
  🕒 Domain Age  : 2 days old
  🏢 Registrar   : Freenom
  ⚠  Newly registered domain — high phishing risk!
==============================================================
```

---

## 🧠 How the Risk Scoring Works

| Check | Max Points | Trigger Condition |
|---|---|---|
| IP-based URL | 30 | URL contains raw IP address |
| Long URL | 20 | URL > 75 characters |
| Suspicious Keywords | 45 | Phishing-related words found |
| `@` Symbol | 25 | `@` found in URL |
| Hyphen-Heavy Domain | 20 | 2+ hyphens in domain |
| Suspicious TLD | 20 | `.tk`, `.xyz`, `.top`, etc. |
| No HTTPS | 10 | Using HTTP instead of HTTPS |
| New Domain (WHOIS) | 35 | Domain < 7 days old |
| VirusTotal | 40 | 10+ engines flagged URL |

| Score Range | Risk Level | SOC Action |
|---|---|---|
| 0 – 30 | 🟢 LOW | Monitor |
| 31 – 60 | 🟡 MEDIUM | Investigate |
| 61+ | 🔴 HIGH | Block & Escalate |

---

## 🔧 Configuration

Edit `config.py` to customize:

```python
VIRUSTOTAL_API_KEY  = "your_key_here"
LONG_URL_THRESHOLD  = 75         # Characters before flagging as long
LOW_RISK_MAX        = 30         # Score threshold for LOW risk
MEDIUM_RISK_MAX     = 60         # Score threshold for MEDIUM risk
SUSPICIOUS_KEYWORDS = [...]      # Add your own keywords
```

---

## 🛡️ SOC Use Cases

- **Phishing email triage** — Paste URLs from suspicious emails for instant assessment
- **Alert enrichment** — Enrich SIEM alerts with domain age and VT detections
- **Security awareness training** — Demonstrate to users what makes a URL suspicious
- **SOAR integration** — Export JSON output to feed into automated playbooks
- **CTF / Blue Team labs** — Practice URL analysis techniques

---

## 📚 Technologies Used

- **Python 3.8+**
- `requests` — VirusTotal API communication
- `python-whois` — Domain registration lookup
- `colorama` — Cross-platform terminal colors
- `validators` — URL format validation

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**[Your Name]**  
Cybersecurity Enthusiast | Aspiring SOC Analyst  
[LinkedIn](https://linkedin.com/in/YOUR_PROFILE) · [GitHub](https://github.com/YOUR_USERNAME)

---

> ⚠️ **Disclaimer**: This tool is intended for educational and legitimate security research purposes only. Do not use it against systems or URLs without proper authorization.
