import streamlit as st

# Import your modules
from analyzer.url_validator import validate_and_parse
from analyzer.phishing_checks import run_all_checks
from analyzer.risk_scorer import calculate_score, classify_risk, collect_reasons
from analyzer.whois_lookup import get_whois_info, whois_risk_score

#css
st.markdown("""<style>
.footer{position:fixed;left:0;bottom:0;width:100%;background-color:#0e1117;
color:white;text-align:center;padding:10px;font-size:14px;
border-top:1px solid #262730;z-index:100;}
</style>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing URL Analyzer",
    page_icon="🛡️",
    layout="centered"
)

# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.title("🛡️ Phishing URL Analyzer")
st.markdown("SOC-style phishing detection tool")
# ─────────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────────
if "url" not in st.session_state:
    st.session_state.url = ""

# ─────────────────────────────────────────────
# LOAD EXAMPLE BUTTON (MOVE ABOVE INPUT)
# ─────────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    analyze_btn = st.button("🔍 Analyze")

with col2:
    if st.button("⚡ Load Example"):
        st.session_state.url = "http://paypal-login-secure.tk@fake.com"

# ─────────────────────────────────────────────
# INPUT FIELD (AFTER SETTING STATE)
# ─────────────────────────────────────────────
url = st.text_input("🔗 Enter URL to analyze", value=st.session_state.url)

# Sync state manually
st.session_state.url = url

# ─────────────────────────────────────────────
# ANALYSIS LOGIC
# ─────────────────────────────────────────────
if analyze_btn:

    if not st.session_state.url:
        st.warning("⚠️ Please enter a URL")
        st.stop()

    with st.spinner("Analyzing URL..."):

        # Validate URL
        valid, parts, parsed_url = validate_and_parse(st.session_state.url)

        if not valid:
            st.error("❌ Invalid URL")
            st.stop()

        st.success("✅ URL is valid")

        # Run phishing checks
        results = run_all_checks(parsed_url, parts)

        # WHOIS lookup
        whois_data = get_whois_info(parts.get("domain", ""))
        whois_result = whois_risk_score(whois_data)
        results.append(whois_result)

        # Risk scoring
        score = calculate_score(results)
        risk = classify_risk(score)
        reasons = collect_reasons(results)

    # ─────────────────────────────────────────────
    # OUTPUT SECTION
    # ─────────────────────────────────────────────

    # 📊 Risk Score
    st.subheader("📊 Risk Score")
    st.write(f"Score: {score} / 170")
    st.progress(score / 170)

    # 🚨 Risk Level
    st.subheader("🚨 Risk Level")

    if risk["level"] == "HIGH":
        st.error("🔴 HIGH RISK")
    elif risk["level"] == "MEDIUM":
        st.warning("🟡 MEDIUM RISK")
    else:
        st.success("🟢 LOW RISK")

    # ℹ️ Explanation
    st.info("This URL is classified based on multiple phishing indicators such as suspicious keywords, domain tricks, and insecure protocol.")

    # 🔍 Indicators
    st.subheader("🔍 Indicators")

    if reasons:
        for r in reasons:
            st.error(f"⚠️ {r}")
    else:
        st.success("✅ No phishing indicators detected")

    # 🌐 WHOIS Info
    st.subheader("🌐 WHOIS Info")

    if whois_data.get("error"):
        st.warning(f"⚠️ {whois_data['error']}")
    else:
        st.write(f"**Domain:** {whois_data.get('domain')}")
        st.write(f"**Created:** {whois_data.get('created_date')}")
        st.write(f"**Registrar:** {whois_data.get('registrar')}")
        st.write(f"**Country:** {whois_data.get('country')}")
        st.write(f"**Age (days):** {whois_data.get('age_days')}")

        if whois_data.get("is_new"):
            st.error("🚨 Newly registered domain (High Risk)")

# ─────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────
st.markdown("""
<div class="footer">
    👨‍💻 Developed by <b>Abhijith A</b> | SOC Analyst (Aspiring) |
    <a href="https://github.com/Abhijith-Anbalagan" target="_blank" style="color:#4da6ff;">🔗 GitHub</a>
</div>
""", unsafe_allow_html=True)