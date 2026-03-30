import streamlit as st

# Import your modules
from analyzer.url_validator import validate_and_parse
from analyzer.phishing_checks import run_all_checks
from analyzer.risk_scorer import calculate_score, classify_risk, collect_reasons
from analyzer.whois_lookup import get_whois_info, whois_risk_score

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
# INPUT
# ─────────────────────────────────────────────
url = st.text_input("🔗 Enter URL to analyze")

# ─────────────────────────────────────────────
# ANALYZE BUTTON
# ─────────────────────────────────────────────
if st.button("🔍 Analyze"):

    if not url:
        st.warning("⚠️ Please enter a URL")
        st.stop()

    with st.spinner("Analyzing URL..."):

        # STEP 1: Validate URL
        valid, parts, parsed_url = validate_and_parse(url)

        if not valid:
            st.error("❌ Invalid URL")
            st.stop()

        st.success("✅ URL is valid")

        # STEP 2: Run checks
        results = run_all_checks(parsed_url, parts)

        # STEP 3: WHOIS
        whois_data = get_whois_info(parts.get("domain", ""))
        whois_result = whois_risk_score(whois_data)
        results.append(whois_result)

        # STEP 4: Risk Calculation
        score = calculate_score(results)
        risk = classify_risk(score)
        reasons = collect_reasons(results)

    # ─────────────────────────────────────────────
    # DISPLAY RESULTS
    # ─────────────────────────────────────────────

    # 📊 Risk Score
    st.subheader("📊 Risk Score")
    st.write(f"Score: {score} / 170")
    st.progress(score / 170)

    # 🚨 Risk Level
    st.subheader("🚨 Risk Level")

    if risk["level"] == "HIGH":
        st.error(f"🔴 HIGH RISK")
    elif risk["level"] == "MEDIUM":
        st.warning(f"🟡 MEDIUM RISK")
    else:
        st.success(f"🟢 LOW RISK")

    # 🔍 Indicators
    st.subheader("🔍 Indicators")

    if reasons:
        for r in reasons:
            st.error(f"⚠️ {r}")
    else:
        st.success("✅ No phishing indicators detected")

    # 🌐 WHOIS INFO
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