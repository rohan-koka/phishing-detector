import streamlit as st
import re
from urllib.parse import urlparse

st.set_page_config(page_title="Phishing URL Detector", layout="centered")

st.title("🎣 Phishing URL Detector")
st.write("Analyze a URL for common phishing indicators.")

url = st.text_input("Enter a URL to analyze (e.g. https://google.com)")

suspicious_keywords = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "credential", "suspend",
    "urgent", "alert", "free", "winner", "prize", "click"
]

suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".pw"]

def analyze_url(url):
    flags = []
    score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        # Check HTTPS
        if parsed.scheme != "https":
            flags.append("❌ Not using HTTPS — data may not be encrypted")
            score += 2

        # Check IP address instead of domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            flags.append("❌ Uses an IP address instead of a domain name")
            score += 3

        # Check URL length
        if len(url) > 75:
            flags.append(f"⚠️ URL is unusually long ({len(url)} characters)")
            score += 1

        # Check for suspicious keywords
        found_keywords = [kw for kw in suspicious_keywords if kw in full]
        if found_keywords:
            flags.append(f"⚠️ Contains suspicious keywords: {', '.join(found_keywords)}")
            score += len(found_keywords)

        # Check for suspicious TLDs
        found_tlds = [tld for tld in suspicious_tlds if domain.endswith(tld)]
        if found_tlds:
            flags.append(f"❌ Uses a suspicious TLD: {', '.join(found_tlds)}")
            score += 3

        # Check for multiple subdomains
        subdomain_count = domain.count(".")
        if subdomain_count > 2:
            flags.append(f"⚠️ Has multiple subdomains ({subdomain_count} dots in domain)")
            score += 2

        # Check for @ symbol in URL
        if "@" in url:
            flags.append("❌ Contains @ symbol — could be used to trick users")
            score += 3

        # Check for double slashes in path
        if "//" in path:
            flags.append("⚠️ Contains double slashes in the path")
            score += 1

        # Check for hyphens in domain
        if domain.count("-") > 1:
            flags.append(f"⚠️ Domain contains multiple hyphens")
            score += 1

        # Check for hex encoding
        if "%" in url:
            flags.append("⚠️ URL contains encoded characters")
            score += 1

    except Exception as e:
        flags.append(f"Could not parse URL: {str(e)}")
        score += 5

    return flags, score

if url:
    flags, score = analyze_url(url)

    st.divider()

    if score == 0:
        st.success("✅ No suspicious indicators found. URL appears safe.")
    elif score <= 3:
        st.warning("⚠️ Low risk — a few minor indicators found.")
    elif score <= 7:
        st.warning("🚨 Medium risk — multiple suspicious indicators found.")
    else:
        st.error("🔴 High risk — this URL has many phishing indicators. Do not visit.")

    st.markdown(f"### Risk Score: {score}")
    st.progress(min(score / 15, 1.0))

    if flags:
        st.markdown("### Flags Found")
        for flag in flags:
            st.write(flag)
    else:
        st.write("No flags raised.")

    st.divider()
    st.markdown("### URL Breakdown")
    try:
        parsed = urlparse(url)
        st.write(f"**Scheme:** {parsed.scheme}")
        st.write(f"**Domain:** {parsed.netloc}")
        st.write(f"**Path:** {parsed.path}")
        if parsed.query:
            st.write(f"**Query:** {parsed.query}")
    except:
        st.write("Could not break down URL.")

st.divider()
st.caption("⚠️ This tool checks for common phishing patterns but is not a guarantee of safety. Always verify URLs carefully.")