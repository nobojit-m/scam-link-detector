import streamlit as st
import re
import whois
import requests
import datetime

# ==============================================================================
# PART 1: BACKEND - SCAM DETECTION LOGIC
# ==============================================================================

# --- 1. URL Extraction and Validation ---
def extract_domain(url):
    """
    Extract the domain from a URL using regex.
    Returns the domain as a string, or None if extraction fails.
    """
    regex = r"^(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9\-\.]+)"
    match = re.search(regex, url)
    return match.group(1) if match else None

# --- 2. WHOIS Lookup for Domain Age ---
def get_domain_age(domain):
    """
    Get the domain's age in days using WHOIS lookup.
    Returns the age in days as an integer, or None if lookup fails.
    """
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation_date = w.creation_date if isinstance(w.creation_date, list) else w.creation_date
            return (datetime.datetime.now() - creation_date).days
    except Exception:
        return None

# --- 3. SSL Certificate Check ---
def check_ssl_certificate(domain):
    """
    Check if the domain has a valid SSL certificate using a free API.
    Returns True if valid and not expired, otherwise False.
    """
    try:
        response = requests.get(f"https://api.sslpki.com/api/v1/check/{domain}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('is_valid', False) and not data.get('is_expired', True)
    except requests.exceptions.RequestException:
        return False

# --- 4. Phishing Keyword Detection ---
def contains_phishing_keywords(url):
    """
    Check if the URL contains common phishing keywords.
    Returns True if any keyword is found, otherwise False.
    """
    keywords = [
        "login", "verify", "account", "update", "secure", "bank",
        "paypal", "signin", "recovery", "password", "support"
    ]
    return any(keyword in url.lower() for keyword in keywords)

# --- 5. Scam Likelihood Score Calculation ---
def calculate_scam_score(url):
    """
    Calculate a scam score for the given URL and provide a detailed explanation.
    Returns a dictionary with the score, verdict, and explanation.
    """
    domain = extract_domain(url)
    if not domain:
        return {"error": "Invalid URL format. Please enter a valid link."}

    score = 0
    explanation = []

    # Check 1: Domain Age
    domain_age = get_domain_age(domain)
    if domain_age is not None:
        if domain_age < 90:  # Less than 3 months old
            score += 40
            explanation.append(f"🚩 **Domain is very new ({domain_age} days old).** Scam sites are often short-lived.")
        elif domain_age < 365:  # Less than a year old
            score += 20
            explanation.append(f"⚠️ **Domain is less than a year old ({domain_age} days old).** Use with caution.")
    else:
        score += 10
        explanation.append("⚠️ **Could not verify domain age.** This can be a red flag for newly created scam sites.")

    # Check 2: SSL Certificate (HTTPS)
    if not check_ssl_certificate(domain):
        score += 30
        explanation.append("🚩 **No valid SSL certificate found.** Secure websites use HTTPS to encrypt your data.")

    # Check 3: Phishing Keywords in URL
    if contains_phishing_keywords(url):
        score += 30
        explanation.append("🚩 **URL contains suspicious keywords** (e.g., 'login', 'verify', 'support').")

    # Final verdict if no issues found
    if not explanation:
        explanation.append("✅ **This link appears to be safe** based on our checks.")

    # Determine verdict based on score
    verdict = "Likely Safe"
    if score >= 70:
        verdict = "High Scam Likelihood"
    elif score >= 40:
        verdict = "Potential Scam"

    return {
        "url": url,
        "score": min(score, 100),
        "verdict": verdict,
        "explanation": explanation
    }

# ==============================================================================
# PART 2: FRONTEND - STREAMLIT WEB GUI
# ==============================================================================

# Set Streamlit page configuration
st.set_page_config(page_title="Scam Link Detector", page_icon="🛡️", layout="centered")

# App title and description
st.title("🛡️ Real-Time Scam Link Detector")
st.write(
    "Paste a URL below to analyze its potential risk. The tool checks domain age, "
    "SSL security, and for suspicious keywords to keep you safe online."
)

# URL input box
url_input = st.text_input("Enter the URL to check", placeholder="https://example.com")

# Analyze button logic
if st.button("Analyze Link", type="primary"):
    if url_input:
        with st.spinner("Analyzing... This may take a moment."):
            results = calculate_scam_score(url_input)

        st.subheader("Analysis Report")

        if "error" in results:
            st.error(results["error"])
        else:
            score = results['score']
            verdict = results['verdict']

            # Display verdict with appropriate color
            if score >= 70:
                st.error(f"**Verdict: {verdict}** (Score: {score}/100)")
            elif score >= 40:
                st.warning(f"**Verdict: {verdict}** (Score: {score}/100)")
            else:
                st.success(f"**Verdict: {verdict}** (Score: {score}/100)")

            # Show detailed explanation
            st.write("#### Detailed Breakdown:")
            for point in results['explanation']:
                st.markdown(f"- {point}")
    else:
        st.warning("Please enter a URL to analyze.")

# Disclaimer at the bottom
st.markdown("---")
st.info(
    "Disclaimer: This tool provides an automated assessment and is not a guarantee. "
    "Always be cautious when clicking unfamiliar links.",
    icon="ℹ️"
)