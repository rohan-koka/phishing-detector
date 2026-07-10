# 🎣 Phishing URL Detector

A web app that analyzes URLs for common phishing indicators and assigns a risk score.

## Features
- Checks for HTTPS usage
- Detects IP addresses used instead of domain names
- Flags suspicious keywords commonly used in phishing attacks
- Identifies suspicious top-level domains (.xyz, .tk, .ml, etc.)
- Detects excessive subdomains, hyphens, and encoded characters
- Provides a risk score and full URL breakdown

## Live Demo
[Try it here](https://phishing-detector-9ky9qgyungbxghe3devyr8.streamlit.app/)

## Built With
- Python
- Streamlit

## Run Locally
```bash
pip3 install streamlit
streamlit run app.py
```

## ⚠️ Disclaimer
This tool checks for common phishing patterns but is not a guarantee of safety. Always verify URLs carefully.
