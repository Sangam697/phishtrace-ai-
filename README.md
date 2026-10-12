# 🛡️ PhishGuard AI — Hybrid Phishing Domain Analysis & Threat Intelligence Platform

**PhishGuard AI** is a full-stack defensive cybersecurity application that analyzes domains and URLs to detect phishing infrastructure, brand impersonation, IDN homograph attacks, and newly registered malicious lures.

It combines **Machine Learning (Random Forest with Explainable AI)**, **Lexical & Entropy Heuristics**, **Typosquatting / Homoglyph Detection**, **Live DNS / SSL / WHOIS Telemetry**, and an **AI Security Analyst Threat Report Generator** in a modern dark-mode SOC Web Dashboard.

---

## ✨ Key Features

1. **Deep Domain Scanner & Composite Risk Gauge (0–100)**
   - Animated SVG Threat Gauge with instant verdict classification (`PHISHING / MALICIOUS`, `SUSPICIOUS`, `LIKELY SAFE`).
   - Breakdown across 4 sub-engines: **ML Classifier Probability**, **Brand & Homoglyph Risk**, **Lexical & URL Heuristics**, and **Network Infrastructure Risk**.
2. **Brand Impersonation, Typosquatting & IDN Homoglyph Engine**
   - Protects 30+ major global targets (PayPal, Microsoft, Apple, Google, Amazon, Chase, GitHub, Binance, etc.).
   - Detects **Leetspeak / Visual Substitutions** (`paypa1`, `arnazon`, `micr0soft`, `g00gle`), **Levenshtein Typosquatting**, **Combo-squatting**, **Subdomain Spoofing**, and **Punycode (`xn--`) Cyrillic/Greek Unicode Homographs**.
3. **Explainable Machine Learning (XAI) Classifier**
   - Built-in `scikit-learn` Random Forest model (`RandomForest-PhishGuard-v1`) evaluating 14 domain, lexical, brand, and infrastructure features.
   - Displays local feature impact scores (`+38.5 High Risk`, `-45.0 Trust Signal`) so analysts see *why* a domain was flagged.
4. **Live DNS, SSL/TLS & WHOIS Infrastructure Inspector**
   - Concurrent inspection of **WHOIS Domain Age** (flags Newly Registered Domains `< 60` days old), **SSL/TLS Certificate chain** (Issuer CA, certificate age, validity), and **DNS Records** (`A`, `MX`, `NS`, `SPF`, and `DMARC`).
5. **AI Threat Intelligence Report & Batch Scanner**
   - Generates an Executive Summary, Attack Vector Analysis, Key Risk/Trust Indicators, and SOC Remediation Steps (works 100% locally out-of-the-box, and optionally upgrades to live **Google Gemini** or **OpenAI GPT** analysis if `GEMINI_API_KEY` or `OPENAI_API_KEY` is provided in `.env`).
   - Includes a **Batch Domain Scanner** and persistent **SQLite Scan History** with JSON report export.

---

## 🚀 Quick Start

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Run the Web Application
```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser to launch the PhishGuard AI SOC Dashboard.

### 3. Run Automated Tests
```powershell
pytest
```

---

## 📂 Project Structure

```text
ai-powerd-phishing_domain_anayles/
├── app/
│   ├── main.py                  # FastAPI server, scoring fusion & REST API endpoints
│   ├── models.py                # Pydantic schemas for telemetry & AI reports
│   ├── database.py              # SQLite persistence for scan history & SOC metrics
│   └── analyzers/
│       ├── lexical_analyzer.py  # URL parsing, Shannon entropy, TLD & lure keyword risk
│       ├── brand_analyzer.py    # Typosquatting, Leetspeak, Combo-squatting & IDN Homoglyphs
│       ├── network_inspector.py # Concurrent DNS (A/MX/NS/SPF/DMARC), SSL/TLS & WHOIS lookup
│       ├── ml_classifier.py     # Random Forest classifier + Explainable AI (XAI) weights
│       └── ai_reasoning.py      # Hybrid AI Threat Analyst (Gemini/OpenAI + Local Expert Engine)
├── static/
│   ├── css/styles.css           # Dark-mode SOC dashboard styling
│   └── js/app.js                # Interactive scanner, SVG gauge, tabs & history controller
├── templates/
│   └── index.html               # Main Web Dashboard interface
├── tests/
│   └── test_analyzer.py         # Pytest suite for lexical, brand, ML & API verification
├── requirements.txt
└── .env.example
```

