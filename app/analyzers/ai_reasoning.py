import json
import os
from typing import List
import httpx
from app.models import (
    LexicalAnalysisResult,
    BrandAnalysisResult,
    NetworkAnalysisResult,
    MLAnalysisResult,
    AIReasoningReport,
)


def _generate_expert_fallback_report(
    overall_score: int,
    risk_level: str,
    lexical: LexicalAnalysisResult,
    brand: BrandAnalysisResult,
    network: NetworkAnalysisResult,
    ml_res: MLAnalysisResult,
) -> AIReasoningReport:
    """
    Deterministic Expert AI Threat Analyst Engine that synthesizes lexical, brand,
    network, and ML telemetry into a structured SOC threat intelligence report.
    """
    domain = lexical.domain

    if brand.is_official_brand_domain:
        brand_name = brand.detected_brands[0].brand if brand.detected_brands else domain
        return AIReasoningReport(
            engine_used="PhishGuard Hybrid Expert AI Engine",
            executive_summary=(
                f"'{domain}' is verified as an authentic, official domain belonging to {brand_name}. "
                f"Lexical telemetry, domain registration longevity, and ML classification ({ml_res.ml_risk_score}% risk) "
                f"confirm legitimate infrastructure."
            ),
            threat_category="Verified Legitimate Brand Domain",
            attack_vector_analysis=(
                f"No deceptive attack vectors observed. The root domain '{lexical.registered_domain}' matches "
                f"the canonical whitelist for {brand_name}. Standard security verification (HTTPS certificate validation) applies."
            ),
            key_risk_indicators=[],
            trust_indicators=[
                f"Verified official root domain for {brand_name} ({lexical.registered_domain})",
                f"Low ML phishing probability ({round(ml_res.phishing_probability * 100, 1)}%)",
                *(s for s in network.signals if "Trust signal" in s or "Active TLS" in s),
            ],
            recommended_actions=[
                "Allow traffic under standard organizational web filtering policies.",
                "Ensure users connect over HTTPS and verify full URL path if redirected from external emails.",
            ],
        )

    # Determine primary threat category
    if brand.is_punycode_idn or brand.homoglyphs_detected:
        threat_cat = "IDN Homograph / Visual Spoofing Attack"
    elif brand.detected_brands:
        tech = brand.detected_brands[0].technique
        target_brand = brand.detected_brands[0].brand
        threat_cat = f"Brand Impersonation ({tech} targeting {target_brand})"
    elif lexical.has_ip_address or lexical.has_at_symbol or lexical.has_double_slash_redirect:
        threat_cat = "URL Obfuscation & Evasion Infrastructure"
    elif lexical.suspicious_keywords and overall_score >= 55:
        threat_cat = "Credential Harvesting / Social Engineering Lure"
    elif network.whois.is_newly_registered:
        threat_cat = "Suspicious Newly Registered Domain (NRD)"
    elif overall_score >= 40:
        threat_cat = "Anomalous / Potentially Deceptive Domain"
    else:
        threat_cat = "Benign / Standard Domain Profile"

    # Build Executive Summary & Attack Vector Analysis
    if overall_score >= 75:
        target_clause = (
            f" specifically impersonating {brand.detected_brands[0].brand} via {brand.detected_brands[0].technique.lower()}"
            if brand.detected_brands
            else ""
        )
        exec_summary = (
            f"CRITICAL THREAT DETECTED: '{domain}' exhibits high-confidence indicators of a phishing domain "
            f"(Overall Risk Score: {overall_score}/100, ML Probability: {round(ml_res.phishing_probability * 100, 1)}%){target_clause}. "
            f"Immediate blocking and credential telemetry review are strongly advised."
        )
    elif overall_score >= 45:
        exec_summary = (
            f"ELEVATED RISK: '{domain}' displays multiple suspicious attributes aligned with phishing or deceptive lures "
            f"(Overall Risk Score: {overall_score}/100). Exercise caution and verify domain ownership before allowing user interaction."
        )
    else:
        exec_summary = (
            f"LOW RISK PROFILE: '{domain}' does not exhibit overt brand impersonation or deceptive lexical patterns "
            f"(Overall Risk Score: {overall_score}/100). Infrastructure appears consistent with standard web properties."
        )

    vector_parts = []
    if brand.detected_brands:
        b = brand.detected_brands[0]
        vector_parts.append(
            f"Attackers leverage {b.technique} ({b.details}) to deceive victims into believing they are interacting with {b.brand}."
        )
    if lexical.suspicious_keywords:
        vector_parts.append(
            f"The URL embeds high-urgency social engineering tokens ({', '.join(lexical.suspicious_keywords[:4])}) "
            f"commonly used in credential harvesting login portals."
        )
    if lexical.is_high_risk_tld:
        vector_parts.append(
            f"Hosted on '.{lexical.tld}', a top-level domain statistically favored by ephemeral phishing campaigns due to low registration cost."
        )
    if network.whois.is_newly_registered and network.whois.domain_age_days is not None:
        vector_parts.append(
            f"WHOIS records reveal the domain was registered only {network.whois.domain_age_days} days ago, matching rapid burn-and-replace phishing infrastructure."
        )
    if not vector_parts:
        vector_parts.append(
            f"Lexical entropy is {lexical.shannon_entropy} bits/char across a {lexical.domain_length}-character hostname with no detected brand spoofing."
        )

    attack_vector_analysis = " ".join(vector_parts)

    # Collect risk vs trust indicators
    risk_indicators: List[str] = []
    trust_indicators: List[str] = []

    for sig in brand.signals:
        if "No brand impersonation" not in sig:
            risk_indicators.append(sig)
        else:
            trust_indicators.append(sig)

    for sig in lexical.signals:
        if "Clean lexical profile" not in sig:
            risk_indicators.append(sig)
        else:
            trust_indicators.append(sig)

    for sig in network.signals:
        if "(+" in sig:
            risk_indicators.append(sig)
        elif "Trust signal" in sig or "Active TLS" in sig:
            trust_indicators.append(sig)

    # Recommended Actions based on severity
    if overall_score >= 70:
        actions = [
            f"Block '{lexical.registered_domain}' and '*.{lexical.registered_domain}' at DNS sinkhole, Secure Web Gateway (SWG), and email security filters.",
            "Search SIEM / proxy logs for any internal endpoints that resolved or submitted HTTP POST requests to this domain.",
            "If any user interacted with this domain, force an immediate password reset and revoke active session tokens / OAuth grants.",
            "Submit the indicator of compromise (IoC) to threat intelligence feeds and abuse registrars.",
        ]
    elif overall_score >= 40:
        actions = [
            f"Place '{lexical.registered_domain}' under browser isolation or warn-and-audit policy in corporate web filters.",
            "Inspect page DOM and certificate chain in a sandboxed environment before permitting credential entry.",
            "Verify sender authenticity if this link arrived via email, SMS (smishing), or instant messaging.",
        ]
    else:
        actions = [
            "No immediate block required based on current lexical and network telemetry.",
            "Continue standard continuous monitoring and HTTPS verification.",
        ]

    return AIReasoningReport(
        engine_used="PhishGuard Hybrid Expert AI Engine",
        executive_summary=exec_summary,
        threat_category=threat_cat,
        attack_vector_analysis=attack_vector_analysis,
        key_risk_indicators=risk_indicators[:7],
        trust_indicators=trust_indicators[:5],
        recommended_actions=actions,
    )


def generate_ai_threat_report(
    overall_score: int,
    risk_level: str,
    lexical: LexicalAnalysisResult,
    brand: BrandAnalysisResult,
    network: NetworkAnalysisResult,
    ml_res: MLAnalysisResult,
) -> AIReasoningReport:
    """
    Uses Gemini API (if GEMINI_API_KEY is set) or OpenAI API (if OPENAI_API_KEY is set)
    to generate a live LLM threat intelligence assessment, with automatic fallback to
    the deterministic PhishGuard Hybrid Expert AI Engine.
    """
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()

    telemetry_summary = {
        "domain": lexical.domain,
        "registered_domain": lexical.registered_domain,
        "overall_risk_score": overall_score,
        "risk_level": risk_level,
        "ml_phishing_probability": ml_res.phishing_probability,
        "lexical_signals": lexical.signals,
        "brand_signals": brand.signals,
        "network_signals": network.signals,
        "detected_brands": [m.model_dump() for m in brand.detected_brands],
        "domain_age_days": network.whois.domain_age_days,
    }

    prompt = (
        "You are a Senior SOC Threat Intelligence Analyst. Analyze the following domain telemetry JSON "
        "and return ONLY a valid JSON object with these exact keys:\n"
        '"executive_summary" (string, 2-3 sentences),\n'
        '"threat_category" (string),\n'
        '"attack_vector_analysis" (string, 2-3 sentences),\n'
        '"key_risk_indicators" (array of strings),\n'
        '"trust_indicators" (array of strings),\n'
        '"recommended_actions" (array of strings, 3-4 actionable items).\n\n'
        f"Telemetry:\n{json.dumps(telemetry_summary)}"
    )

    if gemini_key:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={gemini_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json", "temperature": 0.2},
            }
            with httpx.Client(timeout=6.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                    parsed = json.loads(raw_text)
                    return AIReasoningReport(
                        engine_used="Google Gemini AI Threat Analyst",
                        executive_summary=parsed.get("executive_summary", ""),
                        threat_category=parsed.get("threat_category", "Phishing Threat Analysis"),
                        attack_vector_analysis=parsed.get("attack_vector_analysis", ""),
                        key_risk_indicators=parsed.get("key_risk_indicators", []),
                        trust_indicators=parsed.get("trust_indicators", []),
                        recommended_actions=parsed.get("recommended_actions", []),
                    )
        except Exception:
            pass

    if openai_key:
        try:
            url = "https://api.openai.com/v1/chat/completions"
            headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
            payload = {
                "model": "gpt-4o-mini",
                "response_format": {"type": "json_object"},
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            }
            with httpx.Client(timeout=6.0) as client:
                resp = client.post(url, headers=headers, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    parsed = json.loads(data["choices"][0]["message"]["content"])
                    return AIReasoningReport(
                        engine_used="OpenAI GPT Threat Analyst",
                        executive_summary=parsed.get("executive_summary", ""),
                        threat_category=parsed.get("threat_category", "Phishing Threat Analysis"),
                        attack_vector_analysis=parsed.get("attack_vector_analysis", ""),
                        key_risk_indicators=parsed.get("key_risk_indicators", []),
                        trust_indicators=parsed.get("trust_indicators", []),
                        recommended_actions=parsed.get("recommended_actions", []),
                    )
        except Exception:
            pass

    return _generate_expert_fallback_report(overall_score, risk_level, lexical, brand, network, ml_res)
