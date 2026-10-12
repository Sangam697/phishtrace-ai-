import math
import re
from urllib.parse import urlparse
from typing import Tuple, List
from app.models import LexicalAnalysisResult

HIGH_RISK_TLDS = {
    "xyz", "top", "click", "loan", "work", "gq", "tk", "ml", "cf", "ga",
    "zip", "mov", "icu", "buzz", "rest", "fit", "sbs", "cfd", "cam", "cyou",
    "monster", "quest", "beauty", "hair", "skin", "makeup", "boats", "live",
    "online", "site", "shop", "fun", "pw", "cc", "ws", "su", "bid", "win",
}

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.jp", "ne.jp",
    "com.br", "com.mx", "co.za", "co.nz", "com.sg", "com.hk", "com.cn",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "secure", "security", "account", "update", "wallet", "auth",
    "authenticate", "banking", "confirm", "billing", "support", "helpdesk",
    "unlock", "recover", "recovery", "validation", "validate", "webscr",
    "sso", "mfa", "2fa", "token", "credential", "suspend", "suspended",
    "alert", "urgent", "invoice", "payment", "refund", "kyc", "airdrop",
    "claim", "bonus", "gift", "portal", "service", "session", "oauth",
]

IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def parse_target_url(raw_target: str) -> Tuple[str, str, bool, bool]:
    """
    Normalizes a user-supplied domain or URL and extracts:
    (hostname, path_and_query, has_at_symbol, has_double_slash_redirect)
    """
    cleaned = raw_target.strip()
    has_at = "@" in cleaned

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        parsed_url = urlparse("http://" + cleaned)
    else:
        parsed_url = urlparse(cleaned)

    # Check if there is a '//' redirect inside the path/query portion
    path_part = (parsed_url.path or "") + (f"?{parsed_url.query}" if parsed_url.query else "")
    has_double_slash = "//" in path_part or "http:" in path_part.lower() or "https:" in path_part.lower()

    hostname = (parsed_url.hostname or cleaned.split("/")[0]).lower().strip(".")
    return hostname, path_part or "/", has_at, has_double_slash


def split_domain_parts(hostname: str) -> Tuple[str, str, str]:
    """
    Splits hostname into (subdomain, registered_domain, tld).
    """
    if IPV4_PATTERN.match(hostname):
        return "", hostname, ""

    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 1:
        return "", hostname, ""

    last_two = f"{parts[-2]}.{parts[-1]}"
    if len(parts) >= 3 and last_two in MULTI_PART_TLDS:
        tld = last_two
        reg_domain = f"{parts[-3]}.{tld}"
        subdomain = ".".join(parts[:-3])
    else:
        tld = parts[-1]
        reg_domain = f"{parts[-2]}.{tld}"
        subdomain = ".".join(parts[:-2])

    return subdomain, reg_domain, tld


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 3)


def analyze_lexical(raw_target: str) -> LexicalAnalysisResult:
    hostname, url_path, has_at, has_double_slash = parse_target_url(raw_target)
    subdomain, reg_domain, tld = split_domain_parts(hostname)

    has_ip = bool(IPV4_PATTERN.match(hostname))
    # Domain core without TLD for entropy & vowel/digit ratios
    domain_without_tld = hostname[:-len(tld) - 1] if tld and hostname.endswith("." + tld) else hostname
    alnum_chars = [c for c in domain_without_tld if c.isalnum()]
    vowels = sum(1 for c in alnum_chars if c in "aeiou")
    digits = sum(1 for c in domain_without_tld if c.isdigit())
    hyphens = domain_without_tld.count("-")

    domain_len = len(hostname)
    subdomain_count = len([s for s in subdomain.split(".") if s]) if subdomain else 0
    digit_ratio = round(digits / max(len(domain_without_tld), 1), 3)
    vowel_ratio = round(vowels / max(len(alnum_chars), 1), 3)
    entropy = calculate_shannon_entropy(domain_without_tld)
    is_high_risk_tld = tld in HIGH_RISK_TLDS

    full_search_text = f"{hostname}{url_path}".lower()
    matched_keywords: List[str] = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full_search_text and kw not in matched_keywords:
            matched_keywords.append(kw)

    # Calculate heuristic lexical risk score & signals
    score = 0
    signals: List[str] = []

    if has_ip:
        score += 45
        signals.append("Uses raw IP address instead of a domain name (+45 risk)")

    if is_high_risk_tld:
        score += 22
        signals.append(f"Registered under frequently abused TLD '.{tld}' (+22 risk)")

    if hyphens >= 3:
        score += 25
        signals.append(f"Excessive hyphenation ({hyphens} hyphens in hostname) typical of deceptive URLs (+25 risk)")
    elif hyphens == 2:
        score += 15
        signals.append("Multiple hyphens (2) in domain name (+15 risk)")
    elif hyphens == 1:
        score += 6
        signals.append("Contains hyphenated domain token (+6 risk)")

    if subdomain_count >= 3:
        score += 24
        signals.append(f"Deep subdomain nesting ({subdomain_count} subdomain levels) used to mask true root domain (+24 risk)")
    elif subdomain_count == 2:
        score += 12
        signals.append("Multi-level subdomain structure (2 levels) (+12 risk)")

    if domain_len > 35:
        score += 20
        signals.append(f"Unusually long hostname ({domain_len} characters) (+20 risk)")
    elif domain_len > 24:
        score += 10
        signals.append(f"Elevated hostname length ({domain_len} characters) (+10 risk)")

    if entropy >= 3.85:
        score += 20
        signals.append(f"High character entropy ({entropy} bits) suggesting DGA or randomized phishing subdomain (+20 risk)")
    elif entropy >= 3.5:
        score += 10
        signals.append(f"Moderately high character entropy ({entropy} bits) (+10 risk)")

    if digits >= 4 or digit_ratio >= 0.25:
        score += 15
        signals.append(f"High numeric density ({digits} digits, {int(digit_ratio*100)}% of label) (+15 risk)")
    elif digits >= 1:
        score += 6
        signals.append(f"Contains numeric characters ({digits}) in domain label (+6 risk)")

    if matched_keywords:
        kw_score = min(35, len(matched_keywords) * 12)
        score += kw_score
        signals.append(
            f"Contains {len(matched_keywords)} sensitive lure keyword(s): {', '.join(matched_keywords[:5])} (+{kw_score} risk)"
        )

    if has_at:
        score += 30
        signals.append("Contains '@' symbol in URL (credential/host obfuscation trick) (+30 risk)")

    if has_double_slash:
        score += 20
        signals.append("Contains embedded redirect path ('//' or nested URL in path) (+20 risk)")

    if not signals:
        signals.append("Clean lexical profile: normal length, low entropy, no deceptive keywords or excessive hyphens.")

    lexical_risk_score = min(100, max(0, score))

    return LexicalAnalysisResult(
        domain=hostname,
        registered_domain=reg_domain,
        subdomain=subdomain,
        tld=tld,
        url_path=url_path,
        domain_length=domain_len,
        subdomain_count=subdomain_count,
        hyphen_count=hyphens,
        digit_count=digits,
        digit_ratio=digit_ratio,
        vowel_ratio=vowel_ratio,
        shannon_entropy=entropy,
        is_high_risk_tld=is_high_risk_tld,
        has_ip_address=has_ip,
        has_at_symbol=has_at,
        has_double_slash_redirect=has_double_slash,
        suspicious_keywords=matched_keywords,
        lexical_risk_score=lexical_risk_score,
        signals=signals,
    )
