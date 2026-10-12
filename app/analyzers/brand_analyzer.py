from typing import Dict, List, Set, Tuple
from app.models import BrandAnalysisResult, BrandMatch

# Map of protected high-target brands to their official root domains
PROTECTED_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "azure.com", "windows.com"},
    "apple": {"apple.com", "icloud.com", "me.com", "mzstatic.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleapis.com", "gstatic.com", "google.co.in", "google.co.uk"},
    "amazon": {"amazon.com", "amazonaws.com", "amazon.in", "amazon.co.uk", "amazon.de", "a2z.com", "primevideo.com"},
    "netflix": {"netflix.com", "nflxext.com", "nflximg.net"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "messenger.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "github": {"github.com", "github.io", "githubusercontent.com"},
    "chase": {"chase.com", "jpmorganchase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"},
    "citibank": {"citi.com", "citibank.com"},
    "binance": {"binance.com", "bnbchain.org"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "stripe": {"stripe.com"},
    "cloudflare": {"cloudflare.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"},
    "adobe": {"adobe.com", "adobelogin.com"},
    "openai": {"openai.com", "chatgpt.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamgames.com"},
    "discord": {"discord.com", "discordapp.com", "discord.gg"},
    "telegram": {"telegram.org", "t.me"},
    "yahoo": {"yahoo.com", "ymail.com"},
    "ebay": {"ebay.com", "ebay.co.uk"},
}

ALL_OFFICIAL_DOMAINS: Dict[str, str] = {}
for brand_name, domains in PROTECTED_BRANDS.items():
    for d in domains:
        ALL_OFFICIAL_DOMAINS[d] = brand_name

# Visual ASCII leetspeak / multigraph substitutions used by attackers
LEET_MULTIGRAPHS = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]

LEET_CHAR_MAP = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
})

# Common Unicode Cyrillic/Greek confusable characters
UNICODE_CONFUSABLES: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ӏ": "l",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "α": "a",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes exact Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def normalize_leetspeak(token: str, one_as_i: bool = False) -> str:
    """Normalizes visual ASCII substitutions (e.g. 'paypa1' -> 'paypal', 'arnazon' -> 'amazon')."""
    res = token.lower()
    for src, dst in LEET_MULTIGRAPHS:
        res = res.replace(src, dst)
    if one_as_i:
        table = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
        return res.translate(table)
    return res.translate(LEET_CHAR_MAP)


def decode_idn_and_homoglyphs(hostname: str) -> Tuple[bool, str, List[str]]:
    """Checks for xn-- punycode or non-ASCII Unicode confusable homoglyphs."""
    is_punycode = "xn--" in hostname.lower()
    decoded = hostname
    if is_punycode:
        try:
            decoded = hostname.encode("ascii").decode("idna")
        except Exception:
            decoded = hostname

    homoglyphs_found: List[str] = []
    normalized_chars = []
    for ch in decoded:
        if ch in UNICODE_CONFUSABLES:
            latin_equiv = UNICODE_CONFUSABLES[ch]
            homoglyphs_found.append(f"'{ch}' (U+{ord(ch):04X}) -> '{latin_equiv}'")
            normalized_chars.append(latin_equiv)
        elif ord(ch) > 127:
            homoglyphs_found.append(f"'{ch}' (U+{ord(ch):04X})")
            normalized_chars.append(ch)
        else:
            normalized_chars.append(ch)

    return is_punycode, "".join(normalized_chars), homoglyphs_found


def analyze_brand_impersonation(hostname: str, registered_domain: str, tld: str) -> BrandAnalysisResult:
    # 1. Check if this is an official verified domain
    if registered_domain in ALL_OFFICIAL_DOMAINS:
        official_brand = ALL_OFFICIAL_DOMAINS[registered_domain]
        return BrandAnalysisResult(
            is_official_brand_domain=True,
            is_punycode_idn=False,
            decoded_idn=None,
            homoglyphs_detected=[],
            detected_brands=[
                BrandMatch(
                    brand=official_brand.capitalize(),
                    similarity_score=1.0,
                    technique="Official Verified Domain",
                    details=f"'{registered_domain}' is an official domain owned by {official_brand.capitalize()}.",
                )
            ],
            brand_risk_score=0,
            signals=[f"Verified official domain for {official_brand.capitalize()} ({registered_domain})."],
        )

    is_punycode, unicode_normalized_host, homoglyphs = decode_idn_and_homoglyphs(hostname)

    # Extract domain tokens (excluding TLD)
    host_without_tld = (
        unicode_normalized_host[:-len(tld) - 1]
        if tld and unicode_normalized_host.endswith("." + tld)
        else unicode_normalized_host
    )
    tokens = [t for t in host_without_tld.replace(".", "-").split("-") if len(t) >= 3]
    collapsed_label = host_without_tld.replace("-", "").replace(".", "")

    detected_matches: List[BrandMatch] = []
    seen_brands: Set[str] = set()

    for brand in PROTECTED_BRANDS.keys():
        # A. Check exact brand inclusion in non-official domain (Combo-squatting / Subdomain spoofing)
        if brand in host_without_tld and brand not in seen_brands:
            seen_brands.add(brand)
            technique = "Subdomain Spoofing" if brand in host_without_tld.split(".")[:-1] else "Combo-squatting"
            detected_matches.append(
                BrandMatch(
                    brand=brand.capitalize(),
                    similarity_score=0.95,
                    technique=technique,
                    details=f"Embeds protected brand name '{brand}' inside unauthorized domain '{registered_domain}'.",
                )
            )
            continue

        # B. Check each token and collapsed label for visual homoglyphs / leetspeak & typosquatting
        candidates = tokens + ([collapsed_label] if len(collapsed_label) <= len(brand) + 3 else [])
        for token in candidates:
            if brand in seen_brands:
                break

            # Leetspeak / Visual substitution check (e.g., paypa1, micr0soft, arnazon, g00gle)
            deleet_l = normalize_leetspeak(token, one_as_i=False)
            deleet_i = normalize_leetspeak(token, one_as_i=True)
            if (deleet_l == brand or deleet_i == brand or brand in deleet_l or brand in deleet_i) and token != brand:
                seen_brands.add(brand)
                detected_matches.append(
                    BrandMatch(
                        brand=brand.capitalize(),
                        similarity_score=0.94,
                        technique="Homoglyph / Visual Substitution",
                        details=f"Token '{token}' visually mimics '{brand}' via character substitution.",
                    )
                )
                break

            # Typosquatting via Levenshtein distance on similar-length tokens
            if len(brand) >= 5 and abs(len(token) - len(brand)) <= 2:
                dist = levenshtein_distance(token, brand)
                max_allowed_dist = 1 if len(brand) <= 6 else 2
                if 1 <= dist <= max_allowed_dist:
                    sim = round(1.0 - (dist / max(len(token), len(brand))), 2)
                    seen_brands.add(brand)
                    detected_matches.append(
                        BrandMatch(
                            brand=brand.capitalize(),
                            similarity_score=sim,
                            technique="Typosquatting",
                            details=f"Token '{token}' has edit distance {dist} from '{brand}' ({int(sim*100)}% similarity).",
                        )
                    )
                    break

    # Compute brand risk score & signals
    score = 0
    signals: List[str] = []

    if is_punycode or homoglyphs:
        score += 45
        signals.append(
            f"IDN Punycode / Unicode Homograph attack detected ({', '.join(homoglyphs[:3]) or 'xn-- encoding'}) (+45 risk)"
        )

    for match in detected_matches:
        if match.technique in ("Homoglyph / Visual Substitution", "Subdomain Spoofing"):
            score += 65
            signals.append(f"{match.technique} targeting {match.brand}: {match.details} (+65 risk)")
        elif match.technique == "Combo-squatting":
            score += 55
            signals.append(f"Combo-squatting targeting {match.brand}: {match.details} (+55 risk)")
        elif match.technique == "Typosquatting":
            score += 60
            signals.append(f"Typosquatting targeting {match.brand}: {match.details} (+60 risk)")

    if not signals:
        signals.append("No brand impersonation, typosquatting, or IDN homograph patterns detected.")

    return BrandAnalysisResult(
        is_official_brand_domain=False,
        is_punycode_idn=is_punycode,
        decoded_idn=unicode_normalized_host if is_punycode else None,
        homoglyphs_detected=homoglyphs,
        detected_brands=detected_matches,
        brand_risk_score=min(100, score),
        signals=signals,
    )
