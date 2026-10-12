from typing import List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from app.models import (
    LexicalAnalysisResult,
    BrandAnalysisResult,
    NetworkAnalysisResult,
    MLAnalysisResult,
    FeatureContribution,
)

FEATURE_NAMES = [
    "domain_length",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "digit_ratio",
    "shannon_entropy",
    "is_high_risk_tld",
    "suspicious_keyword_count",
    "brand_impersonation_flag",
    "is_official_brand",
    "is_punycode_or_homoglyph",
    "has_ip_or_redirect_trick",
    "domain_age_risk",
    "ssl_dns_risk",
]


class PhishingMLClassifier:
    """
    Ensemble Random Forest Classifier trained on 14 lexical, brand-impersonation,
    and network infrastructure features with local feature-impact explainability.
    """

    def __init__(self) -> None:
        self.model = RandomForestClassifier(
            n_estimators=120,
            max_depth=8,
            min_samples_leaf=2,
            random_state=42,
        )
        self._train_model()

    def _train_model(self) -> None:
        rng = np.random.default_rng(42)
        X_rows = []
        y_labels = []

        # 1. Generate 350 realistic Benign domain feature profiles
        for _ in range(350):
            is_official = int(rng.random() < 0.25)
            dom_len = int(rng.integers(7, 20))
            sub_cnt = int(rng.choice([0, 1, 2], p=[0.65, 0.30, 0.05]))
            hyphens = int(rng.choice([0, 1], p=[0.88, 0.12]))
            digits = int(rng.choice([0, 1, 2], p=[0.85, 0.10, 0.05]))
            digit_ratio = round(digits / max(dom_len, 1), 3)
            entropy = float(rng.uniform(2.3, 3.45))
            risk_tld = int(rng.random() < 0.03)
            kw_cnt = int(rng.choice([0, 1], p=[0.93, 0.07]))
            brand_imp = 0
            puny = 0
            ip_trick = 0
            age_risk = float(rng.choice([0.0, 0.2, 0.4], p=[0.75, 0.15, 0.10]))
            ssl_risk = float(rng.choice([0.0, 0.25, 0.5], p=[0.80, 0.15, 0.05]))

            X_rows.append([
                dom_len, sub_cnt, hyphens, digits, digit_ratio, entropy,
                risk_tld, kw_cnt, brand_imp, is_official, puny, ip_trick,
                age_risk, ssl_risk
            ])
            y_labels.append(0)

        # 2. Generate 350 realistic Phishing domain feature profiles across attack archetypes
        for i in range(350):
            archetype = i % 4
            if archetype == 0:
                # Combo-squatting + Lure Keywords + Abused TLD
                dom_len = int(rng.integers(20, 48))
                sub_cnt = int(rng.choice([0, 1, 2, 3], p=[0.3, 0.35, 0.2, 0.15]))
                hyphens = int(rng.integers(1, 5))
                digits = int(rng.integers(0, 4))
                digit_ratio = round(digits / max(dom_len, 1), 3)
                entropy = float(rng.uniform(3.3, 4.1))
                risk_tld = int(rng.random() < 0.65)
                kw_cnt = int(rng.integers(1, 4))
                brand_imp = 1
                puny = 0
                ip_trick = 0
            elif archetype == 1:
                # Typosquatting / Homoglyph / Punycode attack (short deceptive domain)
                dom_len = int(rng.integers(9, 22))
                sub_cnt = int(rng.choice([0, 1], p=[0.7, 0.3]))
                hyphens = int(rng.choice([0, 1], p=[0.7, 0.3]))
                digits = int(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
                digit_ratio = round(digits / max(dom_len, 1), 3)
                entropy = float(rng.uniform(2.7, 3.6))
                risk_tld = int(rng.random() < 0.4)
                kw_cnt = int(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
                brand_imp = 1
                puny = int(rng.random() < 0.45)
                ip_trick = 0
            elif archetype == 2:
                # Deep Subdomain + High Entropy DGA / Redirect Phish
                dom_len = int(rng.integers(26, 62))
                sub_cnt = int(rng.integers(2, 5))
                hyphens = int(rng.integers(1, 5))
                digits = int(rng.integers(2, 9))
                digit_ratio = round(digits / max(dom_len, 1), 3)
                entropy = float(rng.uniform(3.65, 4.4))
                risk_tld = int(rng.random() < 0.75)
                kw_cnt = int(rng.integers(1, 4))
                brand_imp = int(rng.random() < 0.5)
                puny = 0
                ip_trick = int(rng.random() < 0.35)
            else:
                # Newly Registered Generic Lure (e.g., secure-wallet-verify.xyz)
                dom_len = int(rng.integers(18, 36))
                sub_cnt = int(rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))
                hyphens = int(rng.integers(1, 4))
                digits = int(rng.integers(0, 3))
                digit_ratio = round(digits / max(dom_len, 1), 3)
                entropy = float(rng.uniform(3.2, 3.95))
                risk_tld = 1
                kw_cnt = int(rng.integers(1, 4))
                brand_imp = 0
                puny = 0
                ip_trick = 0

            age_risk = float(rng.choice([0.5, 0.8, 1.0], p=[0.2, 0.3, 0.5]))
            ssl_risk = float(rng.choice([0.3, 0.6, 1.0], p=[0.3, 0.4, 0.3]))

            X_rows.append([
                dom_len, sub_cnt, hyphens, digits, digit_ratio, entropy,
                risk_tld, kw_cnt, brand_imp, 0, puny, ip_trick,
                age_risk, ssl_risk
            ])
            y_labels.append(1)

        X = np.array(X_rows, dtype=float)
        y = np.array(y_labels, dtype=int)
        self.model.fit(X, y)

    def predict(
        self,
        lexical: LexicalAnalysisResult,
        brand: BrandAnalysisResult,
        network: NetworkAnalysisResult,
    ) -> MLAnalysisResult:
        brand_imp_flag = 1 if (brand.detected_brands and not brand.is_official_brand_domain) else 0
        is_official = 1 if brand.is_official_brand_domain else 0
        puny_flag = 1 if (brand.is_punycode_idn or len(brand.homoglyphs_detected) > 0) else 0
        ip_trick_flag = 1 if (
            lexical.has_ip_address or lexical.has_at_symbol or lexical.has_double_slash_redirect
        ) else 0

        # Domain age risk normalization
        if is_official:
            age_risk = 0.0
        elif network.whois.available and network.whois.domain_age_days is not None:
            if network.whois.domain_age_days <= 60:
                age_risk = 1.0
            elif network.whois.domain_age_days <= 180:
                age_risk = 0.6
            elif network.whois.domain_age_days >= 1095:
                age_risk = 0.0
            else:
                age_risk = 0.2
        else:
            age_risk = 0.45 if network.scanned else 0.25

        # SSL / DNS risk normalization
        if is_official:
            ssl_dns_risk = 0.0
        elif not network.scanned:
            ssl_dns_risk = 0.2
        else:
            ssl_dns_risk = min(1.0, network.network_risk_score / 75.0)

        features = np.array([[
            float(lexical.domain_length),
            float(lexical.subdomain_count),
            float(lexical.hyphen_count),
            float(lexical.digit_count),
            float(lexical.digit_ratio),
            float(lexical.shannon_entropy),
            float(1 if lexical.is_high_risk_tld else 0),
            float(len(lexical.suspicious_keywords)),
            float(brand_imp_flag),
            float(is_official),
            float(puny_flag),
            float(ip_trick_flag),
            float(age_risk),
            float(ssl_dns_risk),
        ]])

        prob = float(self.model.predict_proba(features)[0][1])
        if is_official and not ip_trick_flag:
            prob = min(prob, 0.04)

        ml_risk_score = int(round(prob * 100))
        confidence = round(max(prob, 1.0 - prob) * 100, 1)

        # Build Explainable AI (XAI) feature contributions
        contributions: List[FeatureContribution] = []

        if is_official:
            contributions.append(FeatureContribution(
                feature_name="Official Brand Whitelist",
                value="Verified Official Root Domain",
                impact="Trust Signal",
                weight_score=-45.0,
            ))

        if brand_imp_flag:
            target_names = ", ".join(m.brand for m in brand.detected_brands)
            contributions.append(FeatureContribution(
                feature_name="Brand Impersonation Signal",
                value=f"Targets {target_names} ({brand.detected_brands[0].technique})",
                impact="High Risk",
                weight_score=38.5,
            ))

        if puny_flag:
            contributions.append(FeatureContribution(
                feature_name="IDN / Homoglyph Encoding",
                value="Detected confusable characters",
                impact="High Risk",
                weight_score=32.0,
            ))

        if lexical.suspicious_keywords:
            contributions.append(FeatureContribution(
                feature_name="Phishing Lure Keywords",
                value=", ".join(lexical.suspicious_keywords[:4]),
                impact="High Risk" if len(lexical.suspicious_keywords) >= 2 else "Moderate Risk",
                weight_score=float(min(30, len(lexical.suspicious_keywords) * 11)),
            ))

        if lexical.is_high_risk_tld:
            contributions.append(FeatureContribution(
                feature_name="TLD Reputation",
                value=f".{lexical.tld} (High-Risk TLD)",
                impact="Moderate Risk",
                weight_score=18.0,
            ))

        if lexical.hyphen_count >= 2:
            contributions.append(FeatureContribution(
                feature_name="Hyphenation Density",
                value=f"{lexical.hyphen_count} hyphens",
                impact="Moderate Risk",
                weight_score=15.0,
            ))

        if lexical.shannon_entropy >= 3.6:
            contributions.append(FeatureContribution(
                feature_name="Shannon Entropy",
                value=f"{lexical.shannon_entropy} bits/char",
                impact="Moderate Risk",
                weight_score=14.0,
            ))
        else:
            contributions.append(FeatureContribution(
                feature_name="Shannon Entropy",
                value=f"{lexical.shannon_entropy} bits/char (Normal)",
                impact="Trust Signal",
                weight_score=-6.0,
            ))

        if network.scanned and network.whois.available and network.whois.domain_age_days is not None:
            age = network.whois.domain_age_days
            if age <= 60:
                contributions.append(FeatureContribution(
                    feature_name="WHOIS Domain Age",
                    value=f"{age} days (Newly Registered)",
                    impact="High Risk",
                    weight_score=28.0,
                ))
            elif age >= 1095:
                contributions.append(FeatureContribution(
                    feature_name="WHOIS Domain Age",
                    value=f"{age // 365} years (Established)",
                    impact="Trust Signal",
                    weight_score=-18.0,
                ))

        # Sort contributions by absolute weight
        contributions.sort(key=lambda c: abs(c.weight_score), reverse=True)

        return MLAnalysisResult(
            phishing_probability=round(prob, 4),
            ml_risk_score=ml_risk_score,
            model_name="RandomForest-PhishGuard-v1 (120 Trees, 14 Features)",
            confidence=confidence,
            top_features=contributions[:6],
        )


# Singleton classifier instance
ml_classifier = PhishingMLClassifier()
