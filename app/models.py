from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    target: str = Field(
        ...,
        description="Domain name or full URL to analyze (e.g., 'paypa1-secure-login.xyz' or 'https://apple-id-verify.com/login')",
        examples=["paypa1-secure-login.xyz"],
    )
    deep_network_scan: bool = Field(
        default=True,
        description="Whether to perform live DNS, SSL/TLS, and WHOIS lookups",
    )


class BulkAnalyzeRequest(BaseModel):
    targets: List[str] = Field(
        ...,
        description="List of domains or URLs to scan in batch",
        max_length=50,
    )
    deep_network_scan: bool = Field(default=False)


class LexicalAnalysisResult(BaseModel):
    domain: str
    registered_domain: str
    subdomain: str
    tld: str
    url_path: str
    domain_length: int
    subdomain_count: int
    hyphen_count: int
    digit_count: int
    digit_ratio: float
    vowel_ratio: float
    shannon_entropy: float
    is_high_risk_tld: bool
    has_ip_address: bool
    has_at_symbol: bool
    has_double_slash_redirect: bool
    suspicious_keywords: List[str]
    lexical_risk_score: int = Field(..., ge=0, le=100)
    signals: List[str]


class BrandMatch(BaseModel):
    brand: str
    similarity_score: float
    technique: str  # e.g., "Typosquatting", "Combo-squatting", "Homoglyph / Punycode", "Exact Match (Official)"
    details: str


class BrandAnalysisResult(BaseModel):
    is_official_brand_domain: bool
    is_punycode_idn: bool
    decoded_idn: Optional[str] = None
    homoglyphs_detected: List[str] = []
    detected_brands: List[BrandMatch] = []
    brand_risk_score: int = Field(..., ge=0, le=100)
    signals: List[str]


class DNSInfo(BaseModel):
    resolved: bool
    ip_addresses: List[str] = []
    mx_records: List[str] = []
    ns_records: List[str] = []
    txt_records: List[str] = []
    has_spf: bool = False
    has_dmarc: bool = False


class SSLInfo(BaseModel):
    has_ssl: bool
    issuer: Optional[str] = None
    subject_cn: Optional[str] = None
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_remaining: Optional[int] = None
    cert_age_days: Optional[int] = None
    is_free_Automated_ca: bool = False
    protocol_version: Optional[str] = None
    error: Optional[str] = None


class WhoisInfo(BaseModel):
    available: bool
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrant_country: Optional[str] = None
    is_newly_registered: bool = False
    error: Optional[str] = None


class NetworkAnalysisResult(BaseModel):
    scanned: bool
    dns: DNSInfo
    ssl: SSLInfo
    whois: WhoisInfo
    network_risk_score: int = Field(..., ge=0, le=100)
    signals: List[str]


class FeatureContribution(BaseModel):
    feature_name: str
    value: Any
    impact: str  # "High Risk", "Moderate Risk", "Neutral", "Trust Signal"
    weight_score: float


class MLAnalysisResult(BaseModel):
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    ml_risk_score: int = Field(..., ge=0, le=100)
    model_name: str
    confidence: float
    top_features: List[FeatureContribution]


class AIReasoningReport(BaseModel):
    engine_used: str  # e.g., "Gemini AI Analyst", "OpenAI Threat Analyst", or "PhishGuard Hybrid Expert AI Engine"
    executive_summary: str
    threat_category: str
    attack_vector_analysis: str
    key_risk_indicators: List[str]
    trust_indicators: List[str]
    recommended_actions: List[str]


class DomainAnalysisResponse(BaseModel):
    scan_id: Optional[int] = None
    timestamp: str
    input_target: str
    normalized_domain: str
    overall_risk_score: int = Field(..., ge=0, le=100)
    risk_level: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"
    verdict: str     # "PHISHING / MALICIOUS", "SUSPICIOUS", "LIKELY SAFE"
    lexical: LexicalAnalysisResult
    brand: BrandAnalysisResult
    network: NetworkAnalysisResult
    ml_prediction: MLAnalysisResult
    ai_report: AIReasoningReport
    scan_duration_ms: int
