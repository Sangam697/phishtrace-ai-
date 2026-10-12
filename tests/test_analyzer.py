from fastapi.testclient import TestClient
from app.main import app, run_domain_analysis
from app.analyzers.lexical_analyzer import analyze_lexical
from app.analyzers.brand_analyzer import analyze_brand_impersonation

client = TestClient(app)


def test_official_brand_domain_is_safe():
    res = run_domain_analysis("https://github.com/login", deep_network_scan=False, persist=False)
    assert res.brand.is_official_brand_domain is True
    assert res.overall_risk_score < 20
    assert res.verdict == "LIKELY SAFE"


def test_homoglyph_phishing_domain_detected():
    res = run_domain_analysis("paypa1-secure-login.xyz", deep_network_scan=False, persist=False)
    assert res.brand.is_official_brand_domain is False
    assert len(res.brand.detected_brands) >= 1
    assert res.brand.detected_brands[0].brand == "Paypal"
    assert res.lexical.is_high_risk_tld is True
    assert "login" in res.lexical.suspicious_keywords
    assert res.overall_risk_score >= 75
    assert res.verdict == "PHISHING / MALICIOUS"


def test_idn_punycode_homograph_detected():
    res = run_domain_analysis("xn--pple-43d.com", deep_network_scan=False, persist=False)
    assert res.brand.is_punycode_idn is True
    assert len(res.brand.homoglyphs_detected) > 0
    assert res.overall_risk_score >= 70


def test_combosquatting_detected():
    lex = analyze_lexical("microsoft-office365-account-verify.top")
    brand = analyze_brand_impersonation(lex.domain, lex.registered_domain, lex.tld)
    assert any(m.brand == "Microsoft" for m in brand.detected_brands)
    assert brand.brand_risk_score >= 55


def test_api_endpoints():
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "healthy"

    scan = client.post(
        "/api/analyze",
        json={"target": "arnazon-prime-billing-alert.icu", "deep_network_scan": False},
    )
    assert scan.status_code == 200
    payload = scan.json()
    assert payload["overall_risk_score"] >= 70
    assert payload["verdict"] == "PHISHING / MALICIOUS"

    hist = client.get("/api/history")
    assert hist.status_code == 200
    assert hist.json()["stats"]["total_scans"] >= 1
