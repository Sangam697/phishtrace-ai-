import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import List, Optional
from app.models import DNSInfo, SSLInfo, WhoisInfo, NetworkAnalysisResult

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "2.5"))
SSL_TIMEOUT = float(os.getenv("SSL_TIMEOUT", "3.0"))
WHOIS_TIMEOUT = float(os.getenv("WHOIS_TIMEOUT", "3.5"))

FREE_AUTOMATED_CAS = ["let's encrypt", "letsencrypt", "zerossl", "buypass", "google trust services", "cpanel"]


def inspect_dns(hostname: str, registered_domain: str) -> DNSInfo:
    ip_addresses: List[str] = []
    mx_records: List[str] = []
    ns_records: List[str] = []
    txt_records: List[str] = []
    has_spf = False
    has_dmarc = False

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        # A records
        try:
            answers = resolver.resolve(hostname, "A")
            ip_addresses = [r.to_text() for r in answers]
        except Exception:
            pass

        # MX records on registered domain
        try:
            answers = resolver.resolve(registered_domain, "MX")
            mx_records = [str(r.exchange).rstrip(".") for r in answers]
        except Exception:
            pass

        # NS records on registered domain
        try:
            answers = resolver.resolve(registered_domain, "NS")
            ns_records = [r.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        # TXT / SPF records
        try:
            answers = resolver.resolve(registered_domain, "TXT")
            for r in answers:
                txt_val = r.to_text().strip('"')
                txt_records.append(txt_val[:120])
                if "v=spf1" in txt_val.lower():
                    has_spf = True
        except Exception:
            pass

        # DMARC check
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{registered_domain}", "TXT")
            for r in dmarc_answers:
                if "v=dmarc1" in r.to_text().lower():
                    has_dmarc = True
        except Exception:
            pass
    else:
        try:
            _, _, ip_list = socket.gethostbyname_ex(hostname)
            ip_addresses = list(set(ip_list))
        except Exception:
            pass

    return DNSInfo(
        resolved=len(ip_addresses) > 0,
        ip_addresses=ip_addresses[:6],
        mx_records=mx_records[:5],
        ns_records=ns_records[:5],
        txt_records=txt_records[:5],
        has_spf=has_spf,
        has_dmarc=has_dmarc,
    )


def inspect_ssl(hostname: str) -> SSLInfo:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"
                subject_cn = subject_dict.get("commonName") or hostname

                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                now = datetime.now(timezone.utc)

                valid_from_iso = None
                valid_until_iso = None
                days_remaining = None
                cert_age_days = None

                if not_before_str:
                    dt_from = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    valid_from_iso = dt_from.strftime("%Y-%m-%d")
                    cert_age_days = max(0, (now - dt_from).days)

                if not_after_str:
                    dt_until = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    valid_until_iso = dt_until.strftime("%Y-%m-%d")
                    days_remaining = (dt_until - now).days

                is_free_ca = any(ca in issuer_org.lower() for ca in FREE_AUTOMATED_CAS)

                return SSLInfo(
                    has_ssl=True,
                    issuer=issuer_org,
                    subject_cn=subject_cn,
                    valid_from=valid_from_iso,
                    valid_until=valid_until_iso,
                    days_remaining=days_remaining,
                    cert_age_days=cert_age_days,
                    is_free_Automated_ca=is_free_ca,
                    protocol_version=protocol,
                )
    except Exception as exc:
        return SSLInfo(has_ssl=False, error=str(exc)[:120])


def _normalize_whois_date(dt_val) -> Optional[datetime]:
    if isinstance(dt_val, list) and dt_val:
        dt_val = dt_val[0]
    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            return dt_val.replace(tzinfo=timezone.utc)
        return dt_val.astimezone(timezone.utc)
    return None


def inspect_whois(registered_domain: str) -> WhoisInfo:
    if not HAS_WHOIS or not registered_domain or "." not in registered_domain:
        return WhoisInfo(available=False, error="WHOIS lookup unavailable")

    try:
        w = whois.whois(registered_domain)
        creation_dt = _normalize_whois_date(getattr(w, "creation_date", None))
        expiration_dt = _normalize_whois_date(getattr(w, "expiration_date", None))
        registrar = getattr(w, "registrar", None)
        if isinstance(registrar, list) and registrar:
            registrar = registrar[0]
        country = getattr(w, "country", None)
        if isinstance(country, list) and country:
            country = country[0]

        if not creation_dt and not registrar:
            return WhoisInfo(available=False, error="No public WHOIS record returned")

        now = datetime.now(timezone.utc)
        age_days = max(0, (now - creation_dt).days) if creation_dt else None
        is_nrd = age_days is not None and age_days <= 60

        return WhoisInfo(
            available=True,
            registrar=str(registrar) if registrar else None,
            creation_date=creation_dt.strftime("%Y-%m-%d") if creation_dt else None,
            expiration_date=expiration_dt.strftime("%Y-%m-%d") if expiration_dt else None,
            domain_age_days=age_days,
            registrant_country=str(country) if country else None,
            is_newly_registered=is_nrd,
        )
    except Exception as exc:
        return WhoisInfo(available=False, error=str(exc)[:120])


def analyze_network(hostname: str, registered_domain: str, perform_scan: bool = True) -> NetworkAnalysisResult:
    if not perform_scan:
        return NetworkAnalysisResult(
            scanned=False,
            dns=DNSInfo(resolved=False),
            ssl=SSLInfo(has_ssl=False),
            whois=WhoisInfo(available=False),
            network_risk_score=0,
            signals=["Live network inspection was skipped (fast static mode)."],
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        fut_dns = executor.submit(inspect_dns, hostname, registered_domain)
        fut_ssl = executor.submit(inspect_ssl, hostname)
        fut_whois = executor.submit(inspect_whois, registered_domain)

        dns_info = fut_dns.result()
        ssl_info = fut_ssl.result()
        whois_info = fut_whois.result()

    score = 0
    signals: List[str] = []

    # Evaluate WHOIS signals
    if whois_info.available and whois_info.domain_age_days is not None:
        if whois_info.domain_age_days <= 14:
            score += 45
            signals.append(
                f"Critical Newly Registered Domain (NRD): registered only {whois_info.domain_age_days} days ago (+45 risk)"
            )
        elif whois_info.domain_age_days <= 60:
            score += 30
            signals.append(
                f"Newly Registered Domain (NRD): registered {whois_info.domain_age_days} days ago (+30 risk)"
            )
        elif whois_info.domain_age_days <= 180:
            score += 15
            signals.append(f"Relatively young domain ({whois_info.domain_age_days} days old) (+15 risk)")
        elif whois_info.domain_age_days >= 1825:
            signals.append(
                f"Established domain registration history ({whois_info.domain_age_days // 365} years old) (Trust signal)"
            )
    else:
        score += 12
        signals.append("WHOIS registration metadata unavailable or redacted/unregistered (+12 risk)")

    # Evaluate DNS signals
    if not dns_info.resolved:
        score += 20
        signals.append("Domain does not currently resolve to an active IPv4 address (offline or sinkholed) (+20 risk)")
    else:
        if not dns_info.has_spf and not dns_info.has_dmarc:
            score += 10
            signals.append("Missing email anti-spoofing DNS policies (neither SPF nor DMARC configured) (+10 risk)")
        elif dns_info.has_spf and dns_info.has_dmarc:
            signals.append("Valid SPF and DMARC email authentication records present (Trust signal)")

    # Evaluate SSL signals
    if not ssl_info.has_ssl:
        score += 20
        signals.append("No valid HTTPS/TLS certificate available on port 443 (+20 risk)")
    else:
        if ssl_info.cert_age_days is not None and ssl_info.cert_age_days <= 7 and ssl_info.is_free_Automated_ca:
            score += 18
            signals.append(
                f"Recently issued DV certificate ({ssl_info.cert_age_days} days old via {ssl_info.issuer}) (+18 risk)"
            )
        else:
            signals.append(f"Active TLS certificate issued by {ssl_info.issuer} ({ssl_info.protocol_version})")

    return NetworkAnalysisResult(
        scanned=True,
        dns=dns_info,
        ssl=ssl_info,
        whois=whois_info,
        network_risk_score=min(100, score),
        signals=signals,
    )
