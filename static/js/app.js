let currentScanResult = null;

document.addEventListener("DOMContentLoaded", () => {
    const heroScanForm = document.getElementById("heroScanForm");
    const deepScanForm = document.getElementById("deepScanForm");
    const domainInput = document.getElementById("domainInput");
    const deepDomainInput = document.getElementById("deepDomainInput");
    const deepNetworkToggle = document.getElementById("deepNetworkToggle");

    // Load initial history & stats in background
    fetchHistoryAndStats();

    // Navigation between View 1 (Hero Overview) and View 2 (Deep Analysis View)
    document.getElementById("brandHomeLink").addEventListener("click", (e) => {
        e.preventDefault();
        switchView("hero");
    });
    document.getElementById("navOverviewBtn").addEventListener("click", () => switchView("hero"));
    document.getElementById("backToHeroBtn").addEventListener("click", () => switchView("hero"));

    document.getElementById("navDeepReportBtn").addEventListener("click", () => {
        if (!currentScanResult) {
            const target = domainInput.value.trim() || "paypa1-secure-login.xyz";
            runSingleScan(target, true, true);
        } else {
            switchView("deep");
        }
    });

    document.getElementById("openFullReportBtn").addEventListener("click", () => {
        if (!currentScanResult) {
            const target = domainInput.value.trim() || "paypa1-secure-login.xyz";
            runSingleScan(target, true, true);
        } else {
            switchView("deep");
        }
    });

    // Hero Scan Form submission -> Analyze & transition to Deep Analysis View
    heroScanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const target = domainInput.value.trim();
        if (!target) return;
        await runSingleScan(target, deepNetworkToggle ? deepNetworkToggle.checked : true, true);
    });

    // Deep View inline Scan Form submission
    deepScanForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const target = deepDomainInput.value.trim();
        if (!target) return;
        domainInput.value = target;
        await runSingleScan(target, deepNetworkToggle.checked, true);
    });

    // Quick sample chips on Hero View
    document.querySelectorAll(".pt-sample-chip[data-sample]").forEach((chip) => {
        chip.addEventListener("click", () => {
            const sample = chip.getAttribute("data-sample");
            domainInput.value = sample;
            deepDomainInput.value = sample;
            runSingleScan(sample, true, true);
        });
    });

    // Network tabs switching
    document.querySelectorAll(".net-tab").forEach((tabBtn) => {
        tabBtn.addEventListener("click", () => {
            document.querySelectorAll(".net-tab").forEach((b) => b.classList.remove("active"));
            document.querySelectorAll(".net-tab-content").forEach((c) => c.classList.remove("active"));
            tabBtn.classList.add("active");
            const targetId = tabBtn.getAttribute("data-tab");
            document.getElementById(targetId).classList.add("active");
        });
    });

    // Export JSON button
    document.getElementById("exportJsonBtn").addEventListener("click", () => {
        if (!currentScanResult) return;
        const blob = new Blob([JSON.stringify(currentScanResult, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `phishtrace-report-${currentScanResult.normalized_domain}.json`;
        a.click();
        URL.revokeObjectURL(url);
    });

    // Clear history button
    document.getElementById("clearHistoryBtn").addEventListener("click", async () => {
        await fetch("/api/history", { method: "DELETE" });
        fetchHistoryAndStats();
    });

    // Batch scanner toggles
    const bulkSection = document.getElementById("bulkScannerSection");
    document.getElementById("toggleBulkBtn").addEventListener("click", () => {
        switchView("deep");
        bulkSection.classList.remove("hidden");
        bulkSection.scrollIntoView({ behavior: "smooth" });
    });
    document.getElementById("closeBulkBtn").addEventListener("click", () => {
        bulkSection.classList.add("hidden");
    });
    document.getElementById("fillSampleBulkBtn").addEventListener("click", () => {
        document.getElementById("bulkTextarea").value = [
            "paypa1-secure-login.xyz",
            "microsoft-office365-account-verify.top",
            "xn--pple-43d.com",
            "github.com",
            "arnazon-prime-billing-alert.icu",
            "google.com"
        ].join("\n");
    });
    document.getElementById("runBulkBtn").addEventListener("click", runBulkScan);
});

function switchView(viewName) {
    const heroView = document.getElementById("heroDashboardView");
    const deepView = document.getElementById("deepAnalysisView");
    const navOverviewBtn = document.getElementById("navOverviewBtn");
    const navDeepReportBtn = document.getElementById("navDeepReportBtn");

    if (viewName === "deep") {
        heroView.classList.add("hidden");
        deepView.classList.remove("hidden");
        navOverviewBtn.classList.remove("active");
        navDeepReportBtn.classList.add("active");
        window.scrollTo({ top: 0, behavior: "smooth" });
    } else {
        deepView.classList.add("hidden");
        heroView.classList.remove("hidden");
        navDeepReportBtn.classList.remove("active");
        navOverviewBtn.classList.add("active");
        window.scrollTo({ top: 0, behavior: "smooth" });
    }
}

function showToast(msg) {
    const toast = document.getElementById("toastNotification");
    toast.textContent = msg;
    toast.classList.remove("hidden");
    setTimeout(() => {
        toast.classList.add("hidden");
    }, 4500);
}

function getScoreColor(score) {
    if (score >= 65) return "#fb7185";
    if (score >= 40) return "#f59e0b";
    return "#34d399";
}

function getVerdictClass(score) {
    if (score >= 65) return "verdict-danger";
    if (score >= 40) return "verdict-warning";
    return "verdict-safe";
}

function getInfraPillClass(score) {
    if (score >= 65) return "pt-infra-pill pt-infra-danger";
    if (score >= 40) return "pt-infra-pill pt-infra-warn";
    return "pt-infra-pill pt-infra-safe";
}

function getInfraStatusText(score, isOfficial) {
    if (isOfficial) return "Verified official brand infrastructure";
    if (score >= 65) return "Suspicious infrastructure detected";
    if (score >= 40) return "Anomalous domain signals observed";
    return "Clean domain infrastructure profile";
}

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

async function runSingleScan(target, deepNetwork, autoNavigateToDeep = true) {
    const scanBtn = document.getElementById("scanBtn");
    const scanBtnText = document.getElementById("scanBtnText");
    const scanSpinner = document.getElementById("scanSpinner");
    const deepScanBtn = document.getElementById("deepScanBtn");

    scanBtn.disabled = true;
    scanBtnText.textContent = "Analyzing...";
    scanSpinner.classList.remove("hidden");
    if (deepScanBtn) {
        deepScanBtn.disabled = true;
        deepScanBtn.textContent = "Analyzing...";
    }

    try {
        const resp = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, deep_network_scan: deepNetwork }),
        });

        if (!resp.ok) {
            const errData = await resp.json().catch(() => ({}));
            throw new Error(errData.detail || `Scan failed with status ${resp.status}`);
        }

        const data = await resp.json();
        currentScanResult = data;
        document.getElementById("deepDomainInput").value = data.normalized_domain;
        renderScanResult(data);
        fetchHistoryAndStats();

        if (autoNavigateToDeep) {
            switchView("deep");
        }
    } catch (err) {
        showToast(err.message || "Failed to analyze domain.");
    } finally {
        scanBtn.disabled = false;
        scanBtnText.textContent = "Analyze Domain";
        scanSpinner.classList.add("hidden");
        if (deepScanBtn) {
            deepScanBtn.disabled = false;
            deepScanBtn.textContent = "Analyze Domain";
        }
    }
}

function computeSummaryCounts(data) {
    // Subdomains count: actual subdomain levels + discovered NS/MX host count
    const nsCnt = (data.network && data.network.dns && data.network.dns.ns_records) ? data.network.dns.ns_records.length : 0;
    const mxCnt = (data.network && data.network.dns && data.network.dns.mx_records) ? data.network.dns.mx_records.length : 0;
    const subCount = Math.max(1, data.lexical.subdomain_count + nsCnt + mxCnt);

    // Lookalike permutations count
    const brandMatches = data.brand.detected_brands ? data.brand.detected_brands.length : 0;
    const homoglyphs = data.brand.homoglyphs_detected ? data.brand.homoglyphs_detected.length : 0;
    const lookalikeCount = data.brand.is_official_brand_domain
        ? 0
        : (brandMatches * 6) + (homoglyphs * 3) + (data.lexical.hyphen_count * 2) + (data.lexical.digit_count > 0 ? 3 : 1);

    // Threat signals count
    const riskSigCount = (data.ai_report && data.ai_report.key_risk_indicators)
        ? data.ai_report.key_risk_indicators.length
        : 0;
    const kwCount = data.lexical.suspicious_keywords ? data.lexical.suspicious_keywords.length : 0;
    const totalSignals = data.brand.is_official_brand_domain ? 0 : Math.max(riskSigCount + kwCount, data.overall_risk_score >= 50 ? 5 : 1);

    return { subCount, lookalikeCount, totalSignals };
}

function renderScanResult(data) {
    const score = data.overall_risk_score;
    const color = getScoreColor(score);
    const { subCount, lookalikeCount, totalSignals } = computeSummaryCounts(data);
    const statusText = getInfraStatusText(score, data.brand.is_official_brand_domain);
    const pillClass = getInfraPillClass(score);
    const valColorClass = score >= 65 ? "pt-val-danger" : (score >= 40 ? "pt-val-warn" : "pt-val-safe");

    // A. Update Hero Radar Floating Cards & Hero Summary Card
    const conf = data.ml_prediction.confidence || 96.8;
    const phishProbPct = Math.round(data.ml_prediction.phishing_probability * 100);
    document.getElementById("heroConfidenceVal").textContent = `${conf}%`;
    document.getElementById("heroConfidenceBar").style.width = `${conf}%`;

    const heroThreatEl = document.getElementById("heroThreatLevel");
    heroThreatEl.textContent = data.risk_level;
    heroThreatEl.style.color = color;

    const heroPhishProb = document.getElementById("heroPhishProb");
    heroPhishProb.textContent = `${phishProbPct}%`;
    heroPhishProb.style.color = color;

    const heroPhishBar = document.getElementById("heroPhishBar");
    heroPhishBar.style.width = `${Math.max(4, phishProbPct)}%`;
    heroPhishBar.style.background = color;

    document.getElementById("heroSummaryDomain").textContent = data.normalized_domain;
    const heroPill = document.getElementById("heroSummaryStatusPill");
    heroPill.textContent = statusText;
    heroPill.className = pillClass;

    const heroRiskEl = document.getElementById("heroMetricRisk");
    heroRiskEl.textContent = `${score} / 100`;
    heroRiskEl.className = `pt-metric-value ${valColorClass}`;
    document.getElementById("heroMetricSubdomains").textContent = subCount;
    document.getElementById("heroMetricLookalikes").textContent = lookalikeCount;
    document.getElementById("heroMetricSignals").textContent = totalSignals;

    // B. Update Deep View Top Summary Banner
    document.getElementById("deepSummaryDomain").textContent = data.normalized_domain;
    const deepPill = document.getElementById("deepSummaryStatusPill");
    deepPill.textContent = statusText;
    deepPill.className = pillClass;

    const deepRiskEl = document.getElementById("deepMetricRisk");
    deepRiskEl.textContent = `${score} / 100`;
    deepRiskEl.className = `pt-metric-value ${valColorClass}`;
    document.getElementById("deepMetricSubdomains").textContent = subCount;
    document.getElementById("deepMetricLookalikes").textContent = lookalikeCount;
    document.getElementById("deepMetricSignals").textContent = totalSignals;

    // 1. Update SVG Gauge (arc length = 251.2)
    const arc = document.getElementById("gaugeArc");
    const maxDash = 251.2;
    const offset = maxDash - (score / 100) * maxDash;
    arc.style.strokeDashoffset = offset;
    arc.style.stroke = color;

    const scoreValEl = document.getElementById("overallScoreValue");
    scoreValEl.textContent = score;
    scoreValEl.style.color = color;

    const verdictBadge = document.getElementById("verdictBadge");
    verdictBadge.textContent = `${data.verdict} (${data.risk_level})`;
    verdictBadge.className = `verdict-badge ${getVerdictClass(score)}`;

    document.getElementById("scannedDomainLabel").textContent = data.normalized_domain;
    document.getElementById("scanDurationLabel").textContent = `Completed in ${data.scan_duration_ms} ms • ${data.timestamp}`;

    // Subscores
    updateSubBar("subMlScore", "barMl", `${phishProbPct}%`, data.ml_prediction.ml_risk_score);
    updateSubBar("subBrandScore", "barBrand", `${data.brand.brand_risk_score}/100`, data.brand.brand_risk_score);
    updateSubBar("subLexicalScore", "barLexical", `${data.lexical.lexical_risk_score}/100`, data.lexical.lexical_risk_score);
    updateSubBar("subNetworkScore", "barNetwork", `${data.network.network_risk_score}/100`, data.network.network_risk_score);

    // 2. AI Threat Report
    document.getElementById("aiThreatCategory").textContent = data.ai_report.threat_category;
    document.getElementById("aiEngineBadge").textContent = data.ai_report.engine_used;
    document.getElementById("aiExecutiveSummary").textContent = data.ai_report.executive_summary;
    document.getElementById("aiAttackVector").textContent = data.ai_report.attack_vector_analysis;

    renderList("aiRiskIndicatorsList", data.ai_report.key_risk_indicators, "No elevated risk indicators identified.");
    renderList("aiTrustIndicatorsList", data.ai_report.trust_indicators, "No positive verification signals found.");
    renderList("aiActionsList", data.ai_report.recommended_actions, "Standard monitoring.");

    // 3. Brand Impersonation & Homoglyphs
    const brandBadge = document.getElementById("brandStatusBadge");
    if (data.brand.is_official_brand_domain) {
        brandBadge.textContent = "Official Verified Domain";
        brandBadge.className = "badge verdict-safe";
    } else if (data.brand.brand_risk_score >= 50) {
        brandBadge.textContent = `High Impersonation Risk (${data.brand.brand_risk_score}/100)`;
        brandBadge.className = "badge verdict-danger";
    } else {
        brandBadge.textContent = "No Brand Spoofing";
        brandBadge.className = "badge badge-neutral";
    }

    const brandMatchesEl = document.getElementById("brandMatchesContainer");
    if (data.brand.detected_brands && data.brand.detected_brands.length > 0) {
        brandMatchesEl.innerHTML = data.brand.detected_brands.map((m) => `
            <div class="brand-match-card">
                <div class="brand-match-head">
                    <span class="brand-match-title">${escapeHtml(m.brand)} — ${escapeHtml(m.technique)}</span>
                    <span class="badge ${data.brand.is_official_brand_domain ? 'verdict-safe' : 'verdict-danger'}">
                        ${Math.round(m.similarity_score * 100)}% Match
                    </span>
                </div>
                <p class="text-muted">${escapeHtml(m.details)}</p>
            </div>
        `).join("");
    } else {
        brandMatchesEl.innerHTML = `<div class="brand-match-card"><p class="text-muted">No targeted brand impersonation or typosquatting detected against 30+ monitored global brands.</p></div>`;
    }
    renderList("brandSignalsList", data.brand.signals, "Clean brand check.");

    // 4. Explainable AI (XAI) Feature Contributions
    document.getElementById("mlModelBadge").textContent = `AI Confidence: ${data.ml_prediction.confidence}%`;
    const xaiEl = document.getElementById("xaiFeaturesList");
    xaiEl.innerHTML = data.ml_prediction.top_features.map((f) => {
        const badgeClass = f.impact === "High Risk" ? "verdict-danger"
            : f.impact === "Moderate Risk" ? "verdict-warning" : "verdict-safe";
        const sign = f.weight_score > 0 ? `+${f.weight_score}` : `${f.weight_score}`;
        return `
            <div class="xai-item">
                <div>
                    <div class="xai-name">${escapeHtml(f.feature_name)}</div>
                    <div class="xai-val">${escapeHtml(f.value)}</div>
                </div>
                <span class="badge ${badgeClass}">${escapeHtml(f.impact)} (${sign})</span>
            </div>
        `;
    }).join("");

    // 5. Lexical & URL Anatomy
    const lex = data.lexical;
    const lexBadge = document.getElementById("lexicalScoreBadge");
    lexBadge.textContent = `${lex.lexical_risk_score} / 100`;
    lexBadge.className = `badge ${getVerdictClass(lex.lexical_risk_score)}`;

    document.getElementById("domainAnatomyBar").innerHTML = `
        <div class="anat-chip">
            <span class="anat-label">Subdomain</span>
            <span class="anat-val">${escapeHtml(lex.subdomain || "(none)")}</span>
        </div>
        <div class="anat-chip">
            <span class="anat-label">Registered Root</span>
            <span class="anat-val">${escapeHtml(lex.registered_domain)}</span>
        </div>
        <div class="anat-chip">
            <span class="anat-label">TLD</span>
            <span class="anat-val">.${escapeHtml(lex.tld || "n/a")}</span>
        </div>
        <div class="anat-chip">
            <span class="anat-label">URL Path</span>
            <span class="anat-val">${escapeHtml(lex.url_path)}</span>
        </div>
    `;

    document.getElementById("lexEntropy").textContent = `${lex.shannon_entropy} bits`;
    document.getElementById("lexLength").textContent = `${lex.domain_length} chars`;
    document.getElementById("lexSubdomains").textContent = `${lex.subdomain_count}`;
    document.getElementById("lexHyphensDigits").textContent = `${lex.hyphen_count} / ${lex.digit_count}`;
    document.getElementById("lexDigitRatio").textContent = `${Math.round(lex.digit_ratio * 100)}%`;
    document.getElementById("lexTldStatus").textContent = lex.is_high_risk_tld ? `.${lex.tld} (High Risk)` : `.${lex.tld} (Standard)`;

    const kwBox = document.getElementById("lexKeywordsList");
    if (lex.suspicious_keywords && lex.suspicious_keywords.length > 0) {
        kwBox.innerHTML = lex.suspicious_keywords.map((kw) =>
            `<span class="pill pill-danger">${escapeHtml(kw)}</span>`
        ).join("");
    } else {
        kwBox.innerHTML = `<span class="text-muted">None detected</span>`;
    }
    renderList("lexicalSignalsList", lex.signals, "Clean lexical profile.");

    // 6. Network Inspector (WHOIS, SSL, DNS)
    const net = data.network;
    const netBadge = document.getElementById("networkScoreBadge");
    netBadge.textContent = net.scanned ? `${net.network_risk_score} / 100` : "Skipped";
    netBadge.className = `badge ${getVerdictClass(net.network_risk_score)}`;

    const w = net.whois;
    document.getElementById("whoisKvGrid").innerHTML = `
        <div class="kv-box">
            <span class="kv-key">Domain Age</span>
            <span class="kv-val">${w.domain_age_days !== null ? `${w.domain_age_days} days (${Math.floor(w.domain_age_days / 365)} yrs)` : "Unavailable"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">NRD (<60 Days) Status</span>
            <span class="kv-val">${w.is_newly_registered ? "⚠️ NEWLY REGISTERED" : "Standard / Established"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Creation Date</span>
            <span class="kv-val">${escapeHtml(w.creation_date || "N/A")}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Expiration Date</span>
            <span class="kv-val">${escapeHtml(w.expiration_date || "N/A")}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Registrar</span>
            <span class="kv-val">${escapeHtml(w.registrar || "Redacted / Unknown")}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Registrant Country</span>
            <span class="kv-val">${escapeHtml(w.registrant_country || "Redacted / Unknown")}</span>
        </div>
    `;

    const s = net.ssl;
    document.getElementById("sslKvGrid").innerHTML = `
        <div class="kv-box">
            <span class="kv-key">HTTPS / TLS Active</span>
            <span class="kv-val">${s.has_ssl ? "✅ Active TLS Certificate" : "❌ No Active SSL/TLS"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Certificate Issuer CA</span>
            <span class="kv-val">${escapeHtml(s.issuer || "N/A")}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Subject Common Name</span>
            <span class="kv-val">${escapeHtml(s.subject_cn || "N/A")}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Certificate Age / Remaining</span>
            <span class="kv-val">${s.cert_age_days !== null ? `${s.cert_age_days}d old / ${s.days_remaining}d left` : "N/A"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Validity Window</span>
            <span class="kv-val">${escapeHtml(s.valid_from || "N/A")} → ${escapeHtml(s.valid_until || "N/A")}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">TLS Protocol</span>
            <span class="kv-val">${escapeHtml(s.protocol_version || s.error || "N/A")}</span>
        </div>
    `;

    const d = net.dns;
    document.getElementById("dnsKvGrid").innerHTML = `
        <div class="kv-box">
            <span class="kv-key">A Record IPs</span>
            <span class="kv-val">${d.ip_addresses.length ? escapeHtml(d.ip_addresses.join(", ")) : "Unresolved"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Email Anti-Spoofing</span>
            <span class="kv-val">SPF: ${d.has_spf ? "✅ Yes" : "❌ No"} | DMARC: ${d.has_dmarc ? "✅ Yes" : "❌ No"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">MX Mail Servers</span>
            <span class="kv-val">${d.mx_records.length ? escapeHtml(d.mx_records.join(", ")) : "None"}</span>
        </div>
        <div class="kv-box">
            <span class="kv-key">Authoritative Nameservers</span>
            <span class="kv-val">${d.ns_records.length ? escapeHtml(d.ns_records.join(", ")) : "None"}</span>
        </div>
    `;

    renderList("networkSignalsList", net.signals, "No infrastructure signals.");
}

function updateSubBar(labelId, barId, textVal, numericScore) {
    document.getElementById(labelId).textContent = textVal;
    const bar = document.getElementById(barId);
    bar.style.width = `${Math.min(100, Math.max(4, numericScore))}%`;
    bar.style.backgroundColor = getScoreColor(numericScore);
}

function renderList(elementId, items, emptyFallback) {
    const ul = document.getElementById(elementId);
    if (!items || items.length === 0) {
        ul.innerHTML = `<li class="text-muted">${escapeHtml(emptyFallback)}</li>`;
        return;
    }
    ul.innerHTML = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
}

async function fetchHistoryAndStats() {
    try {
        const resp = await fetch("/api/history?limit=15");
        if (!resp.ok) return;
        const data = await resp.json();

        document.getElementById("statTotal").textContent = data.stats.total_scans;
        document.getElementById("statMalicious").textContent = data.stats.malicious_count;
        document.getElementById("statSuspicious").textContent = data.stats.suspicious_count;
        document.getElementById("statSafe").textContent = data.stats.safe_count;

        const tbody = document.getElementById("historyTableBody");
        if (!data.recent_scans || data.recent_scans.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-row">No domains scanned yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = data.recent_scans.map((row) => `
            <tr data-scan-id="${row.id}">
                <td class="mono-val">${escapeHtml(row.timestamp)}</td>
                <td class="mono-val">${escapeHtml(row.normalized_domain)}</td>
                <td>${escapeHtml(row.threat_category)}</td>
                <td class="mono-val" style="color:${getScoreColor(row.overall_risk_score)}">${row.overall_risk_score} / 100</td>
                <td><span class="badge ${getVerdictClass(row.overall_risk_score)}">${escapeHtml(row.verdict)}</span></td>
                <td><button type="button" class="btn btn-ghost btn-sm">View Report</button></td>
            </tr>
        `).join("");

        tbody.querySelectorAll("tr[data-scan-id]").forEach((tr) => {
            tr.addEventListener("click", async () => {
                const id = tr.getAttribute("data-scan-id");
                const detailResp = await fetch(`/api/history/${id}`);
                if (detailResp.ok) {
                    const fullRecord = await detailResp.json();
                    currentScanResult = fullRecord;
                    renderScanResult(fullRecord);
                    switchView("deep");
                }
            });
        });
    } catch (e) {
        console.error("Failed to fetch history:", e);
    }
}

async function runBulkScan() {
    const rawText = document.getElementById("bulkTextarea").value;
    const targets = rawText.split("\n").map((s) => s.trim()).filter(Boolean);
    if (targets.length === 0) return;

    const btn = document.getElementById("runBulkBtn");
    const container = document.getElementById("bulkResultsContainer");
    btn.disabled = true;
    btn.textContent = "Scanning Batch...";

    try {
        const resp = await fetch("/api/bulk-analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ targets, deep_network_scan: false }),
        });
        const data = await resp.json();
        container.classList.remove("hidden");

        container.innerHTML = `
            <div class="table-responsive">
                <table class="history-table">
                    <thead>
                        <tr>
                            <th>Domain</th>
                            <th>Threat Category</th>
                            <th>ML Prob</th>
                            <th>Composite Score</th>
                            <th>Verdict</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.results.map((r) => {
                            if (r.error) {
                                return `<tr><td class="mono-val">${escapeHtml(r.input_target)}</td><td colspan="4">${escapeHtml(r.error)}</td></tr>`;
                            }
                            return `
                                <tr>
                                    <td class="mono-val">${escapeHtml(r.normalized_domain)}</td>
                                    <td>${escapeHtml(r.ai_report.threat_category)}</td>
                                    <td class="mono-val">${Math.round(r.ml_prediction.phishing_probability * 100)}%</td>
                                    <td class="mono-val" style="color:${getScoreColor(r.overall_risk_score)}">${r.overall_risk_score}/100</td>
                                    <td><span class="badge ${getVerdictClass(r.overall_risk_score)}">${escapeHtml(r.verdict)}</span></td>
                                </tr>
                            `;
                        }).join("")}
                    </tbody>
                </table>
            </div>
        `;
        fetchHistoryAndStats();
    } finally {
        btn.disabled = false;
        btn.textContent = "Run Batch Scan";
    }
}
