"""
The hybrid verdict engine - where the three independent opinions are fused.

    heuristic score  (0-100)  explainable rules, works fully offline
    ML probability   (0-1)    learned patterns, works fully offline
    VirusTotal score (0-100)  70+ real security vendors, needs internet + key

Fusion (weights live in config.py, nothing is hard-coded here):

    VT available   ->  final = 0.35*heuristic + 0.40*(ml_prob*100) + 0.25*vt
    VT unavailable ->  final = 0.50*heuristic + 0.50*(ml_prob*100)
    model missing  ->  final = heuristic            (ml_status="unavailable")

Verdict bands:   < 30 Safe        30-60 Suspicious        > 60 Malicious

Why fuse at all? Each signal fails differently. The rules miss a brand-new
attack pattern nobody wrote a rule for; the ML model is only as good as its
training data; VirusTotal knows nothing about a URL registered ten minutes ago.
Averaging them means one blind spot does not decide the outcome.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.analyzer import certs, heuristics, predictor, virustotal
from app.analyzer.features import extract_features, get_hostname, normalise_url, url_metadata
from app.config import (
    FUSION_NO_VT,
    FUSION_WITH_VT,
    THRESHOLD_MALICIOUS,
    THRESHOLD_SAFE,
    VERDICT_MALICIOUS,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
)


def classify(final_score: float) -> str:
    """Map a 0-100 score onto the three verdict bands."""
    if final_score < THRESHOLD_SAFE:
        return VERDICT_SAFE
    if final_score <= THRESHOLD_MALICIOUS:
        return VERDICT_SUSPICIOUS
    return VERDICT_MALICIOUS


def confidence_for(final_score: float) -> int:
    """
    How far the score sits from the nearest decision boundary, as 0-100.

    A score of 5 is deep inside "Safe" and gets high confidence; a score of 29
    is one point from flipping to "Suspicious" and gets a low one. This is an
    honest statement of margin, not a probability - the README says so
    explicitly.

    Each band is normalised by its own half-width so the three bands are
    comparable:
      Safe        0  .. 30   -> distance from 30, normalised by 30
      Suspicious  30 .. 60   -> distance from whichever edge is closer, by 15
      Malicious   60 .. 100  -> distance from 60, normalised by 40
    """
    score = max(0.0, min(100.0, float(final_score)))

    if score < THRESHOLD_SAFE:
        span = THRESHOLD_SAFE or 1
        margin = (THRESHOLD_SAFE - score) / span
    elif score <= THRESHOLD_MALICIOUS:
        half = (THRESHOLD_MALICIOUS - THRESHOLD_SAFE) / 2 or 1
        nearest = min(score - THRESHOLD_SAFE, THRESHOLD_MALICIOUS - score)
        margin = nearest / half
    else:
        span = (100 - THRESHOLD_MALICIOUS) or 1
        margin = (score - THRESHOLD_MALICIOUS) / span

    return int(round(max(0.0, min(1.0, margin)) * 100))


def analyze_url(
    url: str,
    *,
    check_cert: bool = True,
    check_vt: bool = True,
    resolve_dns: bool = True,
) -> dict:
    """
    Run the complete pipeline for one URL and return the full report dict.

    This is THE entry point shared by the web API (main.py) and the CLI
    (cli.py), so both interfaces are guaranteed to produce identical verdicts.

    Every stage is individually wrapped: a certificate failure, a DNS failure, a
    VirusTotal outage or a missing model all degrade to a partial result. The
    function never raises.
    """
    normalised = normalise_url(url)
    hostname = get_hostname(normalised)

    # --- 1. URL string features (always available, always offline) ---------
    try:
        features = extract_features(normalised)
    except Exception:
        features = {}
    metadata = url_metadata(normalised)

    # --- 2. DNS resolution (display only, never an ML feature) -------------
    ip_addresses: list[str] = []
    if resolve_dns and hostname:
        try:
            ip_addresses = certs.resolve_ip(hostname)
        except Exception:
            ip_addresses = []

    # --- 3. TLS certificate ------------------------------------------------
    if check_cert and hostname and not metadata["is_ip_host"]:
        try:
            cert_info = certs.inspect_certificate(hostname)
        except Exception as exc:
            cert_info = certs._empty_result(certs.STATUS_ERROR, str(exc))
    else:
        cert_info = certs._empty_result(
            certs.STATUS_ERROR,
            "certificate check skipped" if not check_cert else "no hostname to inspect",
        )
        if not check_cert:
            cert_info["status"] = "skipped"

    # --- 4. Heuristic rules -------------------------------------------------
    try:
        heuristic_score, reasons = heuristics.score_url(normalised, features, cert_info)
    except Exception as exc:
        heuristic_score, reasons = 0, [
            {
                "rule": "heuristic_error",
                "points": 0,
                "severity": "LOW",
                "message": f"Heuristic engine error: {exc}",
            }
        ]

    # --- 5. ML model --------------------------------------------------------
    ml_probability = predictor.predict_proba(normalised)
    if ml_probability is None:
        ml_status = "unavailable"
        ml_reason = predictor.load_error() or "model not loaded"
    else:
        ml_status = "ok"
        ml_reason = ""

    # --- 6. VirusTotal ------------------------------------------------------
    if check_vt:
        try:
            vt_result = virustotal.check_url(normalised)
        except Exception as exc:
            vt_result = virustotal._result("unavailable", f"VirusTotal error: {exc}")
    else:
        vt_result = virustotal._result("not_configured", "VirusTotal lookup skipped")

    vt_usable = vt_result.get("status") == "ok" and vt_result.get("total", 0) > 0

    # --- 7. Fuse -------------------------------------------------------------
    ml_score = (ml_probability * 100) if ml_probability is not None else None
    vt_score = float(vt_result.get("vt_score", 0.0))

    if ml_score is None:
        # No model: the rules decide on their own.
        final_score = float(heuristic_score)
        weights_used = {"heuristic": 1.0}
        formula = "final = heuristic (ML model unavailable)"
    elif vt_usable:
        weights_used = dict(FUSION_WITH_VT)
        final_score = (
            weights_used["heuristic"] * heuristic_score
            + weights_used["ml"] * ml_score
            + weights_used["vt"] * vt_score
        )
        formula = (
            f"final = {weights_used['heuristic']}*heuristic + "
            f"{weights_used['ml']}*ml + {weights_used['vt']}*virustotal"
        )
    else:
        weights_used = dict(FUSION_NO_VT)
        final_score = (
            weights_used["heuristic"] * heuristic_score + weights_used["ml"] * ml_score
        )
        formula = (
            f"final = {weights_used['heuristic']}*heuristic + "
            f"{weights_used['ml']}*ml (VirusTotal unavailable)"
        )

    final_score = max(0.0, min(100.0, final_score))
    verdict = classify(final_score)

    return {
        "url": normalised,
        "original_input": url,
        "hostname": hostname,
        "ip_addresses": ip_addresses,
        "verdict": verdict,
        "final_score": round(final_score, 2),
        "confidence": confidence_for(final_score),
        "scores": {
            "heuristic": round(float(heuristic_score), 2),
            "ml_probability": round(ml_probability, 4) if ml_probability is not None else None,
            "ml_score": round(ml_score, 2) if ml_score is not None else None,
            "virustotal": round(vt_score, 2),
        },
        "weights_used": weights_used,
        "formula": formula,
        "ml_status": ml_status,
        "ml_message": ml_reason,
        "ml_model": predictor.model_name(),
        "vt": vt_result,
        "certificate": cert_info,
        "reasons": reasons,
        "metadata": metadata,
        "features": features,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
