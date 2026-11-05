"""Turn a model decision score into a 0-100 risk score, severity, threat type and confidence."""
from config import SEVERITY_BANDS


def risk_score(score: float, threshold: float) -> int:
    """Piece-wise linear map: score==threshold -> 50; 0 -> 0; 1 -> 100."""
    threshold = min(max(threshold, 1e-6), 1 - 1e-6)
    if score < threshold:
        r = 50 * score / threshold
    else:
        r = 50 + 50 * (score - threshold) / (1 - threshold)
    return int(round(min(max(r, 0), 100)))


def severity(risk: int) -> str:
    for lo, name in SEVERITY_BANDS:
        if risk >= lo:
            return name
    return "Low"


def threat_type(p_sup: float, s_anom: float, risk: int, sup_cut: float = 0.5, anom_cut: float = 0.95) -> str:
    """Alert logic:
       risk < 50                          -> Benign
       supervised branch confident        -> Known Attack
       otherwise (anomalous but not recognised by supervised model) -> Zero-Day Attack (suspected)"""
    if risk < 50:
        return "Benign"
    if p_sup >= sup_cut:
        return "Known Attack"
    if s_anom >= anom_cut:
        return "Zero-Day Attack"
    return "Suspicious Anomaly"


def confidence(score: float, threshold: float) -> int:
    """Decision margin as a percentage (distance from the threshold, normalised). Not a calibrated probability."""
    span = max(threshold, 1 - threshold)
    return int(round(min(99, 50 + 50 * abs(score - threshold) / span)))


def build_alert(score, p_sup, s_anom, threshold) -> dict:
    r = risk_score(score, threshold)
    return {
        "riskScore": r,
        "threatType": threat_type(p_sup, s_anom, r),
        "severity": severity(r) if r >= 50 else "Low",
        "confidence": f"{confidence(score, threshold)}%",
        "anomalyScore": round(float(s_anom), 4),
        "supervisedProbability": round(float(p_sup), 4),
    }
