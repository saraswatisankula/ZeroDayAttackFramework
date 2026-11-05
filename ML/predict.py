"""Inference on uploaded flow CSVs. Used by the CLI and by the FastAPI service the ASP.NET backend calls."""
import argparse, json
import joblib
import numpy as np
import pandas as pd

from config import MODEL_DIR
from risk_scoring import build_alert

_BUNDLE = None


def load_bundle(path=None):
    global _BUNDLE
    if _BUNDLE is None or path:
        _BUNDLE = joblib.load(path or MODEL_DIR / "zero_day_bundle.joblib")
    return _BUNDLE


def predict_dataframe(df: pd.DataFrame, bundle=None, max_rows=None):
    bundle = bundle or load_bundle()
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.drop(columns=[c for c in ("Label", "label") if c in df.columns])
    if max_rows:
        df = df.head(max_rows)
    X = bundle["pipeline"].transform(df).to_numpy()
    model = bundle["model"]
    p_sup, s_anom = model.components(X)
    score = model.w * p_sup + (1 - model.w) * s_anom
    results = []
    for i in range(len(df)):
        a = build_alert(score[i], p_sup[i], s_anom[i], model.threshold_)
        a["flowId"] = int(i)
        results.append(a)
    sev = pd.Series([r["severity"] for r in results if r["threatType"] != "Benign"]).value_counts().to_dict()
    types = pd.Series([r["threatType"] for r in results]).value_counts().to_dict()
    summary = {"totalFlows": len(results),
               "threats": int(sum(r["threatType"] != "Benign" for r in results)),
               "zeroDayDetections": int(types.get("Zero-Day Attack", 0)),
               "highRiskAlerts": int(sum(r["riskScore"] >= 70 for r in results)),
               "byThreatType": types, "bySeverity": sev,
               "threshold": round(float(model.threshold_), 4), "blendWeight": round(float(model.w), 2)}
    return {"summary": summary, "results": results}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--model", default=None)
    ap.add_argument("--top", type=int, default=5)
    a = ap.parse_args()
    out = predict_dataframe(pd.read_csv(a.csv, encoding="latin1", low_memory=False), load_bundle(a.model))
    top = sorted(out["results"], key=lambda r: -r["riskScore"])[: a.top]
    print(json.dumps({"summary": out["summary"], "topAlerts": top}, indent=2))
