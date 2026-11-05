"""Inference microservice (FastAPI). The ASP.NET Core backend posts uploaded CSVs here.
   uvicorn api:app --host 0.0.0.0 --port 8000
"""
import io, os
import pandas as pd
from fastapi import FastAPI, File, UploadFile, HTTPException, Header

from predict import load_bundle, predict_dataframe

app = FastAPI(title="Zero-Day ML Service", version="1.0")


def ensure_model():
    """If MODEL_URL is set and the bundle is missing, download it once (used on Render, where the
    trained .joblib is hosted as a GitHub Release asset instead of being committed to git)."""
    import pathlib, urllib.request
    path = pathlib.Path(os.getenv("MODEL_PATH") or pathlib.Path(__file__).parent / "models" / "zero_day_bundle.joblib")
    url = os.getenv("MODEL_URL")
    if url and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, path)
    return path


try:
    ensure_model()
except Exception as _e:          # service still starts; /health reports model-not-loaded
    print("model download failed:", _e)
API_KEY = os.getenv("ML_API_KEY", "")


def _auth(key):
    if API_KEY and key != API_KEY:
        raise HTTPException(401, "invalid API key")


@app.get("/health")
def health():
    try:
        b = load_bundle(os.getenv("MODEL_PATH") or None)
        m = {k: (round(float(v), 4) if isinstance(v, float) else v) for k, v in b.get("metrics_known_split", {}).items()}
        return {"status": "ok", "features": len(b["feature_names"]), "families": b["families"], "metrics": m,
                "threshold": round(float(b["model"].threshold_), 4), "blendWeight": round(float(b["model"].w), 2)}
    except Exception as e:
        return {"status": "model-not-loaded", "detail": str(e)}


@app.post("/predict")
async def predict(file: UploadFile = File(...), max_rows: int = 50000, x_api_key: str = Header(default="")):
    _auth(x_api_key)
    try:
        bundle = load_bundle(os.getenv("MODEL_PATH") or None)
    except Exception as e:
        raise HTTPException(503, f"model not available: {e}")
    raw = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(raw), encoding="latin1", low_memory=False)
    except Exception as e:
        raise HTTPException(400, f"cannot parse CSV: {e}")
    if df.empty:
        raise HTTPException(400, "CSV has no rows")
    return predict_dataframe(df, bundle, max_rows=max_rows)
