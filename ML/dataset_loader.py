"""Dataset loading for CIC-IDS2017, CTU-13, USTC-TFC2016 (+ synthetic smoke-test data).

Official sources (download manually, they are large):
  CIC-IDS2017  : https://www.unb.ca/cic/datasets/ids-2017.html  (MachineLearningCSV.zip)
  CTU-13       : https://www.stratosphereips.org/datasets-ctu13  (*.binetflow files)
  USTC-TFC2016 : https://github.com/yungshenglu/USTC-TFC2016    (pcaps -> convert to flows
                 with CICFlowMeter, then point load_ustc_tfc2016 at the CSV folder)
"""
from pathlib import Path
import numpy as np
import pandas as pd

from config import LABEL_COL, FAMILY_MAP, BENIGN_NAMES, DATA_DIR
from synthetic_data import make_synthetic


def _family(label: str) -> str:
    l = str(label).strip().lower()
    if l in BENIGN_NAMES:
        return "BENIGN"
    if l in FAMILY_MAP:
        return FAMILY_MAP[l]
    if l.startswith("web attack"):
        return "WebAttack"
    return str(label).strip()


def load_cicids2017(folder=None, max_rows_per_file=None) -> pd.DataFrame:
    """Load all MachineLearningCVE/*.csv files of CIC-IDS2017 into one DataFrame."""
    folder = Path(folder or DATA_DIR / "CIC-IDS2017")
    files = sorted(folder.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {folder}. Download from "
                                "https://www.unb.ca/cic/datasets/ids-2017.html")
    frames = []
    for f in files:
        df = pd.read_csv(f, nrows=max_rows_per_file, encoding="latin1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df[LABEL_COL] = df[LABEL_COL].map(_family)
    return df


def load_ctu13(folder=None) -> pd.DataFrame:
    """Load CTU-13 *.binetflow files. Background flows are dropped; 'Botnet' -> Botnet."""
    folder = Path(folder or DATA_DIR / "CTU-13")
    files = sorted(folder.glob("*.binetflow")) + sorted(folder.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No binetflow/CSV files in {folder}")
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        lab = df["Label"].astype(str).str.lower()
        keep = lab.str.contains("botnet") | lab.str.contains("normal")
        df = df[keep].copy()
        df[LABEL_COL] = np.where(lab[keep].str.contains("botnet"), "Botnet", "BENIGN")
        for c in ("Proto", "Dir", "State"):           # categorical -> codes
            if c in df:
                df[c] = df[c].astype("category").cat.codes
        for c in ("StartTime", "SrcAddr", "DstAddr", "sTos", "dTos"):
            if c in df:
                df = df.drop(columns=c)
        for c in ("Sport", "Dport"):                   # may be hex / blank
            if c in df:
                df[c] = pd.to_numeric(df[c], errors="coerce")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def load_ustc_tfc2016(folder=None) -> pd.DataFrame:
    """USTC-TFC2016 flow CSVs (pcaps converted with CICFlowMeter).
    File names containing 'benign' / 'normal' are benign; every other file is malware."""
    folder = Path(folder or DATA_DIR / "USTC-TFC2016")
    files = sorted(folder.rglob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files in {folder}")
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        name = f.stem
        df[LABEL_COL] = "BENIGN" if any(k in name.lower() for k in ("benign", "normal")) else name
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def load_synthetic(**kw) -> pd.DataFrame:
    return make_synthetic(**kw)


def load_dataset(name: str, folder=None, **kw) -> pd.DataFrame:
    name = name.lower().replace("-", "").replace("_", "")
    loaders = {"cicids2017": load_cicids2017, "ctu13": load_ctu13,
               "ustctfc2016": load_ustc_tfc2016, "ustc": load_ustc_tfc2016,
               "synthetic": lambda folder=None, **k: load_synthetic(**k)}
    if name not in loaders:
        raise ValueError(f"Unknown dataset {name}; choose {list(loaders)}")
    return loaders[name](folder, **kw) if name != "synthetic" else loaders[name](**kw)
