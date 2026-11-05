"""Synthetic CIC-IDS2017-like flow generator.

FOR SMOKE-TESTING THE PIPELINE ONLY. Metrics produced on this data are NOT
research results and must never be reported as such. Use the real datasets
(see dataset_loader.py) for any number that goes into the report.
"""
import numpy as np
import pandas as pd

COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
    "Flow Packets/s", "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "Flow IAT Mean", "SYN Flag Count", "ACK Flag Count", "Packet Length Mean",
    "Packet Length Std", "Init_Win_bytes_forward",
]


def _flows(rng, n, kind):
    p = dict(dur=(11, 2.0), fp=(2.0, .8), bp=(2.0, .8), fl=(6, 1.2), bl=(7, 1.5),
             port=[80, 443, 53, 22, 8080], syn=(.1, .3), ack=(.7, .45), win=(8.5, 1.0))
    if kind == "DoS":
        p.update(dur=(13, 1.2), fp=(3.2, .6), bp=(.8, .6), fl=(5, .8), bl=(3, 1.0), syn=(.5, .5))
    elif kind == "PortScan":
        p.update(dur=(5, 1.0), fp=(.7, .3), bp=(.3, .3), fl=(2.5, .6), bl=(1.5, .8),
                 port=list(range(1, 1024)), syn=(.95, .2), ack=(.05, .2), win=(6.5, .5))
    elif kind == "BruteForce":
        p.update(dur=(12, .8), fp=(2.6, .4), bp=(2.5, .4), fl=(6.5, .5), bl=(6.8, .5),
                 port=[21, 22], ack=(.95, .2))
    elif kind == "Botnet":
        p.update(dur=(14, .6), fp=(1.5, .3), bp=(1.5, .3), fl=(5.5, .4), bl=(5.5, .4),
                 port=[8080, 6667, 4444], win=(9.5, .4))
    elif kind == "WebAttack":
        p.update(dur=(11.5, 1.0), fp=(2.4, .5), bp=(2.2, .5), fl=(7.5, .6), bl=(8.0, .8),
                 port=[80, 8080], ack=(.9, .3))
    fp = np.expm1(rng.normal(*p["fp"], n)).clip(1, None)
    bp = np.expm1(rng.normal(*p["bp"], n)).clip(0, None)
    dur = np.expm1(rng.normal(*p["dur"], n)).clip(1, None)
    fl = np.expm1(rng.normal(*p["fl"], n)).clip(0, None) * fp / 5
    bl = np.expm1(rng.normal(*p["bl"], n)).clip(0, None) * bp / 5
    df = pd.DataFrame({
        "Destination Port": rng.choice(p["port"], n),
        "Flow Duration": dur,
        "Total Fwd Packets": fp.round(), "Total Backward Packets": bp.round(),
        "Total Length of Fwd Packets": fl, "Total Length of Bwd Packets": bl,
        "Flow Bytes/s": (fl + bl) / (dur / 1e6),
        "Flow Packets/s": (fp + bp) / (dur / 1e6),
        "Fwd Packet Length Mean": fl / fp,
        "Bwd Packet Length Mean": np.where(bp > 0, bl / np.maximum(bp, 1), 0),
        "Flow IAT Mean": dur / (fp + bp + 1),
        "SYN Flag Count": (rng.random(n) < p["syn"][0]).astype(int),
        "ACK Flag Count": (rng.random(n) < p["ack"][0]).astype(int),
        "Packet Length Mean": (fl + bl) / (fp + bp + 1),
        "Packet Length Std": np.abs(rng.normal(60, 40, n)),
        "Init_Win_bytes_forward": np.expm1(rng.normal(*p["win"], n)),
    })
    df["Label"] = "BENIGN" if kind == "BENIGN" else kind
    return df


def make_synthetic(n_benign=12000, n_per_attack=1500, seed=42):
    rng = np.random.default_rng(seed)
    parts = [_flows(rng, n_benign, "BENIGN")]
    for fam in ["DoS", "PortScan", "BruteForce", "Botnet", "WebAttack"]:
        parts.append(_flows(rng, n_per_attack, fam))
    df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=seed).reset_index(drop=True)
    # inject dirt that real CIC-IDS2017 files contain
    df.loc[df.sample(20, random_state=1).index, "Flow Bytes/s"] = np.inf
    df.loc[df.sample(20, random_state=2).index, "Flow Packets/s"] = np.nan
    return pd.concat([df, df.iloc[:50]], ignore_index=True)  # duplicates
