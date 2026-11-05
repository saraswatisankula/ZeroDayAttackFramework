"""Domain features + feature selection (correlation filter -> mutual information top-k)."""
import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif


def _col(df, name):
    return df[name] if name in df.columns else None


def add_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    """Adds ratio / rate features when the CIC-IDS2017 columns they need exist (safe otherwise)."""
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    fp, bp = _col(df, "Total Fwd Packets"), _col(df, "Total Backward Packets")
    fl, bl = _col(df, "Total Length of Fwd Packets"), _col(df, "Total Length of Bwd Packets")
    dur = _col(df, "Flow Duration")
    syn, ack = _col(df, "SYN Flag Count"), _col(df, "ACK Flag Count")
    eps = 1e-9
    if fp is not None and bp is not None:
        df["FE_pkt_ratio_fwd_bwd"] = fp / (bp + 1)
        df["FE_total_packets"] = fp + bp
    if fl is not None and bl is not None:
        df["FE_byte_ratio_fwd_bwd"] = fl / (bl + 1)
        df["FE_total_bytes"] = fl + bl
        if fp is not None and bp is not None:
            df["FE_bytes_per_packet"] = (fl + bl) / (fp + bp + 1)
    if dur is not None and fp is not None and bp is not None:
        df["FE_pkts_per_ms"] = (fp + bp) / (dur / 1000 + eps)
    if syn is not None and ack is not None:
        df["FE_syn_minus_ack"] = syn - ack
    return df


class FeatureSelector:
    """Drop one of each highly-correlated pair, then keep the top-k by mutual information."""

    def __init__(self, k=40, corr_threshold=0.95, mi_sample=20000, seed=42):
        self.k, self.corr_threshold, self.mi_sample, self.seed = k, corr_threshold, mi_sample, seed

    def fit(self, X: pd.DataFrame, y):
        corr = X.corr().abs()
        upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
        drop = [c for c in upper.columns if (upper[c] > self.corr_threshold).any()]
        Xr = X.drop(columns=drop)
        idx = np.random.default_rng(self.seed).choice(len(Xr), min(self.mi_sample, len(Xr)), replace=False)
        mi = mutual_info_classif(Xr.iloc[idx], np.asarray(y)[idx], random_state=self.seed)
        order = np.argsort(mi)[::-1][: self.k]
        self.selected_ = [Xr.columns[i] for i in order]
        self.mi_ = dict(zip(Xr.columns, mi))
        self.dropped_corr_ = drop
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        return X[self.selected_]


from preprocessing import Preprocessor  # noqa: E402  (kept here so pickled bundles resolve to this module)


class FeaturePipeline:
    """raw flow DataFrame -> engineered -> imputed/scaled -> selected features. Fit on TRAIN only."""

    def __init__(self, k=40, corr_threshold=0.95, seed=42):
        self.prep = Preprocessor()
        self.sel = FeatureSelector(k=k, corr_threshold=corr_threshold, seed=seed)

    def fit(self, df_features: pd.DataFrame, y):
        Z = self.prep.fit_transform(add_engineered_features(df_features))
        self.sel.fit(Z, y)
        self.feature_names_ = self.sel.selected_
        return self

    def transform(self, df_features: pd.DataFrame) -> pd.DataFrame:
        return self.sel.transform(self.prep.transform(add_engineered_features(df_features)))
