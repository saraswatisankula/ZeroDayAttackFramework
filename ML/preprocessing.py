"""Cleaning + scaling. The Preprocessor is fit on TRAIN data only and persisted for inference."""
import numpy as np
import pandas as pd
from config import LABEL_COL


def clean_dataframe(df: pd.DataFrame, label_col: str = LABEL_COL) -> pd.DataFrame:
    """Strip headers, drop non-numeric cols, inf->NaN, drop duplicates & rows without label."""
    df = df.copy()
    df.columns = [str(c).strip() for c in df.columns]
    df = df.dropna(subset=[label_col])
    y = df[label_col]
    X = df.drop(columns=[label_col]).apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.dropna(axis=1, how="all")
    out = pd.concat([X, y], axis=1).drop_duplicates().reset_index(drop=True)
    return out


def signed_log1p(a: np.ndarray) -> np.ndarray:
    return np.sign(a) * np.log1p(np.abs(a))


class Preprocessor:
    """median-impute -> winsorise (0.1/99.9 pct) -> signed log1p -> standardise.
    Constant columns are dropped. Missing columns at inference are filled with the train median."""

    def __init__(self, lo_q=0.001, hi_q=0.999):
        self.lo_q, self.hi_q = lo_q, hi_q

    def fit(self, X: pd.DataFrame):
        X = X.replace([np.inf, -np.inf], np.nan)
        keep = [c for c in X.columns if X[c].nunique(dropna=True) > 1]
        X = X[keep]
        self.columns_ = keep
        self.median_ = X.median()
        self.lo_ = X.quantile(self.lo_q)
        self.hi_ = X.quantile(self.hi_q)
        Z = signed_log1p(self._clip(X.fillna(self.median_)).to_numpy(float))
        self.mean_ = Z.mean(0)
        self.std_ = Z.std(0)
        self.std_[self.std_ == 0] = 1.0
        return self

    def _clip(self, X):
        return X.clip(self.lo_, self.hi_, axis=1)

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        X = X.copy()
        X.columns = [str(c).strip() for c in X.columns]
        X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        for c in self.columns_:
            if c not in X:
                X[c] = np.nan
        X = X[self.columns_].fillna(self.median_)
        Z = (signed_log1p(self._clip(X).to_numpy(float)) - self.mean_) / self.std_
        return pd.DataFrame(Z, columns=self.columns_, index=X.index)

    def fit_transform(self, X):
        return self.fit(X).transform(X)
