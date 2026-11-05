"""Anomaly scoring (calibrated Isolation Forest) and the Hybrid IF + XGBoost ensemble."""
import numpy as np
from sklearn.base import BaseEstimator
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold
from sklearn.metrics import precision_recall_curve
from xgboost import XGBClassifier


def best_threshold(y_true, score):
    """Threshold maximising F1 on the given set (automated threshold optimisation)."""
    p, r, t = precision_recall_curve(y_true, score)
    f1 = 2 * p[:-1] * r[:-1] / np.maximum(p[:-1] + r[:-1], 1e-12)
    if len(t) == 0:
        return 0.5
    return float(t[int(np.nanargmax(f1))])


class AnomalyScorer:
    """Isolation Forest trained on benign flows only. score() returns the empirical percentile of the
    raw anomaly score w.r.t. held-out benign scores -> value in [0,1], ~uniform for normal traffic."""

    def __init__(self, n_estimators=200, contamination="auto", seed=42, n_jobs=-1):
        self.n_estimators, self.contamination, self.seed, self.n_jobs = n_estimators, contamination, seed, n_jobs

    def _new(self):
        return IsolationForest(n_estimators=self.n_estimators, contamination=self.contamination,
                               random_state=self.seed, n_jobs=self.n_jobs)

    def fit(self, X_benign, oof_folds=3):
        Xb = np.asarray(X_benign)
        self.iforest_ = self._new().fit(Xb)
        oof = np.zeros(len(Xb))                       # out-of-fold benign scores -> unbiased calibration
        for tr, te in KFold(oof_folds, shuffle=True, random_state=self.seed).split(Xb):
            oof[te] = -self._new().fit(Xb[tr]).score_samples(Xb[te])
        self.oof_benign_scores_ = oof
        self.calib_ = np.sort(oof)
        return self

    def raw(self, X):
        return -self.iforest_.score_samples(np.asarray(X))

    def score(self, X):
        return np.searchsorted(self.calib_, self.raw(X), side="right") / len(self.calib_)


class HybridIFXGB(BaseEstimator):
    """Hybrid ensemble:
         s_anom = percentile score of an Isolation Forest trained on benign traffic (unsupervised)
         p_sup  = XGBoost probability on [features, s_anom]   (supervised, SMOTE-balanced)
         score  = w * p_sup + (1 - w) * s_anom
    w and the decision threshold are tuned on a validation set containing a *pseudo-unknown* attack
    family so the blend learns how much to trust the anomaly branch for unseen attacks."""

    def __init__(self, w=0.6, use_smote=True, xgb_params=None, if_estimators=200, seed=42, n_jobs=-1):
        self.w, self.use_smote, self.xgb_params = w, use_smote, xgb_params
        self.if_estimators, self.seed, self.n_jobs = if_estimators, seed, n_jobs
        self.threshold_ = 0.5

    def _augment(self, X, s):
        return np.column_stack([np.asarray(X), s])

    def fit(self, X, y):
        X, y = np.asarray(X), np.asarray(y).astype(int)
        self.anom_ = AnomalyScorer(self.if_estimators, seed=self.seed, n_jobs=self.n_jobs).fit(X[y == 0])
        s = self.anom_.score(X)
        # benign rows were used to fit the forest -> replace their score with the out-of-fold score
        s = s.copy()
        s[y == 0] = np.searchsorted(self.anom_.calib_, self.anom_.oof_benign_scores_, side="right") / len(self.anom_.calib_)
        Xa = self._augment(X, s)
        if self.use_smote and 0 < min(np.bincount(y)) < max(np.bincount(y)):
            from imblearn.over_sampling import SMOTE
            k = max(1, min(5, int(min(np.bincount(y))) - 1))
            Xa, y = SMOTE(k_neighbors=k, random_state=self.seed).fit_resample(Xa, y)
        params = dict(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.8,
                      colsample_bytree=0.8, eval_metric="logloss", random_state=self.seed,
                      n_jobs=self.n_jobs, tree_method="hist")
        params.update(self.xgb_params or {})
        self.xgb_ = XGBClassifier(**params).fit(Xa, y)
        return self

    def components(self, X):
        s = self.anom_.score(X)
        return self.xgb_.predict_proba(self._augment(X, s))[:, 1], s

    def decision_score(self, X, w=None):
        p, s = self.components(X)
        w = self.w if w is None else w
        return w * p + (1 - w) * s

    def tune_blend(self, X_val, y_val, grid=np.linspace(0, 1, 11)):
        """Choose w and threshold maximising F1 on validation data."""
        p, s = self.components(X_val)
        best = (-1, self.w, 0.5)
        for w in grid:
            sc = w * p + (1 - w) * s
            t = best_threshold(y_val, sc)
            pred = sc >= t
            tp = np.sum(pred & (y_val == 1)); fp = np.sum(pred & (y_val == 0)); fn = np.sum(~pred & (y_val == 1))
            f1 = 2 * tp / max(2 * tp + fp + fn, 1)
            if f1 > best[0]:
                best = (f1, float(w), t)
        _, self.w, self.threshold_ = best
        return self

    def predict(self, X):
        return (self.decision_score(X) >= self.threshold_).astype(int)
