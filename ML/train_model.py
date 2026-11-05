"""Training + experiment protocols.

Protocols
  * zero-day  : one attack family is completely hidden from training and used only for testing.
  * known     : random stratified split of all families (classic IDS evaluation).
Production training (`python train_model.py --dataset cicids2017`) trains the Hybrid IF+XGBoost model on
all families, tunes blend weight + threshold on a validation set containing a pseudo-unknown family,
then saves ML/models/zero_day_bundle.joblib.
"""
import argparse, json, time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.model_selection import RandomizedSearchCV
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

from config import LABEL_COL, MODEL_DIR, SEED
from dataset_loader import load_dataset
from preprocessing import clean_dataframe
from feature_engineering import FeaturePipeline
from anomaly_detection import AnomalyScorer, HybridIFXGB, best_threshold
from evaluate_model import evaluate


# ---------------------------------------------------------------- splitting
def _split3(idx, rng, fr=(0.6, 0.2)):
    idx = rng.permutation(idx)
    a, b = int(len(idx) * fr[0]), int(len(idx) * (fr[0] + fr[1]))
    return idx[:a], idx[a:b], idx[b:]


def make_splits(labels: pd.Series, target=None, seed=SEED):
    rng = np.random.default_rng(seed)
    labels = labels.reset_index(drop=True)
    b_tr, b_va, b_te = _split3(np.where(labels == "BENIGN")[0], rng)
    attacks = sorted(f for f in labels.unique() if f != "BENIGN")
    known = [f for f in attacks if f != target]
    pseudo = known[len(known) // 2] if len(known) >= 2 else None
    tr, va, te = [b_tr], [b_va], [b_te]
    for f in known:
        idx = np.where(labels == f)[0]
        if f == pseudo:
            va.append(idx)                    # pseudo-unknown family: validation only
            continue
        a, b, c = _split3(idx, rng)
        tr.append(a); va.append(b)
        if target is None:
            te.append(c)
    if target is not None:
        te.append(np.where(labels == target)[0])
    return {"train": np.concatenate(tr), "val": np.concatenate(va), "test": np.concatenate(te),
            "pseudo_unknown": pseudo, "known": known}


# ---------------------------------------------------------------- tuning
def tune_xgb(X, y, n_iter=8, cv=3, seed=SEED, max_rows=20000):
    idx = np.random.default_rng(seed).choice(len(X), min(max_rows, len(X)), replace=False)
    space = {"n_estimators": [150, 300, 500], "max_depth": [3, 4, 6, 8], "learning_rate": [0.03, 0.05, 0.1, 0.2],
             "subsample": [0.7, 0.85, 1.0], "colsample_bytree": [0.6, 0.8, 1.0], "min_child_weight": [1, 3, 5]}
    rs = RandomizedSearchCV(XGBClassifier(tree_method="hist", eval_metric="logloss", random_state=seed, n_jobs=-1),
                            space, n_iter=n_iter, cv=cv, scoring="f1", random_state=seed, n_jobs=1)
    rs.fit(np.asarray(X)[idx], np.asarray(y)[idx])
    return rs.best_params_


# ---------------------------------------------------------------- experiment
def prepare(df: pd.DataFrame) -> pd.DataFrame:
    return clean_dataframe(df).reset_index(drop=True)


def run_experiment(df: pd.DataFrame, target=None, seed=SEED, tune=False, k_features=40, max_train=60000):
    """df must already be cleaned (prepare). Returns {model_name: metrics_dict}."""
    labels = df[LABEL_COL]
    sp = make_splits(labels, target, seed)
    y_all = (labels != "BENIGN").astype(int).to_numpy()
    feats = df.drop(columns=[LABEL_COL])

    tr = sp["train"]
    if len(tr) > max_train:
        tr = np.random.default_rng(seed).choice(tr, max_train, replace=False)
    pipe = FeaturePipeline(k=k_features, seed=seed).fit(feats.iloc[tr], y_all[tr])
    Xtr, Xva, Xte = (pipe.transform(feats.iloc[sp[s] if s != "train" else tr]).to_numpy()
                     for s in ("train", "val", "test"))
    ytr, yva, yte = y_all[tr], y_all[sp["val"]], y_all[sp["test"]]

    xgb_params = tune_xgb(Xtr, ytr, seed=seed) if tune else None
    results, timing = {}, {}

    def finish(name, score_val, score_test, t0):
        thr = best_threshold(yva, score_val)
        results[name] = evaluate(yte, score_test, thr)
        results[name]["threshold"] = float(thr)
        timing[name] = round(time.time() - t0, 1)

    # --- unsupervised baselines (trained on benign only)
    t0 = time.time()
    iso = AnomalyScorer(200, seed=seed).fit(Xtr[ytr == 0], oof_folds=2)
    finish("Isolation Forest", iso.score(Xva), iso.score(Xte), t0)

    t0 = time.time()
    rng = np.random.default_rng(seed)
    Xb = Xtr[ytr == 0]
    Xb = Xb[rng.choice(len(Xb), min(4000, len(Xb)), replace=False)]
    oc = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(Xb)
    finish("One-Class SVM", -oc.decision_function(Xva), -oc.decision_function(Xte), t0)

    # --- supervised baselines (SMOTE-balanced)
    Xs, ys = Xtr, ytr
    if 0 < min(np.bincount(ytr)) < max(np.bincount(ytr)):
        from imblearn.over_sampling import SMOTE
        kn = max(1, min(5, int(min(np.bincount(ytr))) - 1))
        Xs, ys = SMOTE(k_neighbors=kn, random_state=seed).fit_resample(Xtr, ytr)
    xp = dict(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8)
    xp.update(xgb_params or {})
    sup = {
        "Random Forest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=seed),
        "XGBoost": XGBClassifier(**xp, tree_method="hist", eval_metric="logloss", random_state=seed, n_jobs=-1),
        "LightGBM": LGBMClassifier(n_estimators=300, learning_rate=0.1, num_leaves=63, subsample=0.8,
                                   colsample_bytree=0.8, random_state=seed, verbose=-1, n_jobs=-1),
    }
    for name, m in sup.items():
        t0 = time.time()
        m.fit(Xs, ys)
        finish(name, m.predict_proba(Xva)[:, 1], m.predict_proba(Xte)[:, 1], t0)

    # --- proposed hybrid
    t0 = time.time()
    hyb = HybridIFXGB(xgb_params=xgb_params, seed=seed).fit(Xtr, ytr).tune_blend(Xva, yva)
    results["Hybrid IF + XGBoost (Proposed)"] = evaluate(yte, hyb.decision_score(Xte), hyb.threshold_)
    results["Hybrid IF + XGBoost (Proposed)"]["threshold"] = hyb.threshold_
    results["Hybrid IF + XGBoost (Proposed)"]["blend_w"] = hyb.w
    timing["Hybrid IF + XGBoost (Proposed)"] = round(time.time() - t0, 1)
    return results, {"target": target, "pseudo_unknown": sp["pseudo_unknown"], "n_train": int(len(tr)),
                     "n_val": int(len(sp["val"])), "n_test": int(len(sp["test"])), "timing_s": timing}


# ---------------------------------------------------------------- production training
def train_production(df, out_path=None, tune=False, seed=SEED, k_features=40, max_train=200000):
    df = prepare(df)
    labels = df[LABEL_COL]
    sp = make_splits(labels, target=None, seed=seed)
    y_all = (labels != "BENIGN").astype(int).to_numpy()
    feats = df.drop(columns=[LABEL_COL])
    tr = sp["train"]
    if len(tr) > max_train:
        tr = np.random.default_rng(seed).choice(tr, max_train, replace=False)
    # include the pseudo-unknown family in the final fit, but not in the tuning fit
    pseudo_idx = np.where(labels == sp["pseudo_unknown"])[0] if sp["pseudo_unknown"] else np.array([], int)
    full_tr = np.concatenate([tr, pseudo_idx])

    pipe = FeaturePipeline(k=k_features, seed=seed).fit(feats.iloc[full_tr], y_all[full_tr])
    X = lambda i: pipe.transform(feats.iloc[i]).to_numpy()
    Xtr, Xva, Xte, Xfull = X(tr), X(sp["val"]), X(sp["test"]), X(full_tr)
    xgb_params = tune_xgb(Xtr, y_all[tr], seed=seed) if tune else None

    tuner = HybridIFXGB(xgb_params=xgb_params, seed=seed).fit(Xtr, y_all[tr]).tune_blend(Xva, y_all[sp["val"]])
    final = HybridIFXGB(w=tuner.w, xgb_params=xgb_params, seed=seed).fit(Xfull, y_all[full_tr])
    final.threshold_ = tuner.threshold_
    metrics = evaluate(y_all[sp["test"]], final.decision_score(Xte), final.threshold_)

    bundle = {"pipeline": pipe, "model": final, "families": sorted(labels.unique()),
              "feature_names": pipe.feature_names_, "metrics_known_split": metrics,
              "xgb_params": xgb_params, "trained_rows": int(len(full_tr)), "seed": seed}
    out_path = out_path or MODEL_DIR / "zero_day_bundle.joblib"
    joblib.dump(bundle, out_path)
    return bundle, out_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Train the Hybrid IF+XGBoost zero-day detector")
    ap.add_argument("--dataset", default="cicids2017", help="cicids2017 | ctu13 | ustc | synthetic")
    ap.add_argument("--folder", default=None)
    ap.add_argument("--tune", action="store_true", help="RandomizedSearchCV for XGBoost")
    ap.add_argument("--out", default=None)
    ap.add_argument("--max-train", type=int, default=200000)
    a = ap.parse_args()
    raw = load_dataset(a.dataset, a.folder)
    bundle, path = train_production(raw, a.out, a.tune, max_train=a.max_train)
    print(json.dumps({k: (round(v, 4) if isinstance(v, float) else v)
                      for k, v in bundle["metrics_known_split"].items()}, indent=2))
    print("saved ->", path)
