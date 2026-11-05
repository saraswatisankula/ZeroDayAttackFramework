"""Compare all models under the zero-day protocol (leave-one-attack-family-out) and optionally against
the base paper's reported error rate.

  python model_compare.py --dataset cicids2017 --folder data/CIC-IDS2017 --tune
  python model_compare.py --dataset synthetic              # smoke test only, NOT a research result
  python model_compare.py --dataset cicids2017 --paper-error 0.0xx   # error rate quoted in the base paper
"""
import argparse, json
import pandas as pd

from config import RESULTS_DIR, LABEL_COL
from dataset_loader import load_dataset
from train_model import prepare, run_experiment

COLS = ["Accuracy", "Precision", "Recall", "F1 Score", "Error Rate"]


def to_markdown(df):
    head = "| " + " | ".join(df.columns) + " |\n|" + "---|" * len(df.columns) + "\n"
    rows = ""
    for _, r in df.iterrows():
        rows += "| " + " | ".join(f"{v:.4f}" if isinstance(v, float) else str(v) for v in r) + " |\n"
    return head + rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--folder", default=None)
    ap.add_argument("--families", nargs="*", default=None, help="attack families to hold out (default: all)")
    ap.add_argument("--tune", action="store_true")
    ap.add_argument("--paper-error", type=float, default=None, help="base-paper error rate (0-1) from its results table")
    ap.add_argument("--max-train", type=int, default=60000)
    a = ap.parse_args()

    df = prepare(load_dataset(a.dataset, a.folder))
    fams = a.families or sorted(f for f in df[LABEL_COL].unique() if f != "BENIGN")
    per_family, meta = [], {}
    for f in fams:
        print(f"== zero-day hold-out: {f}")
        res, info = run_experiment(df, target=f, tune=a.tune, max_train=a.max_train)
        meta[f] = info
        for model, m in res.items():
            per_family.append({"Held-out family": f, "Model": model, **m})
    pf = pd.DataFrame(per_family)
    avg = pf.groupby("Model")[COLS + ["FPR", "MCC", "ROC-AUC", "PR-AUC"]].mean().reset_index()
    avg = avg.sort_values("F1 Score", ascending=False).reset_index(drop=True)

    tag = a.dataset.lower()
    pf.to_csv(RESULTS_DIR / f"{tag}_per_family.csv", index=False)
    avg.to_csv(RESULTS_DIR / f"{tag}_comparison.csv", index=False)
    md = "## Zero-day protocol, mean over held-out families\n\n" + to_markdown(avg[["Model"] + COLS]) + "\n"

    if a.paper_error is not None:
        best = avg[avg["Model"].str.contains("Proposed")].iloc[0]["Error Rate"]
        rel = (a.paper_error - best) / a.paper_error * 100
        md += (f"\nBase paper error rate: {a.paper_error:.4f}; proposed: {best:.4f}; "
               f"relative error reduction: {rel:.1f}% (target >= 10%)\n")
    (RESULTS_DIR / f"{tag}_comparison.md").write_text(md)
    (RESULTS_DIR / f"{tag}_meta.json").write_text(json.dumps(meta, indent=2, default=str))
    print(md)


if __name__ == "__main__":
    main()
