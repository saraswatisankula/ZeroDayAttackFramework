"""Turn model_compare.py output into LaTeX for the paper.

  python results_to_latex.py --dataset cicids2017 --paper-error 0.0xx --out ../Documentation/Paper

Writes results_table.tex (comparison table) and results_macros.tex (numbers used in the abstract/conclusion).
--paper-error is the error rate (0-1) reported in the base paper; take it from that paper's results table.
"""
import argparse
from pathlib import Path
import pandas as pd
from config import RESULTS_DIR

COLS = ["Accuracy", "Precision", "Recall", "F1 Score", "Error Rate"]


def tex_escape(s):
    return s.replace("&", r"\&").replace("_", r"\_").replace("%", r"\%")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--paper-error", type=float, default=None)
    ap.add_argument("--out", default=str(RESULTS_DIR))
    a = ap.parse_args()
    df = pd.read_csv(RESULTS_DIR / f"{a.dataset.lower()}_comparison.csv")
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)

    best_col = df[COLS].copy()
    lines = [r"\begin{tabular}{lccccc}", r"\hline", "Model & Acc. & Prec. & Rec. & F1 & Err. \\\\", r"\hline"]
    for _, r in df.iterrows():
        cells = []
        for c in COLS:
            v = f"{r[c]:.4f}"
            best = (r[c] == best_col[c].min()) if c == "Error Rate" else (r[c] == best_col[c].max())
            cells.append(rf"\textbf{{{v}}}" if best else v)
        lines.append(tex_escape(r["Model"]) + " & " + " & ".join(cells) + r" \\")
    lines += [r"\hline", r"\end{tabular}"]
    (out / "results_table.tex").write_text("\n".join(lines) + "\n")

    # per-family error-rate table (models x held-out families)
    pf_path = RESULTS_DIR / f"{a.dataset.lower()}_per_family.csv"
    if pf_path.exists():
        pf = pd.read_csv(pf_path)
        piv = pf.pivot_table(index="Model", columns="Held-out family", values="Error Rate").reindex(df["Model"])
        cols = list(piv.columns)
        L = [r"\begin{tabular}{l" + "c" * len(cols) + "}", r"\hline", "Model & " + " & ".join(tex_escape(c) for c in cols) + r" \\", r"\hline"]
        for model, row in piv.iterrows():
            vals = [rf"\textbf{{{v:.3f}}}" if v == piv[c].min() else f"{v:.3f}" for c, v in zip(cols, row)]
            L.append(tex_escape(model) + " & " + " & ".join(vals) + r" \\")
        L += [r"\hline", r"\end{tabular}"]
        (out / "results_perfamily.tex").write_text("\n".join(L) + "\n")

    hyb = df[df["Model"].str.contains("Proposed")].iloc[0]
    base = df[~df["Model"].str.contains("Proposed")].sort_values("Error Rate").iloc[0]
    m = {
        "hybErr": f"{hyb['Error Rate'] * 100:.2f}\\%", "hybFscore": f"{hyb['F1 Score']:.4f}",
        "hybPrec": f"{hyb['Precision']:.4f}", "hybRec": f"{hyb['Recall']:.4f}", "hybAcc": f"{hyb['Accuracy'] * 100:.2f}\\%",
        "bestBaseName": tex_escape(base["Model"]), "bestBaseErr": f"{base['Error Rate'] * 100:.2f}\\%",
        "relRedBase": f"{(base['Error Rate'] - hyb['Error Rate']) / base['Error Rate'] * 100:.1f}\\%",
    }
    if a.paper_error is not None:
        m["paperErr"] = f"{a.paper_error * 100:.2f}\\%"
        m["relRedPaper"] = f"{(a.paper_error - hyb['Error Rate']) / a.paper_error * 100:.1f}\\%"
    (out / "results_macros.tex").write_text("".join(f"\\renewcommand{{\\{k}}}{{{v}}}\n" for k, v in m.items()))
    print("wrote", out / "results_table.tex", "and", out / "results_macros.tex")


if __name__ == "__main__":
    main()
