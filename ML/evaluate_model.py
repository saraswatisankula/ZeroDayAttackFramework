"""Metrics used throughout the project (Error Rate = 1 - Accuracy)."""
import numpy as np
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, average_precision_score, matthews_corrcoef,
                             confusion_matrix)


def evaluate(y_true, score, threshold):
    y_true = np.asarray(y_true).astype(int)
    pred = (np.asarray(score) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    acc = accuracy_score(y_true, pred)
    return {
        "Accuracy": acc,
        "Precision": precision_score(y_true, pred, zero_division=0),
        "Recall": recall_score(y_true, pred, zero_division=0),
        "F1 Score": f1_score(y_true, pred, zero_division=0),
        "Error Rate": 1 - acc,
        "FPR": fp / max(fp + tn, 1),
        "MCC": matthews_corrcoef(y_true, pred),
        "ROC-AUC": roc_auc_score(y_true, score) if len(np.unique(y_true)) > 1 else float("nan"),
        "PR-AUC": average_precision_score(y_true, score) if len(np.unique(y_true)) > 1 else float("nan"),
        "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn),
    }
