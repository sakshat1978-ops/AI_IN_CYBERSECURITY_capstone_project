import os
import json
import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, Optional
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, classification_report,
    confusion_matrix
)

logger = logging.getLogger(__name__)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_proba: Optional[np.ndarray] = None) -> Dict[str, float]:
    """Computes comprehensive binary classification metrics."""
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
    }
    if y_proba is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
            metrics["pr_auc"] = float(average_precision_score(y_true, y_proba))
        except Exception:
            metrics["roc_auc"] = 0.0
            metrics["pr_auc"] = 0.0
    return metrics


def compute_per_attack_recall(
    y_true_categories: np.ndarray,
    y_pred_categories: np.ndarray
) -> pd.DataFrame:
    """
    Computes recall for each distinct attack type.
    """
    df_eval = pd.DataFrame({
        "true": y_true_categories,
        "pred": y_pred_categories
    })
    
    # Filter only attacks
    df_attacks = df_eval[df_eval["true"] != "Normal"]
    results = []

    for cat, group in df_attacks.groupby("true"):
        total = len(group)
        # Correctly detected if predicted as anything other than 'Normal' (and ideally matching category)
        detected_as_attack = (group["pred"] != "Normal").sum()
        exact_match = (group["pred"] == cat).sum()
        results.append({
            "Attack Category": cat,
            "Total Flows": total,
            "Detected as Threat (%)": round((detected_as_attack / total) * 100, 2),
            "Exact Category Match (%)": round((exact_match / total) * 100, 2)
        })

    df_out = pd.DataFrame(results).sort_values("Total Flows", ascending=False)
    return df_out


def save_evaluation_report(
    metrics: Dict[str, Any],
    per_attack_df: pd.DataFrame,
    output_dir: str = "docs"
) -> str:
    """Saves metrics summary as a clean JSON file and markdown summary table."""
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "evaluation_metrics.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    csv_path = os.path.join(output_dir, "per_attack_breakdown.csv")
    per_attack_df.to_csv(csv_path, index=False)
    logger.info(f"Evaluation artifacts saved to {json_path} and {csv_path}")
    return json_path
