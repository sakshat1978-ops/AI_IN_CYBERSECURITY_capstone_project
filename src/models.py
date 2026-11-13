import os
import time
import logging
import joblib
import numpy as np
from typing import Dict, Any, Tuple, Optional
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

logger = logging.getLogger(__name__)


def create_classifier(model_type: str, params: Optional[Dict[str, Any]] = None):
    """Instantiates a classifier according to model_type and parameters."""
    params = params or {}
    model_type = model_type.lower()

    if model_type in ["decision_tree", "dt"]:
        default_params = {"max_depth": 12, "class_weight": "balanced", "random_state": 42}
        default_params.update(params)
        return DecisionTreeClassifier(**default_params)

    elif model_type in ["random_forest", "rf"]:
        default_params = {"n_estimators": 100, "max_depth": 15, "class_weight": "balanced", "random_state": 42, "n_jobs": -1}
        default_params.update(params)
        return RandomForestClassifier(**default_params)

    elif model_type in ["mlp", "neural_net", "neural_network"]:
        default_params = {"hidden_layer_sizes": (64, 32), "early_stopping": True, "max_iter": 200, "random_state": 42}
        default_params.update(params)
        return MLPClassifier(**default_params)

    elif model_type in ["logistic_regression", "lr"]:
        default_params = {"max_iter": 1000, "class_weight": "balanced", "random_state": 42}
        default_params.update(params)
        return LogisticRegression(**default_params)

    else:
        raise ValueError(f"Unsupported model type: {model_type}")


class DualStageNIDS:
    """
    Dual-Stage Network Intrusion Detection System.
    - Stage 1: High-throughput Binary Gate (Normal vs Attack).
    - Stage 2: Fine-grained Multi-Class Classifier (identifies exact attack taxonomy).
    """

    def __init__(
        self,
        stage1_model_type: str = "decision_tree",
        stage1_params: Optional[Dict[str, Any]] = None,
        stage2_model_type: str = "random_forest",
        stage2_params: Optional[Dict[str, Any]] = None,
        binary_threshold: float = 0.50
    ):
        self.stage1_model = create_classifier(stage1_model_type, stage1_params)
        self.stage2_model = create_classifier(stage2_model_type, stage2_params)
        self.binary_threshold = binary_threshold
        self.is_fitted = False
        self.stage2_classes_: np.ndarray = np.array([])

    def fit(self, X_train: np.ndarray, y_binary_train: np.ndarray, y_multi_train: np.ndarray):
        """
        Trains Stage 1 on all traffic flows, and Stage 2 specifically on the malicious traffic.
        """
        logger.info("Training Stage 1 (Binary Gate: Normal vs Suspicious)...")
        t0 = time.perf_counter()
        self.stage1_model.fit(X_train, y_binary_train)
        stage1_time = time.perf_counter() - t0
        logger.info(f"Stage 1 trained in {stage1_time:.2f} seconds.")

        # Train Stage 2 only on attack flows
        attack_mask = (y_binary_train == 1)
        if attack_mask.sum() == 0:
            logger.warning("No attack samples present in training set for Stage 2.")
            self.stage2_classes_ = np.array(["Unknown Threat"])
        else:
            X_attacks = X_train[attack_mask]
            y_attacks = y_multi_train[attack_mask]

            logger.info(f"Training Stage 2 (Multi-Class Taxonomy) on {len(X_attacks)} attack samples...")
            t0 = time.perf_counter()
            self.stage2_model.fit(X_attacks, y_attacks)
            stage2_time = time.perf_counter() - t0
            self.stage2_classes_ = self.stage2_model.classes_
            logger.info(f"Stage 2 trained in {stage2_time:.2f} seconds across classes: {list(self.stage2_classes_)}")

        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Runs dual-stage inference:
        Returns:
            - binary_preds (0 for Normal, 1 for Attack)
            - attack_probs (Probability of being an attack)
            - final_categories (Array of 'Normal' or identified attack taxonomy strings)
        """
        if not self.is_fitted:
            raise RuntimeError("DualStageNIDS models are not fitted!")

        # Stage 1: Binary evaluation
        s1_probas = self.stage1_model.predict_proba(X)[:, 1]
        binary_preds = (s1_probas >= self.binary_threshold).astype(int)

        final_categories = np.array(["Normal"] * len(X), dtype=object)
        attack_indices = np.where(binary_preds == 1)[0]

        # Stage 2: Route attacks to multi-class identification
        if len(attack_indices) > 0 and len(self.stage2_classes_) > 0:
            X_flagged = X[attack_indices]
            s2_preds = self.stage2_model.predict(X_flagged)
            final_categories[attack_indices] = s2_preds

        return binary_preds, s1_probas, final_categories

    def save(self, filepath: str) -> None:
        """Saves the dual-stage models to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        logger.info(f"Saved dual-stage model artifact to {filepath}")

    @classmethod
    def load(cls, filepath: str) -> "DualStageNIDS":
        """Loads a pre-trained DualStageNIDS instance."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found at {filepath}")
        return joblib.load(filepath)
