import os
import joblib
import numpy as np
import pandas as pd
from typing import Tuple, List, Optional
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.config import CORE_FEATURES


class FlowPreprocessor(BaseEstimator, TransformerMixin):
    """
    Production-grade preprocessing pipeline for network flow intrusion detection.
    Features:
    - Automatically buckets 'Destination Port' into well_known, registered, dynamic.
    - Imputes missing continuous metrics with median statistics.
    - Scales numeric flow statistics via StandardScaler.
    - Serializes and restores pipelines safely without data leakage.
    """

    def __init__(self, port_bins=None, port_labels=None):
        self.port_bins = port_bins or [-1, 1023, 49151, 65535]
        self.port_labels = port_labels or ["well_known", "registered", "dynamic"]
        self.pipeline: Optional[ColumnTransformer] = None
        self.feature_names_: List[str] = []
        self.expected_columns_: List[str] = []

    def _prepare_columns(self, X: pd.DataFrame) -> pd.DataFrame:
        df = X.copy()
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Ensure Destination Port exists
        if "Destination Port" not in df.columns:
            df["Destination Port"] = 0

        # Bucket Destination Port
        df["Port Class"] = pd.cut(
            df["Destination Port"].astype(float),
            bins=self.port_bins,
            labels=self.port_labels
        ).astype(str).fillna("well_known")

        # Fill any missing expected core columns with 0
        for col in self.expected_columns_:
            if col not in df.columns and col != "Port Class":
                df[col] = 0.0

        return df

    def fit(self, X: pd.DataFrame, y=None):
        X_df = X.copy()
        X_df.columns = X_df.columns.str.strip()
        self.expected_columns_ = [c for c in X_df.columns if c not in ["Label", "is_attack", "attack_category"]]

        prepared = self._prepare_columns(X_df[self.expected_columns_])
        cat_cols = ["Port Class"]
        num_cols = [c for c in prepared.columns if c not in cat_cols]

        self.pipeline = ColumnTransformer(
            transformers=[
                ("num", Pipeline([
                    ("imputer", SimpleImputer(strategy="median")),
                    ("scaler", StandardScaler())
                ]), num_cols),
                ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), cat_cols),
            ],
            sparse_threshold=0
        )

        self.pipeline.fit(prepared)
        self.feature_names_ = list(self.pipeline.get_feature_names_out())
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        if self.pipeline is None:
            raise RuntimeError("Preprocessor has not been fitted yet!")
        prepared = self._prepare_columns(X)
        return self.pipeline.transform(prepared)

    def fit_transform(self, X: pd.DataFrame, y=None) -> np.ndarray:
        return self.fit(X, y).transform(X)

    def save(self, filepath: str) -> None:
        """Saves the fitted preprocessor to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "FlowPreprocessor":
        """Loads a pre-trained FlowPreprocessor instance."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Preprocessor file not found at {filepath}")
        return joblib.load(filepath)
