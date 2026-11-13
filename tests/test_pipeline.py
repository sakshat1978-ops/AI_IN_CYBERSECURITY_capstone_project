import sys
import os
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import numpy as np
import pandas as pd
from src.data_loader import generate_synthetic_cicids_flows, prepare_labels
from src.preprocessor import FlowPreprocessor
from src.models import DualStageNIDS
from src.config import load_config, CORE_FEATURES
from src.predict import ThreatPredictor


def test_synthetic_data_generator():
    """Validates that synthetic flow generator adheres to standard CICIDS2017 schema."""
    df = generate_synthetic_cicids_flows(n_samples=50)
    assert len(df) == 50
    assert "Label" in df.columns
    assert "Destination Port" in df.columns
    assert df["Destination Port"].isna().sum() == 0


def test_prepare_labels():
    """Validates label mapping into binary and taxonomy categories."""
    cfg = load_config()
    df = generate_synthetic_cicids_flows(n_samples=30)
    df_prepared = prepare_labels(df, cfg["attack_taxonomy"])
    assert "is_attack" in df_prepared.columns
    assert "attack_category" in df_prepared.columns
    assert set(df_prepared["is_attack"].unique()).issubset({0, 1})


def test_preprocessor_pipeline():
    """Validates that preprocessor handles port bucketing and imputation without leakage."""
    df = generate_synthetic_cicids_flows(n_samples=100)
    preprocessor = FlowPreprocessor()
    X_trans = preprocessor.fit_transform(df)
    
    assert X_trans.shape[0] == 100
    assert not np.isnan(X_trans).any()
    assert len(preprocessor.feature_names_) > 0


def test_dual_stage_model():
    """Tests training and prediction on dual-stage model architecture."""
    df = generate_synthetic_cicids_flows(n_samples=120)
    cfg = load_config()
    df_prepared = prepare_labels(df, cfg["attack_taxonomy"])

    preprocessor = FlowPreprocessor()
    X = df_prepared.drop(columns=["Label", "is_attack", "attack_category"])
    X_trans = preprocessor.fit_transform(X)

    y_bin = df_prepared["is_attack"].values
    y_mul = df_prepared["attack_category"].values

    model = DualStageNIDS()
    model.fit(X_trans, y_bin, y_mul)

    bin_preds, probs, cat_preds = model.predict(X_trans[:10])
    assert len(bin_preds) == 10
    assert len(probs) == 10
    assert len(cat_preds) == 10
    assert all(0.0 <= p <= 1.0 for p in probs)
