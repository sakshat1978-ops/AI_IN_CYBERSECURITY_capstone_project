import os
import sys
import argparse
import json
import logging
import pandas as pd
from sklearn.model_selection import train_test_split

from src.config import load_config, CORE_FEATURES
from src.data_loader import load_dataset, prepare_labels, generate_synthetic_cicids_flows
from src.preprocessor import FlowPreprocessor
from src.models import DualStageNIDS
from src.evaluate import compute_metrics, compute_per_attack_recall, save_evaluation_report
from src.predict import ThreatPredictor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def command_train(args):
    """Executes the full dual-stage training and artifact generation pipeline."""
    cfg = load_config()
    data_path = args.data or cfg["paths"]["raw_data_dir"]
    models_dir = cfg["paths"]["models_dir"]
    sample_size = args.samples or cfg["training"]["sample_size"]

    logger.info("=== Starting Dual-Stage NIDS Training Pipeline ===")
    
    # 1. Load Data
    df = load_dataset(data_path, max_rows=sample_size, random_state=cfg["training"]["random_state"])
    df = prepare_labels(df, cfg["attack_taxonomy"])

    y_binary = df["is_attack"].values
    y_multi = df["attack_category"].values
    X_raw = df.drop(columns=["Label", "is_attack", "attack_category"])

    # 2. Train / Test Split
    logger.info("Splitting dataset into stratified train and test sets (75/25)...")
    X_train, X_test, y_bin_train, y_bin_test, y_mul_train, y_mul_test = train_test_split(
        X_raw, y_binary, y_multi, test_size=cfg["training"]["test_size"],
        stratify=y_binary, random_state=cfg["training"]["random_state"]
    )

    # 3. Fit Preprocessor
    logger.info("Fitting feature preprocessor...")
    preprocessor = FlowPreprocessor(
        port_bins=cfg["feature_engineering"]["port_bins"],
        port_labels=cfg["feature_engineering"]["port_labels"]
    )
    X_tr_trans = preprocessor.fit_transform(X_train)
    X_te_trans = preprocessor.transform(X_test)

    prep_path = os.path.join(models_dir, "preprocessor.joblib")
    preprocessor.save(prep_path)
    logger.info(f"Preprocessor saved to {prep_path}")

    # 4. Train Dual-Stage Models
    s1_cfg = cfg["stage1_binary"]
    s2_cfg = cfg["stage2_multiclass"]

    model = DualStageNIDS(
        stage1_model_type=s1_cfg["model_type"],
        stage1_params=s1_cfg["params"],
        stage2_model_type=s2_cfg["model_type"],
        stage2_params=s2_cfg["params"],
        binary_threshold=s1_cfg["threshold"]
    )
    model.fit(X_tr_trans, y_bin_train, y_mul_train)

    model_path = os.path.join(models_dir, "dual_stage_model.joblib")
    model.save(model_path)

    # 5. Evaluation
    logger.info("Running evaluation on test split...")
    bin_preds, atk_probs, multi_preds = model.predict(X_te_trans)

    metrics = compute_metrics(y_bin_test, bin_preds, atk_probs)
    per_attack = compute_per_attack_recall(y_mul_test, multi_preds)

    print("\n" + "=" * 50)
    print("      STAGE 1: BINARY DETECTION METRICS")
    print("=" * 50)
    for k, v in metrics.items():
        print(f"  {k.replace('_', ' ').title():<20}: {v:.4f}")

    print("\n" + "=" * 50)
    print("      STAGE 2: MULTI-CLASS ATTACK BREAKDOWN")
    print("=" * 50)
    print(per_attack.to_string(index=False))
    print("=" * 50 + "\n")

    save_evaluation_report(metrics, per_attack, cfg["paths"]["reports_dir"])
    logger.info("Training pipeline completed successfully!")


def command_generate_samples(args):
    """Generates a dedicated test sample CSV for testing and demo."""
    cfg = load_config()
    out_path = args.output or cfg["paths"]["sample_flows"]
    n_samples = args.count or 100
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    
    logger.info(f"Generating {n_samples} benchmark sample flows...")
    df = generate_synthetic_cicids_flows(n_samples=n_samples)
    df.to_csv(out_path, index=False)
    logger.info(f"Saved benchmark sample flows to {out_path}")


def command_demo(args):
    """Runs a quick live terminal defense/viva simulation."""
    predictor = ThreatPredictor()
    if not predictor.is_ready:
        logger.error("Models not found. Training quick benchmark model first...")
        command_train(argparse.Namespace(data=None, samples=5000))
        predictor = ThreatPredictor()

    cfg = load_config()
    telemetry_path = cfg["paths"].get("telemetry_stream", "data/network_telemetry_stream.csv")
    if not os.path.exists(telemetry_path):
        telemetry_path = cfg["paths"].get("primary_dataset", "data/cicids2017_cleaned.csv")

    df_samples = pd.read_csv(telemetry_path).head(5)
    print("\n" + "=" * 65)
    print("   AI-POWERED NIDS: LIVE TRAFFIC FLOW INFERENCE DEMO")
    print("=" * 65)

    results = predictor.predict_batch(df_samples)
    for res in results:
        v_color = "\033[92m" if res["verdict"] == "NORMAL" else "\033[91m"
        reset = "\033[0m"
        print(f"Flow #{res['index'] + 1}:")
        print(f"  Verdict       : {res['verdict']}")
        print(f"  Threat Score  : {res['threat_score']}/100")
        print(f"  Classification: {res['attack_category']} [{res['severity']}]")
        print(f"  Action        : {res['recommended_action']}")
        print(f"  Mitigation    : {res['mitigation_strategy']}")
        print("-" * 65)


def main():
    parser = argparse.ArgumentParser(description="Capstone Project: AI-Powered Network Intrusion Detection System")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # train command
    train_parser = subparsers.add_parser("train", help="Train the dual-stage NIDS pipeline")
    train_parser.add_argument("--data", type=str, default=None, help="Path to raw CSV or folder")
    train_parser.add_argument("--samples", type=int, default=None, help="Max rows to train on")

    # demo command
    subparsers.add_parser("demo", help="Run a terminal defense demo with sample flows")

    # generate-samples command
    gen_parser = subparsers.add_parser("generate-samples", help="Generate benchmark sample CSV")
    gen_parser.add_argument("--output", type=str, default=None, help="Output CSV path")
    gen_parser.add_argument("--count", type=int, default=100, help="Number of flow samples")

    args = parser.parse_args()

    if args.command == "train":
        command_train(args)
    elif args.command == "demo":
        command_demo(args)
    elif args.command == "generate-samples":
        command_generate_samples(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
