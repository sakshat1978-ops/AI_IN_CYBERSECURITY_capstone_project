import os
import glob
import logging
import numpy as np
import pandas as pd
from typing import Optional, Tuple, List, Dict
from src.config import load_config, CORE_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Strips column names, replaces infinities with NaN, and converts numeric types."""
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    return df


def load_dataset(
    data_path: str,
    max_rows: Optional[int] = 200_000,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Loads one or more CSV files from a file path or folder.
    Cleans column names and replaces infinite values.
    """
    if os.path.isdir(data_path):
        csv_files = sorted(glob.glob(os.path.join(data_path, "*.csv")))
    elif os.path.isfile(data_path):
        csv_files = [data_path]
    else:
        csv_files = []

    if not csv_files:
        logger.warning(f"No CSV files found at '{data_path}'. Generating synthetic fallback dataset.")
        return generate_synthetic_cicids_flows(n_samples=5000)

    logger.info(f"Loading {len(csv_files)} CSV file(s) from {data_path}...")
    dfs = []
    for f in csv_files:
        try:
            temp = pd.read_csv(f, low_memory=False)
            temp = clean_dataframe(temp)
            dfs.append(temp)
            logger.info(f"Loaded {os.path.basename(f)}: shape {temp.shape}")
        except Exception as e:
            logger.error(f"Error reading {f}: {e}")

    if not dfs:
        raise ValueError("Failed to load any valid dataframes.")

    df = pd.concat(dfs, ignore_index=True)
    logger.info(f"Total merged shape before sampling: {df.shape}")

    if max_rows and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=random_state).reset_index(drop=True)
        logger.info(f"Subsampled dataset to {max_rows} rows for high performance.")

    return df


def prepare_labels(df: pd.DataFrame, taxonomy_map: Dict[str, str]) -> pd.DataFrame:
    """
    Standardizes 'Label' column into:
    - 'is_attack' (0 = Normal, 1 = Attack)
    - 'attack_category' (mapped friendly name)
    """
    df = df.copy()
    if "Label" not in df.columns:
        raise KeyError("Dataset must contain a 'Label' column.")

    raw_labels = df["Label"].astype(str).str.strip()
    df["is_attack"] = (raw_labels.str.upper() != "BENIGN").astype(int)
    
    # Map to standardized taxonomy
    df["attack_category"] = raw_labels.map(
        lambda x: taxonomy_map.get(x, taxonomy_map.get(x.strip(), "Unknown Threat"))
    )
    return df


def generate_synthetic_cicids_flows(n_samples: int = 5000) -> pd.DataFrame:
    """
    Generates realistic synthetic flow records mirroring CICIDS2017 feature schema
    across Normal, DDoS, PortScan, SSH-Patator, Web Attacks, and Botnets.
    Allows zero-friction live demonstrations and automated testing.
    """
    np.random.seed(42)
    classes = [
        ("BENIGN", 0.65),
        ("DDoS", 0.12),
        ("PortScan", 0.10),
        ("SSH-Patator", 0.05),
        ("DoS Hulk", 0.04),
        ("Bot", 0.02),
        ("Web Attack - Brute Force", 0.02)
    ]
    labels_chosen = np.random.choice([c[0] for c in classes], size=n_samples, p=[c[1] for c in classes])

    data = {}
    for feat in CORE_FEATURES:
        data[feat] = np.random.exponential(scale=50.0, size=n_samples)

    df = pd.DataFrame(data)
    df["Label"] = labels_chosen

    # Inject domain-specific characteristics
    # PortScan: High packet rate, short duration, wide port distribution
    ps_mask = df["Label"] == "PortScan"
    df.loc[ps_mask, "Destination Port"] = np.random.randint(1, 65535, size=ps_mask.sum())
    df.loc[ps_mask, "Flow Duration"] = np.random.uniform(50, 1500, size=ps_mask.sum())
    df.loc[ps_mask, "Flow Packets/s"] = np.random.uniform(2000, 50000, size=ps_mask.sum())
    df.loc[ps_mask, "SYN Flag Count"] = 1
    df.loc[ps_mask, "ACK Flag Count"] = 0

    # DDoS: Concentrated port 80/443, massive packet length and bulk flow
    ddos_mask = df["Label"] == "DDoS"
    df.loc[ddos_mask, "Destination Port"] = np.random.choice([80, 443, 8080], size=ddos_mask.sum())
    df.loc[ddos_mask, "Flow Bytes/s"] = np.random.uniform(500000, 5000000, size=ddos_mask.sum())
    df.loc[ddos_mask, "Total Fwd Packets"] = np.random.randint(50, 2000, size=ddos_mask.sum())

    # SSH-Patator: Destination port 22, constant flow duration, high forward packets
    ssh_mask = df["Label"] == "SSH-Patator"
    df.loc[ssh_mask, "Destination Port"] = 22
    df.loc[ssh_mask, "Flow Duration"] = np.random.uniform(10000, 30000, size=ssh_mask.sum())
    df.loc[ssh_mask, "Fwd Header Length"] = 32

    # Normal: Well-known ports (80, 443, 53, 8080), balanced forward/backward ratio
    benign_mask = df["Label"] == "BENIGN"
    df.loc[benign_mask, "Destination Port"] = np.random.choice([80, 443, 53, 8080, 21, 25], size=benign_mask.sum())
    df.loc[benign_mask, "Flow Duration"] = np.random.exponential(scale=5000, size=benign_mask.sum())

    return df
