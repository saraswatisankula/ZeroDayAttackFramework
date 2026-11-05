"""Central configuration for the Zero-Day Attack Framework ML package."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"
for _p in (DATA_DIR, MODEL_DIR, RESULTS_DIR):
    _p.mkdir(parents=True, exist_ok=True)

SEED = 42
LABEL_COL = "Label"
BENIGN_NAMES = {"benign", "normal", "background-normal"}

# Canonical attack-family names (CIC-IDS2017 raw labels -> family)
FAMILY_MAP = {
    "dos hulk": "DoS", "dos goldeneye": "DoS", "dos slowloris": "DoS",
    "dos slowhttptest": "DoS", "ddos": "DDoS",
    "portscan": "PortScan",
    "ftp-patator": "BruteForce", "ssh-patator": "BruteForce",
    "bot": "Botnet", "botnet": "Botnet",
    "web attack \x96 brute force": "WebAttack", "web attack – brute force": "WebAttack",
    "web attack \x96 xss": "WebAttack", "web attack – xss": "WebAttack",
    "web attack \x96 sql injection": "WebAttack", "web attack – sql injection": "WebAttack",
    "web attack brute force": "WebAttack", "web attack xss": "WebAttack",
    "web attack sql injection": "WebAttack",
    "infiltration": "Infiltration", "heartbleed": "Heartbleed",
}

# Dataset download pages (official sources)
DATASET_LINKS = {
    "CIC-IDS2017": "https://www.unb.ca/cic/datasets/ids-2017.html",
    "CTU-13": "https://www.stratosphereips.org/datasets-ctu13",
    "USTC-TFC2016": "https://github.com/yungshenglu/USTC-TFC2016",
}

# Severity bands for risk score (0-100)
SEVERITY_BANDS = [(90, "Critical"), (70, "High"), (50, "Medium"), (0, "Low")]
