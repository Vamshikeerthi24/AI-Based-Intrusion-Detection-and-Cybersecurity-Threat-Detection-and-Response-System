import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import pandas as pd
from utils.utils import setup_logging

logger = setup_logging()

OUT = Path('data/flows.parquet')
RAW = Path('data/UNSW_NB15_training-set.csv')
SYNTH = Path('data/synth_flows.parquet')
CAPTURED = Path('data/flows.csv')

KEEP = ['src_ip', 'dst_ip', 'sport', 'dport', 'proto', 'dur', 'sbytes', 'dbytes',
        'pkts', 'state', 'ct_flw_http_mthd', 'ct_state_ttl', 'ct_srv_src', 'label']

def load_unsw(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df = df[KEEP].dropna()
    df['proto'] = df['proto'].astype('category').cat.codes
    df['state'] = df['state'].astype('category').cat.codes
    if df['label'].dtype == object:
        df['label'] = (df['label'] != 'Benign').astype(int)
    return df

def load_captured(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df = df[KEEP].dropna()
    df['proto'] = df['proto'].astype('category').cat.codes
    df['state'] = df['state'].astype('category').cat.codes
    df['label'] = df['label'].astype(int)
    return df

def load_synth(parquet_path: str) -> pd.DataFrame:
    df = pd.read_parquet(parquet_path)
    df = df[KEEP].dropna()
    df['proto'] = df['proto'].astype('category').cat.codes
    df['state'] = df['state'].astype('category').cat.codes
    df['label'] = df['label'].astype(int)
    return df

if __name__ == '__main__':
    if CAPTURED.exists():
        df = load_captured(str(CAPTURED))
        logger.info(f'Loaded captured data from {CAPTURED}')
    elif RAW.exists():
        df = load_unsw(str(RAW))
        logger.info(f'Loaded UNSW data from {RAW}')
    elif SYNTH.exists():
        df = load_synth(str(SYNTH))
        logger.info(f'Loaded synthetic data from {SYNTH}')
    else:
        logger.error('No dataset found')
        raise SystemExit('No dataset found. Run python train/generate_synth.py or python data.py first.')
    df.to_parquet(OUT)
    logger.info(f'Wrote {OUT} with {len(df)} rows')
    print(f'Wrote {OUT} with {len(df)} rows')
