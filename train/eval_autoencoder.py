"""Evaluate trained autoencoder and suggest anomaly thresholds.

Computes reconstruction errors on train/test splits and reports percentiles
that can be used as anomaly thresholds (e.g., 95th, 99th percentiles).

Usage:
    python train/eval_autoencoder.py

Outputs printed summary and writes `results/ae_recon_stats.json`.
"""
from pathlib import Path
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

try:
    import torch
except Exception:
    torch = None

from models.nn_models import DenseAutoencoder


def find_data_path() -> Path:
    candidates = [Path('data/synth_flows.parquet'), Path('data/flows.parquet')]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError('No input data found (looked for synth_flows.parquet or flows.parquet)')


def load_numeric_features(path: Path):
    df = pd.read_parquet(path)
    drop_cols = [c for c in ['label', 'src_ip', 'dst_ip'] if c in df.columns]
    X = df.drop(columns=drop_cols)
    X = X.select_dtypes(include=[np.number]).fillna(0.0)
    return X.astype(np.float32).values


def compute_recon_errors(ae, X):
    if torch is None:
        raise RuntimeError('PyTorch is required to compute reconstructions')
    device = torch.device('cpu')
    ae.to(device)
    ae.eval()
    with torch.no_grad():
        xs = torch.from_numpy(X)
        recon = ae(xs)
        mse = ((recon - xs) ** 2).mean(dim=1).cpu().numpy()
    return mse


def main():
    data_path = find_data_path()
    print(f'Loading data from {data_path}')
    X = load_numeric_features(data_path)
    print(f'Samples: {X.shape[0]}, features: {X.shape[1]}')

    # Load autoencoder model if available
    model_path = Path('models/autoencoder.pth')
    if not model_path.exists():
        print('No autoencoder model found at models/autoencoder.pth')
        return

    if torch is None:
        print('PyTorch not installed; cannot evaluate autoencoder')
        return

    # instantiate model
    ae = DenseAutoencoder(input_dim=X.shape[1], latent_dim=min(32, max(8, X.shape[1]//2)))
    state = torch.load(model_path, map_location='cpu')
    try:
        ae.load_state_dict(state)
    except Exception:
        # If state is not a state_dict, try loading into a wrapper
        try:
            ae.load_state_dict(state['model_state_dict'])
        except Exception:
            print('Could not load model state; aborting')
            return

    # Split
    Xtr, Xte = train_test_split(X, test_size=0.2, random_state=42)

    tr_err = compute_recon_errors(ae, Xtr)
    te_err = compute_recon_errors(ae, Xte)

    stats = {
        'train': {
            'count': int(len(tr_err)),
            'mean': float(tr_err.mean()),
            'std': float(tr_err.std()),
            'p95': float(np.percentile(tr_err, 95)),
            'p99': float(np.percentile(tr_err, 99))
        },
        'test': {
            'count': int(len(te_err)),
            'mean': float(te_err.mean()),
            'std': float(te_err.std()),
            'p95': float(np.percentile(te_err, 95)),
            'p99': float(np.percentile(te_err, 99))
        }
    }

    out_dir = Path('results')
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / 'ae_recon_stats.json'
    with open(out_file, 'w') as f:
        json.dump(stats, f, indent=2)

    print('Autoencoder reconstruction error stats:')
    print(json.dumps(stats, indent=2))
    print('\nSuggested thresholds (percentiles):')
    print(f"Train p95: {stats['train']['p95']:.6f}, p99: {stats['train']['p99']:.6f}")
    print(f"Test  p95: {stats['test']['p95']:.6f}, p99: {stats['test']['p99']:.6f}")


if __name__ == '__main__':
    main()
