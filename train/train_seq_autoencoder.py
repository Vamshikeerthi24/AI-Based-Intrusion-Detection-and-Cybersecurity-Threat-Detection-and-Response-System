"""Train a small LSTM sequence autoencoder on synthetic sequence data.

This is a lightweight script intended for smoke-testing the LSTM autoencoder
implementation. It builds short sequences from flows by grouping consecutive
rows per source IP (if available) or by simple sliding windows.
"""
from pathlib import Path
import torch
from torch.utils.data import DataLoader, TensorDataset
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import numpy as np

from models.nn_models import LSTMSeqAutoencoder


def find_data_path() -> Path:
    candidates = [Path('data/synth_flows.parquet'), Path('data/flows.parquet')]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError('No input data found (looked for synth_flows.parquet or flows.parquet)')


def build_sequences(df: pd.DataFrame, seq_len: int = 8) -> np.ndarray:
    # Use numeric columns only
    X = df.select_dtypes(include=[np.number]).fillna(0.0).values.astype(np.float32)
    # Create sliding windows
    if X.shape[0] < seq_len:
        # replicate rows to create one sequence
        pad = np.tile(X, (int(np.ceil(seq_len / max(1, X.shape[0]))), 1))
        X = pad[:seq_len]

    sequences = []
    for i in range(0, max(1, X.shape[0] - seq_len + 1), seq_len):
        seq = X[i:i+seq_len]
        if seq.shape[0] == seq_len:
            sequences.append(seq)
    if not sequences:
        # fallback: reshape into single sequence
        sequences = [X[:seq_len]]
    return np.stack(sequences)


def train_seq_autoencoder(epochs: int = 3, batch_size: int = 8, lr: float = 1e-3):
    data_path = find_data_path()
    print(f'Loading data from {data_path}')
    df = pd.read_parquet(data_path)
    seqs = build_sequences(df, seq_len=8)
    print(f'Built sequences: {seqs.shape}')

    ds = TensorDataset(torch.from_numpy(seqs))
    dl = DataLoader(ds, batch_size=batch_size, shuffle=True)

    feature_dim = seqs.shape[2]
    model = LSTMSeqAutoencoder(feature_dim, hidden_dim=32, latent_dim=16)
    device = torch.device('cpu')
    model.to(device)

    criterion = nn.MSELoss()
    opt = optim.Adam(model.parameters(), lr=lr)

    model.train()
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        batches = 0
        for (batch,) in dl:
            batch = batch.to(device)
            recon = model(batch)
            loss = criterion(recon, batch)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total_loss += loss.item()
            batches += 1
        print(f'Epoch {epoch}/{epochs} - loss: {total_loss / max(1,batches):.6f}')

    Path('models').mkdir(exist_ok=True)
    out_path = Path('models/lstm_seq_autoencoder.pth')
    torch.save(model.state_dict(), out_path)
    print(f'Saved LSTM seq autoencoder to {out_path}')


if __name__ == '__main__':
    train_seq_autoencoder()
"""
Train a small LSTM sequence autoencoder on sequences of flows grouped by `src_ip` (CPU-friendly).
This script constructs short sequences per source IP and trains an LSTM autoencoder.
Saves model to `models/seq_ae.pth` and the scaler to `models/seq_ae_scaler.joblib`.
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import joblib
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from models.nn_models import LSTMSeqAutoencoder
from utils.utils import setup_logging

logger = setup_logging()

MODEL_DIR = Path('models')
MODEL_DIR.mkdir(exist_ok=True)


def load_and_make_sequences(parquet_path: str = 'data/flows.parquet', seq_len: int = 8):
    df = pd.read_parquet(parquet_path)
    drop_cols = [c for c in ['label', 'src_ip', 'dst_ip'] if c in df.columns]
    features = df.drop(columns=drop_cols)

    # We'll group by `src_ip` if present, otherwise use rolling windows
    if 'src_ip' in df.columns:
        seqs = []
        grouped = df.groupby('src_ip')
        for _, group in grouped:
            g = group.drop(columns=drop_cols)
            if len(g) >= seq_len:
                # create sliding windows
                arr = g.values
                for i in range(0, len(arr) - seq_len + 1):
                    seqs.append(arr[i:i+seq_len])
        if not seqs:
            raise RuntimeError('No sequences of required length found in data')
        X = np.stack(seqs)
    else:
        # Fallback: rolling windows over full dataset
        arr = features.values
        seqs = []
        for i in range(0, len(arr) - seq_len + 1):
            seqs.append(arr[i:i+seq_len])
        X = np.stack(seqs)

    return X


def train_sequence_autoencoder(X: np.ndarray, epochs: int = 20, batch_size: int = 64, lr: float = 1e-3):
    device = torch.device('cpu')
    batch, seq_len, feat_dim = X.shape
    model = LSTMSeqAutoencoder(feature_dim=feat_dim, hidden_dim=64, latent_dim=32)
    model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    dataset = TensorDataset(torch.from_numpy(X.astype(np.float32)))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_loss = 0.0
        for batch_data in loader:
            x = batch_data[0].to(device)
            recon = model(x)
            loss = criterion(recon, x)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * x.size(0)

        epoch_loss /= len(loader.dataset)
        logger.info(f'Epoch {epoch}/{epochs} - Loss: {epoch_loss:.6f}')
        print(f'Epoch {epoch}/{epochs} - Loss: {epoch_loss:.6f}')

    model_path = MODEL_DIR / 'seq_ae.pth'
    torch.save({'model_state_dict': model.state_dict(), 'feature_dim': feat_dim, 'seq_len': seq_len}, str(model_path))
    logger.info(f'Saved sequence autoencoder to {model_path}')


if __name__ == '__main__':
    X = load_and_make_sequences(seq_len=8)

    # Flatten to fit scaler (fit on features per timestep)
    batch, seq_len, feat_dim = X.shape
    X_flat = X.reshape(-1, feat_dim)
    scaler = StandardScaler()
    X_flat_scaled = scaler.fit_transform(X_flat)

    # Reshape back to sequences
    X_scaled = X_flat_scaled.reshape(batch, seq_len, feat_dim)

    # Save scaler
    joblib.dump(scaler, MODEL_DIR / 'seq_ae_scaler.joblib')

    train_sequence_autoencoder(X_scaled, epochs=20, batch_size=64, lr=1e-3)
