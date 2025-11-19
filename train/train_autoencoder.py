"""Train a small dense autoencoder on tabular flow features (CPU-friendly).

This script runs a short training loop (few epochs) intended as a smoke
test and example for Master's-level experiments. It loads either
`data/synth_flows.parquet` or `data/flows.parquet` and trains a tiny
autoencoder, saving the model to `models/autoencoder.pth`.
"""
from pathlib import Path
import torch
from torch.utils.data import DataLoader, TensorDataset
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import numpy as np

from models.nn_models import DenseAutoencoder


def find_data_path() -> Path:
    candidates = [Path('data/synth_flows.parquet'), Path('data/flows.parquet')]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError('No input data found (looked for synth_flows.parquet or flows.parquet)')


def load_features(path: Path) -> np.ndarray:
    df = pd.read_parquet(path)
    # Drop identifiers and label if present
    drop_cols = [c for c in ['label', 'src_ip', 'dst_ip'] if c in df.columns]
    X = df.drop(columns=drop_cols)
    # Ensure numeric
    X = X.select_dtypes(include=[np.number]).fillna(0.0)
    return X.astype(np.float32).values


def train_autoencoder(epochs: int = 5, batch_size: int = 64, lr: float = 1e-3):
    data_path = find_data_path()
    print(f'Loading data from {data_path}')
    X = load_features(data_path)
    print(f'Data shape: {X.shape}')

    ds = TensorDataset(torch.from_numpy(X))
    dl = DataLoader(ds, batch_size=batch_size, shuffle=True)

    input_dim = X.shape[1]
    model = DenseAutoencoder(input_dim=input_dim, latent_dim=min(32, input_dim//2 or 8))
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

    # Save model
    Path('models').mkdir(exist_ok=True)
    out_path = Path('models/autoencoder.pth')
    torch.save(model.state_dict(), out_path)
    print(f'Saved autoencoder to {out_path}')


if __name__ == '__main__':
    train_autoencoder()
"""
Train a small dense autoencoder on tabular flow features (CPU-friendly).
Saves model to `models/ae.pth` and the scaler to `models/ae_scaler.joblib`.
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
from models.nn_models import DenseAutoencoder
from utils.utils import setup_logging

logger = setup_logging()

MODEL_DIR = Path('models')
MODEL_DIR.mkdir(exist_ok=True)


def load_data(parquet_path: str = 'data/flows.parquet'):
    df = pd.read_parquet(parquet_path)
    # Drop non-feature columns if present
    drop_cols = [c for c in ['label', 'src_ip', 'dst_ip'] if c in df.columns]
    X = df.drop(columns=drop_cols)
    return X


def train(input_dim: int, X: np.ndarray, epochs: int = 25, batch_size: int = 256, lr: float = 1e-3):
    device = torch.device('cpu')
    model = DenseAutoencoder(input_dim, latent_dim=min(32, max(8, input_dim // 4)))
    model.to(device)

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()

    dataset = TensorDataset(torch.from_numpy(X.astype(np.float32)))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_loss = 0.0
        for batch in loader:
            x = batch[0].to(device)
            recon = model(x)
            loss = criterion(recon, x)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * x.size(0)

        epoch_loss /= len(loader.dataset)
        logger.info(f'Epoch {epoch}/{epochs} - Loss: {epoch_loss:.6f}')
        print(f'Epoch {epoch}/{epochs} - Loss: {epoch_loss:.6f}')

    # Save model
    model_path = MODEL_DIR / 'ae.pth'
    torch.save({'model_state_dict': model.state_dict(), 'input_dim': input_dim}, str(model_path))
    logger.info(f'Saved autoencoder to {model_path}')


if __name__ == '__main__':
    Xdf = load_data()
    scaler = StandardScaler()
    X = scaler.fit_transform(Xdf.values)

    # Save scaler
    joblib.dump(scaler, MODEL_DIR / 'ae_scaler.joblib')

    train(input_dim=X.shape[1], X=X, epochs=20, batch_size=256, lr=1e-3)
