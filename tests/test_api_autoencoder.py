import sys
from pathlib import Path
import json

sys.path.append(str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient

import app.api as api


client = TestClient(api.app)


def sample_flow():
    return {
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'sport': 12345,
        'dport': 80,
        'proto': 'tcp',
        'dur': 0.5,
        'sbytes': 1000,
        'dbytes': 500,
        'pkts': 10,
        'state': 'EST',
        'ct_flw_http_mthd': 1,
        'ct_state_ttl': 1.0,
        'ct_srv_src': 1
    }


def test_ingest_with_dummy_ae(monkeypatch):
    # Create a dummy autoencoder object that returns input as reconstruction
    class DummyAE:
        def __call__(self, x):
            return x

    # Patch the api module's ae to DummyAE
    monkeypatch.setattr(api, 'ae', DummyAE())

    r = client.post('/ingest', json=sample_flow())
    assert r.status_code == 200
    data = r.json()
    assert 'ml_insights' in data
    ad = data['ml_insights']['anomaly_detection']
    # With perfect reconstruction, reconstruction score should be 0.0
    assert 'autoencoder_reconstruction' in ad
    assert float(ad['autoencoder_reconstruction']) == 0.0


def test_ingest_without_ae(monkeypatch):
    # Ensure ae is None
    monkeypatch.setattr(api, 'ae', None)
    r = client.post('/ingest', json=sample_flow())
    assert r.status_code == 200
    data = r.json()
    assert 'ml_insights' in data
    ad = data['ml_insights']['anomaly_detection']
    # Field exists and is numeric (default 0.0 when AE absent)
    assert 'autoencoder_reconstruction' in ad
    assert isinstance(ad['autoencoder_reconstruction'], float) or isinstance(ad['autoencoder_reconstruction'], int)
