import numpy as np
import pandas as pd
from pathlib import Path

np.random.seed(42)

N_NORMAL = 5000
N_ATTACK = 800

def random_ips(n):
    return [f'10.0.{np.random.randint(0,256)}.{np.random.randint(1,255)}' for _ in range(n)]

def make_normal(n):
    return pd.DataFrame({
        'src_ip': random_ips(n),
        'dst_ip': np.random.choice([f'10.0.0.{i}' for i in range(2,50)], size=n),
        'sport': np.random.randint(1024, 65535, size=n),
        'dport': np.random.choice([80,443,53,123,445,22,3389], size=n, p=[0.35,0.35,0.05,0.05,0.08,0.06,0.06]),
        'proto': np.random.choice(['tcp','udp'], size=n, p=[0.8,0.2]),
        'dur': np.random.exponential(scale=0.8, size=n),
        'sbytes': np.random.lognormal(mean=7.0, sigma=0.8, size=n).astype(int),
        'dbytes': np.random.lognormal(mean=6.0, sigma=0.8, size=n).astype(int),
        'pkts': np.random.poisson(lam=20, size=n),
        'state': np.random.choice(['EST','S1','SF','INT'], size=n, p=[0.4,0.25,0.25,0.10]),
        'ct_flw_http_mthd': np.random.binomial(1, 0.15, size=n),
        'ct_state_ttl': np.random.randint(0, 5, size=n),
        'ct_srv_src': np.random.randint(0, 10, size=n),
        'label': 0
    })

def make_attack(n):
    return pd.DataFrame({
        'src_ip': random_ips(n),
        'dst_ip': np.random.choice([f'10.0.0.{i}' for i in range(2,10)], size=n),
        'sport': np.random.randint(1024, 65535, size=n),
        'dport': np.random.choice([22,3389,1433,3306], size=n),
        'proto': 'tcp',
        'dur': np.random.exponential(scale=0.2, size=n),
        'sbytes': np.random.lognormal(mean=6.0, sigma=0.6, size=n).astype(int),
        'dbytes': np.random.lognormal(mean=4.8, sigma=0.6, size=n).astype(int),
        'pkts': np.random.poisson(lam=8, size=n),
        'state': np.random.choice(['S1','SF','INT'], size=n),
        'ct_flw_http_mthd': 0,
        'ct_state_ttl': np.random.randint(2, 12, size=n),
        'ct_srv_src': np.random.randint(0, 3, size=n),
        'label': 1
    })

if __name__ == '__main__':
    normal = make_normal(N_NORMAL)
    attack = make_attack(N_ATTACK)
    df = pd.concat([normal, attack], ignore_index=True)
    Path('data').mkdir(exist_ok=True)
    df.to_parquet('data/synth_flows.parquet')
    print(f'Wrote data/synth_flows.parquet with {len(df)} rows')
