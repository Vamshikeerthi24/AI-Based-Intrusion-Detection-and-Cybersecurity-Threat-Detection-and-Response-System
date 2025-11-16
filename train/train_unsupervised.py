import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from utils.utils import setup_logging

logger = setup_logging()

DF = pd.read_parquet('data/flows.parquet')
benign = DF[DF['label'] == 0]
X = benign.drop(columns=['label', 'src_ip', 'dst_ip'])
iso = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
iso.fit(X)
logger.info('Trained unsupervised Isolation Forest model')

Path('models').mkdir(exist_ok=True)
joblib.dump({'model': iso, 'columns': list(X.columns)}, 'models/iso.joblib')
logger.info('Saved unsupervised model to models/iso.joblib')
