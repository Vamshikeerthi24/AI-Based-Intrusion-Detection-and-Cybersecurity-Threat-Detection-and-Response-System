import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from utils.utils import setup_logging

logger = setup_logging()

DF = pd.read_parquet('data/flows.parquet')
X = DF.drop(columns=['label', 'src_ip', 'dst_ip'])
y = DF['label']
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

clf = RandomForestClassifier(n_estimators=100, max_depth=10, n_jobs=-1, random_state=42)
clf.fit(Xtr, ytr)
print(classification_report(yte, clf.predict(Xte)))
logger.info('Trained supervised Random Forest model')

Path('models').mkdir(exist_ok=True)
joblib.dump({'model': clf, 'columns': list(X.columns)}, 'models/rf.joblib')
logger.info('Saved supervised model to models/rf.joblib')
