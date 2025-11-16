import logging
import yaml
from pathlib import Path

def setup_logging():
    logging.basicConfig(
        filename='logs/app.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger()

def load_config():
    with open('config/config.yaml', 'r') as f:
        return yaml.safe_load(f)
