import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import json
from datetime import datetime, timedelta
from utils.utils import setup_logging, load_config

logger = setup_logging()
config = load_config()

class ResponseManager:
    def __init__(self):
        self.blocklist_file = Path('blocklist/blocklist.json')
        self.blocklist_file.parent.mkdir(exist_ok=True)
        if not self.blocklist_file.exists():
            self.blocklist_file.write_text('{}')

    def block(self, ip: str):
        ttl = config['block_ttl_minutes']
        blocked_at = datetime.now().isoformat()
        with open(self.blocklist_file, 'r+') as f:
            blocklist = json.load(f)
            blocklist[ip] = {'blocked_at': blocked_at, 'ttl_minutes': ttl}
            f.seek(0)
            json.dump(blocklist, f, indent=2)
        logger.info(f'Blocked IP {ip} for {ttl} minutes')

    def unblock(self, ip: str):
        with open(self.blocklist_file, 'r+') as f:
            blocklist = json.load(f)
            if ip in blocklist:
                del blocklist[ip]
                f.seek(0)
                json.dump(blocklist, f, indent=2)
                logger.info(f'Unblocked IP {ip}')

    def check_blocklist(self):
        with open(self.blocklist_file, 'r+') as f:
            blocklist = json.load(f)
            now = datetime.now()
            for ip, data in list(blocklist.items()):
                blocked_at = datetime.fromisoformat(data['blocked_at'])
                ttl = timedelta(minutes=data['ttl_minutes'])
                if now >= blocked_at + ttl:
                    del blocklist[ip]
                    logger.info(f'Expired block for IP {ip}')
            f.seek(0)
            f.truncate()
            json.dump(blocklist, f, indent=2)
