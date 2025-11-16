import requests
import json
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

print('Testing backend at http://127.0.0.1:8000')
try:
    r = requests.get('http://127.0.0.1:8000/docs', timeout=3)
    print('GET /docs', r.status_code)
    logger.debug(f'Response headers: {r.headers}')
    logger.debug(f'Response content: {r.text[:500]}...')
except Exception as e:
    logger.error('GET /docs failed:', exc_info=True)
    print('GET /docs failed:', e)

flow = {
 'src_ip':'10.0.0.1','dst_ip':'10.0.0.2','sport':12345,'dport':80,'proto':'tcp',
 'dur':0.5,'sbytes':1000,'dbytes':500,'pkts':10,'state':'EST','ct_flw_http_mthd':1,'ct_state_ttl':1.0,'ct_srv_src':1
}
try:
    logger.debug(f'Sending POST request to /ingest with data: {flow}')
    r = requests.post('http://127.0.0.1:8000/ingest', json=flow, timeout=10)
    print('POST /ingest', r.status_code)
    try:
        response_json = r.json()
        print('JSON response:', json.dumps(response_json, indent=2))
        logger.debug(f'Full response JSON: {response_json}')
    except Exception as e:
        logger.error('Failed to parse JSON response:', exc_info=True)
        print('Raw response:', r.text[:2000])
except Exception as e:
    logger.error('POST /ingest failed:', exc_info=True)
    print('POST /ingest failed:', e)
