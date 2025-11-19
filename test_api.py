import requests
import json

url = "http://localhost:8000/ingest"
payload = {
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "proto": "TCP",
    "src_port": 54321,
    "dst_port": 443,
    "bytes_sent": 1024,
    "bytes_received": 2048,
    "packet_count": 50,
    "flow_duration": 30,
    "packet_rate": 1.67,
    "byte_rate": 102.4,
    "anomaly_score": 0.15
}

try:
    response = requests.post(url, json=payload, timeout=5)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
