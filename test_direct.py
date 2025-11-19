import logging
import sys
from pathlib import Path

# Set up logging to see debug messages
logging.basicConfig(level=logging.DEBUG, format='%(name)s - %(levelname)s - %(message)s')

# Add parent directory to path
sys.path.append(str(Path(__file__).parent))

from app.api import ingest_flow
from app.schemas import Flow
import asyncio

async def test_ingest():
    """Test the ingest endpoint directly"""
    flow = Flow(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        proto="TCP",
        sport=54321,
        dport=443,
        sbytes=1024,
        dbytes=2048,
        pkts=50,
        dur=30,
        state="SYN_ACK",
        ct_flw_http_mthd=0,
        ct_state_ttl=64,
        ct_srv_src=1
    )
    
    try:
        result = await ingest_flow(flow)
        print(f"\n\nResult type: {type(result)}")
        print(f"Result: {result}")
        return result
    except Exception as e:
        print(f"\n\nError: {e}", exc_info=True)
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    result = asyncio.run(test_ingest())
    if result:
        print(f"\n\nSuccess! Response: {result}")
