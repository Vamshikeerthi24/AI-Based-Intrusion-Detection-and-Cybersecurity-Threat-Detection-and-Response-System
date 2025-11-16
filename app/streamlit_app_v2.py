import sys
from pathlib import Path
import os

# Ensure parent package is on sys.path for local imports.
sys.path.append(str(Path(__file__).parent.parent))

import streamlit as st
import requests
import json
from typing import List, Dict, Any
import pandas as pd
import plotly.express as px
from utils.utils import setup_logging

logger = setup_logging()

# Constants and Paths
BLOCKLIST_DIR = Path('blocklist')
BLOCKLIST_PATH = BLOCKLIST_DIR / 'blocklist.json'
DEFAULT_BACKEND = 'http://127.0.0.1:8000'

# Theme and Page Config
st.set_page_config(
    page_title='Network IDS Dashboard',
    page_icon='🛡️',
    layout='wide',
    initial_sidebar_state='expanded'
)

# Custom CSS
st.markdown('''
    <style>
        .block-container {
            padding-top: 1rem;
            padding-bottom: 0rem;
        }
        .stAlert {
            padding: 0.5rem;
            margin-bottom: 0.5rem;
        }
        div[data-testid="stMetricDelta"] {
            background-color: rgba(28, 131, 225, 0.1);
            padding: 0.5rem;
            border-radius: 0.5rem;
        }
    </style>
''', unsafe_allow_html=True)

# Helpers
def ensure_blocklist_exists() -> None:
    """Ensure the blocklist directory and file exist."""
    BLOCKLIST_DIR.mkdir(parents=True, exist_ok=True)
    if not BLOCKLIST_PATH.exists():
        BLOCKLIST_PATH.write_text(json.dumps([]))

def load_blocklist() -> List[str]:
    ensure_blocklist_exists()
    try:
        text = BLOCKLIST_PATH.read_text(encoding='utf-8')
        return json.loads(text)
    except json.JSONDecodeError:
        logger.error('blocklist JSON corrupted, recreating empty list')
        BLOCKLIST_PATH.write_text(json.dumps([]))
        return []

def save_blocklist(entries: List[str]) -> None:
    ensure_blocklist_exists()
    BLOCKLIST_PATH.write_text(json.dumps(entries, indent=2))

def backend_health(backend_url: str) -> Dict[str, Any]:
    """Return dict with status and optional message."""
    health = {'ok': False, 'msg': ''}
    try:
        r = requests.get(backend_url.rstrip('/') + '/docs', timeout=3)
        if r.status_code == 200:
            health['ok'] = True
            health['msg'] = 'Backend reachable (docs)'
        else:
            health['msg'] = f'Backend responded (status {r.status_code})'
    except requests.RequestException as e:
        health['msg'] = str(e)
    return health

def show_test_flow_form():
    """Display and handle the test flow form."""
    with st.form('test_flow_form', clear_on_submit=False):
        cols = st.columns(3)
        with cols[0]:
            src_ip = st.text_input('Source IP 🌐', value='10.0.0.1')
            sport = st.number_input('Source Port 🔌', value=12345, min_value=0, max_value=65535)
            dur = st.number_input('Duration ⏱️', value=0.5, format='%.3f')
            sbytes = st.number_input('Source Bytes 📊', value=1000)
            ct_flw_http_mthd = st.number_input('HTTP Method Count 🌐', value=1, help="Count of HTTP methods used in the flow")
            
        with cols[1]:
            dst_ip = st.text_input('Destination IP 🎯', value='10.0.0.2')
            dport = st.number_input('Destination Port 🔌', value=80, min_value=0, max_value=65535)
            pkts = st.number_input('Packets 📦', value=10)
            dbytes = st.number_input('Destination Bytes 📊', value=500)
            ct_state_ttl = st.number_input('State TTL 🕒', value=1.0, format='%.3f', help="Time to live for connection state")
            
        with cols[2]:
            proto = st.selectbox('Protocol 🔄', ['tcp', 'udp', 'icmp'], index=0)
            state = st.text_input('Connection State 🔗', value='EST')
            ct_srv_src = st.number_input('Source Service Count 🔢', value=1, help="Count of services from source")
            
        submitted = st.form_submit_button('Send Test Flow 🚀', use_container_width=True)
        
        if submitted:
            return {
                'src_ip': src_ip, 'dst_ip': dst_ip, 'sport': int(sport), 'dport': int(dport),
                'proto': proto, 'dur': float(dur), 'sbytes': int(sbytes), 'dbytes': int(dbytes), 
                'pkts': int(pkts), 'state': state, 'ct_flw_http_mthd': int(ct_flw_http_mthd),
                'ct_state_ttl': float(ct_state_ttl), 'ct_srv_src': int(ct_srv_src)
            }
    return None

def show_blocklist_manager():
    """Display and handle the blocklist manager UI."""
    st.header('Blocklist Manager 🛡️')
    entries = load_blocklist()
    
    # Stats at the top
    stats_cols = st.columns(3)
    with stats_cols[0]:
        st.metric("Total Blocked IPs", len(entries))
    
    # Search and display
    search = st.text_input('🔍 Search blocklist', placeholder='Enter IP or substring...')
    filtered = [ip for ip in entries if search.lower() in ip.lower()] if search else entries
    
    # Display blocklist with pagination
    items_per_page = 10
    if filtered:
        page = st.selectbox('Page', range(1, (len(filtered) + items_per_page - 1) // items_per_page + 1))
        start_idx = (page - 1) * items_per_page
        end_idx = start_idx + items_per_page
        
        for ip in filtered[start_idx:end_idx]:
            col1, col2 = st.columns([3, 1])
            with col1:
                st.code(ip, language='text')
            with col2:
                if st.button('🗑️ Remove', key=f'remove_{ip}'):
                    entries.remove(ip)
                    save_blocklist(entries)
                    st.success(f'Removed {ip}')
                    st.experimental_rerun()
    else:
        st.info('No IPs in blocklist match your search')
    
    # Add new IP
    st.markdown('### Add New IP')
    cols = st.columns([3, 1])
    with cols[0]:
        new_ip = st.text_input('🆕 IP Address', key='add_ip', placeholder='Enter IP to block...')
    with cols[1]:
        if st.button('Add IP ➕', use_container_width=True):
            if new_ip:
                if new_ip in entries:
                    st.warning('⚠️ IP already in blocklist')
                else:
                    entries.append(new_ip)
                    save_blocklist(entries)
                    st.success(f'✅ Added {new_ip}')
                    st.experimental_rerun()
            else:
                st.warning('⚠️ Enter an IP address')

def show_history_and_stats():
    """Display session history and statistics."""
    history = st.session_state.get('history', [])
    
    if not history:
        st.info('👋 No detection history yet. Try sending some test flows!')
        return
        
    # Summary metrics
    total = len(history)
    blocked = sum(1 for h in history if h['response'].get('action') == 'block')
    allowed = total - blocked
    
    cols = st.columns(3)
    with cols[0]:
        st.metric("Total Flows", total)
    with cols[1]:
        st.metric("Blocked", blocked)
    with cols[2]:
        st.metric("Allowed", allowed)
    
    # Risk score distribution
    risks = [h['response'].get('risk_score', 0) for h in history if isinstance(h.get('response'), dict)]
    if risks:
        df_risks = pd.DataFrame({'Risk Score': risks})
        fig = px.histogram(df_risks, x='Risk Score', nbins=20,
                          title='Risk Score Distribution',
                          color_discrete_sequence=['#1f77b4'])
        st.plotly_chart(fig, use_container_width=True)
    
    # Recent flows table
    st.subheader('Recent Flows')
    for idx, item in enumerate(history[:10]):  # Show last 10 flows
        with st.expander(f"#{idx+1} {item['flow']['src_ip']} → {item['flow']['dst_ip']}"):
            cols = st.columns(2)
            with cols[0]:
                st.markdown('#### Flow Details')
                st.json(item['flow'])
            with cols[1]:
                st.markdown('#### Detection Results')
                st.json(item['response'])

def main():
    # Sidebar Configuration
    st.sidebar.title('🛡️ IDS Dashboard')
    st.sidebar.markdown('---')
    
    # Backend Configuration
    st.sidebar.header('Backend Settings ⚙️')
    backend_url = st.sidebar.text_input(
        'Backend URL',
        value=st.session_state.get('backend_url', DEFAULT_BACKEND)
    )
    
    if st.sidebar.button('Save Backend URL 💾'):
        st.session_state['backend_url'] = backend_url
        
    # Backend Status
    status = backend_health(backend_url)
    if status['ok']:
        st.sidebar.success('✅ Backend Connected')
    else:
        st.sidebar.error(f"❌ Backend Error: {status['msg']}")
    
    # LLM Settings
    st.sidebar.markdown('---')
    st.sidebar.header('Explainability Settings 🤖')
    request_explain_allowed = st.sidebar.checkbox(
        'Generate explanations for allowed flows',
        value=False,
        key='request_explain_allowed',
        help='Request natural language explanations for allowed flows (may increase response time)'
    )
    
    # Main Content Area
    tab1, tab2, tab3 = st.tabs(['🎯 Test Detection', '📊 Analytics', '🛡️ Blocklist'])
    
    with tab1:
        st.header('Test Network Flow 🌐')
        test_flow = show_test_flow_form()
        
        if test_flow:
            with st.spinner('Processing flow...'):
                try:
                    r = requests.post(f"{backend_url.rstrip('/')}/ingest", 
                                    json=test_flow, timeout=5)
                    try:
                        data = r.json()
                        
                        # Update session history
                        history = st.session_state.get('history', [])
                        history.insert(0, {'flow': test_flow, 'response': data})
                        st.session_state['history'] = history[:50]  # Keep last 50
                        
                        # Show results
                        if data.get('action') == 'block':
                            st.error('⛔ Flow Blocked!')
                        else:
                            st.success('✅ Flow Allowed')
                            
                        st.json(data)
                        
                        # Show explanation if available
                        explanation = data.get('explanation')
                        if explanation:
                            st.info('🤖 Analysis Explanation')
                            st.write(explanation)
                        elif request_explain_allowed and data.get('action') != 'block':
                            try:
                                r2 = requests.post(
                                    f"{backend_url.rstrip('/')}/explain",
                                    json=test_flow,
                                    timeout=10
                                )
                                exdata = r2.json()
                                if exdata.get('explanation'):
                                    st.info('🤖 Generated Explanation')
                                    st.write(exdata['explanation'])
                            except Exception as e:
                                st.warning(f'Could not get explanation: {e}')
                                
                    except ValueError:
                        st.error('🚫 Backend returned invalid JSON')
                        logger.error('Invalid JSON from backend: %s', r.text)
                        
                except requests.RequestException as e:
                    st.error(f'🚫 Failed to contact backend: {e}')
                    logger.error('Failed to POST test flow: %s', e)
    
    with tab2:
        st.header('Analytics & History 📊')
        show_history_and_stats()
        
        # Load visualizations if available
        try:
            from app.visual import get_renderer
            render_visuals = get_renderer()
            render_visuals(st.session_state.get('history', []))
        except Exception as e:
            st.warning(f'Additional visualizations unavailable: {e}')
    
    with tab3:
        show_blocklist_manager()
        
    # Footer
    st.markdown('---')
    st.markdown('''
        <div style="text-align: center; color: #666;">
            <small>🛡️ Network Intrusion Detection System Dashboard v2.0</small>
        </div>
    ''', unsafe_allow_html=True)

if __name__ == '__main__':
    main()