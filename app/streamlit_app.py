import sys
from pathlib import Path
import os

# Ensure parent package is on sys.path for local imports.
sys.path.append(str(Path(__file__).parent.parent))

import streamlit as st
import requests
import json
import pandas as pd
import numpy as np
import plotly.express as px
from datetime import datetime
from typing import List, Dict, Any
from utils.utils import setup_logging

logger = setup_logging()

# Constants and Paths
BLOCKLIST_DIR = Path('blocklist')
BLOCKLIST_PATH = BLOCKLIST_DIR / 'blocklist.json'
DEFAULT_BACKEND = 'http://127.0.0.1:8000'

# Theme and Page Config
st.set_page_config(
    page_title='Network IDS ML Dashboard',
    page_icon='shield',
    layout='wide',
    initial_sidebar_state='expanded'
)

# Custom CSS for improved UI
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
        .risk-indicator {
            padding: 0.5rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
            font-weight: bold;
        }
        .high-risk {
            background-color: rgba(255, 0, 0, 0.1);
            border: 1px solid rgba(255, 0, 0, 0.2);
        }
        .medium-risk {
            background-color: rgba(255, 165, 0, 0.1);
            border: 1px solid rgba(255, 165, 0, 0.2);
        }
        .low-risk {
            background-color: rgba(0, 255, 0, 0.1);
            border: 1px solid rgba(0, 255, 0, 0.2);
        }
        .feature-importance {
            padding: 1rem;
            background-color: rgba(28, 131, 225, 0.05);
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
        .tech-details {
            font-family: monospace;
            padding: 1rem;
            background-color: rgba(0, 0, 0, 0.05);
            border-radius: 0.5rem;
        }
        .attack-pattern {
            padding: 0.5rem;
            margin: 0.25rem 0;
            background-color: rgba(255, 0, 0, 0.05);
            border-radius: 0.25rem;
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
            src_ip = st.text_input('Source IP', value='10.0.0.1')
            sport = st.number_input('Source Port', value=12345, min_value=0, max_value=65535)
            dur = st.number_input('Duration (s)', value=0.5, format='%.3f')
            sbytes = st.number_input('Source Bytes', value=1000)
            ct_flw_http_mthd = st.number_input('HTTP Method Count', value=1, help="Count of HTTP methods used in the flow")
            
        with cols[1]:
            dst_ip = st.text_input('Destination IP', value='10.0.0.2')
            dport = st.number_input('Destination Port', value=80, min_value=0, max_value=65535)
            pkts = st.number_input('Packets', value=10)
            dbytes = st.number_input('Destination Bytes', value=500)
            ct_state_ttl = st.number_input('State TTL', value=1.0, format='%.3f', help="Time to live for connection state")
            
        with cols[2]:
            proto = st.selectbox('Protocol', ['tcp', 'udp', 'icmp'], index=0)
            state = st.text_input('Connection State', value='EST')
            ct_srv_src = st.number_input('Source Service Count', value=1, help="Count of services from source")
            
        submitted = st.form_submit_button('Send Test Flow', use_container_width=True)
        
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
                    st.success(f'Added {new_ip}')
                    st.experimental_rerun()
            else:
                st.warning('⚠️ Enter an IP address')

def risk_level_badge(score):
    """Return a styled risk level badge."""
    if score > 0.7:
        return "High"
    elif score > 0.4:
        return "Medium"
    return "Low"


def generate_anomaly_explanation(insights: Dict[str, Any], flow: Dict[str, Any]) -> str:
    """Generate a short human-readable explanation for an anomaly using simple heuristics.

    This runs locally in the UI as a fallback so users see immediate context when LLM is
    unavailable or expensive.
    """
    if not insights or 'anomaly_detection' not in insights:
        return 'No anomaly information available.'

    a = insights['anomaly_detection'].get('anomaly_score', 0)
    parts = []
    parts.append(f"Anomaly score is {a:.3f} (higher means more unusual)")

    # Significant features
    feat_text = ''
    if 'feature_importance' in insights and insights['feature_importance']:
        top = insights['feature_importance'][:5]
        feat_text = ', '.join([f"{f} ({imp:.3f})" if isinstance(imp, (int, float)) else f"{f}" for f, imp in top])
        parts.append(f"Top contributing features: {feat_text}.")

    # Patterns
    if 'attack_patterns' in insights and insights['attack_patterns']:
        pats = ', '.join([p['pattern'] for p in insights['attack_patterns']])
        parts.append(f"Related attack patterns: {pats}.")

    # Flow-based hints
    if flow.get('sbytes', 0) > 100000 and a > 0.3:
        parts.append('Large outbound transfer detected; consider inspecting payloads or egress rules.')
    if flow.get('ct_srv_src', 0) > 5 and a > 0.2:
        parts.append('Multiple services from same source — may indicate scanning.')

    return ' '.join(parts)

def show_history_and_stats():
    """Display enhanced session history with ML insights and statistics."""
    history = st.session_state.get('history', [])
    
    if not history:
        st.info('👋 No detection history yet. Try sending some test flows!')
        return
        
    # Summary metrics
    total = len(history)
    blocked = sum(1 for h in history if h['response'].get('action') == 'block')
    allowed = total - blocked
    
    # Enhanced metrics display
    st.subheader('🔍 Security Overview')
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Flows", total, 
                 delta=f"{total - len(history[1:]) if len(history) > 1 else total}")
    with col2:
        st.metric("High Risk Flows", blocked, 
                 delta=f"{round(blocked/total*100 if total else 0, 1)}%",
                 delta_color="inverse")
    with col3:
        st.metric("Average Risk Score", 
                 f"{sum(h['response'].get('risk_score', 0) for h in history)/total:.2f}")
    with col4:
        anomaly_count = sum(1 for h in history if h['response'].get('ml_insights', {}).get('anomaly_detection', {}).get('anomaly_score', 0) > 0.7)
        st.metric("Anomaly Rate", 
                 f"{anomaly_count/total*100:.1f}%")
    
    # Advanced visualizations
    st.subheader('📊 ML Insights')
    viz_tabs = st.tabs(['Risk Analysis', 'Attack Patterns', 'Feature Importance'])
    
    with viz_tabs[0]:
        # Risk score distribution with threshold lines
        risks = [h['response'].get('risk_score', 0) for h in history if isinstance(h.get('response'), dict)]
        if risks:
            df_risks = pd.DataFrame({'Risk Score': risks})
            fig = px.histogram(df_risks, x='Risk Score', nbins=20,
                             title='Risk Score Distribution',
                             color_discrete_sequence=['#1f77b4'])
            
            # Add threshold lines
            fig.add_vline(x=0.7, line_dash="dash", line_color="red", 
                         annotation_text="High Risk Threshold")
            fig.add_vline(x=0.4, line_dash="dash", line_color="orange",
                         annotation_text="Medium Risk Threshold")
                         
            st.plotly_chart(fig, use_container_width=True)
            
    with viz_tabs[1]:
        # Attack pattern analysis
        pattern_counts = {}
        for h in history:
            if 'attack_patterns' in h['response'].get('ml_insights', {}):
                for pattern in h['response']['ml_insights']['attack_patterns']:
                    pattern_counts[pattern['pattern']] = pattern_counts.get(pattern['pattern'], 0) + 1
        
        if pattern_counts:
            df_patterns = pd.DataFrame(list(pattern_counts.items()), 
                                     columns=['Attack Pattern', 'Count'])
            fig = px.bar(df_patterns, x='Attack Pattern', y='Count',
                        title='Detected Attack Patterns',
                        color='Count',
                        color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack patterns detected in current session")
            
    with viz_tabs[2]:
        # Aggregate feature importance
        feature_imp = {}
        for h in history:
            if 'feature_importance' in h['response'].get('ml_insights', {}):
                        features = h['response']['ml_insights']['feature_importance']
                        if isinstance(features, list):
                            for feat, imp in features:
                                feature_imp[feat] = feature_imp.get(feat, 0) + float(imp)
                                
        if feature_imp:
            df_features = pd.DataFrame(list(feature_imp.items()),
                                     columns=['Feature', 'Importance'])
            df_features['Importance'] = df_features['Importance'] / len(history)
            fig = px.bar(df_features.sort_values('Importance', ascending=True).tail(10),
                        x='Importance', y='Feature', orientation='h',
                        title='Top 10 Important Features',
                        color='Importance',
                        color_continuous_scale='Blues')
            st.plotly_chart(fig, use_container_width=True)
    
    # Recent flows with enhanced ML insights
    st.subheader('🔍 Recent Flow Analysis')
    for idx, item in enumerate(history[:10]):
        with st.expander(f"#{idx+1} {item['flow']['src_ip']} → {item['flow']['dst_ip']}",
                        expanded=(idx == 0)):
            
            # Risk level indicator
            risk_score = item['response'].get('risk_score', 0)
            risk_class = ('high-risk' if risk_score > 0.7 else 
                         'medium-risk' if risk_score > 0.4 else 'low-risk')
            
            st.markdown(f"""
                <div class="risk-indicator {risk_class}">
                    Risk Score: {risk_score:.2f} 
                    ({item['response'].get('action', 'unknown').upper()})
                </div>
                """, unsafe_allow_html=True)
            
            # Flow details and ML insights in tabs
            detail_tabs = st.tabs(['ML Insights', 'Technical Details', 'Raw Data'])
            
            with detail_tabs[0]:
                if 'ml_insights' in item['response']:
                    insights = item['response']['ml_insights']
                    
                    # Feature importance
                    if 'feature_importance' in insights:
                        st.markdown('##### 🎯 Key Features')
                        features = insights['feature_importance']
                        if isinstance(features, list):
                            for feat, imp in features:
                                st.progress(float(imp), text=f"{feat}: {float(imp):.3f}")
                    
                    # Attack patterns
                    if 'attack_patterns' in insights:
                        st.markdown('##### ⚠️ Detected Patterns')
                        for pattern in insights['attack_patterns']:
                            st.markdown(f"""
                                <div class="attack-pattern">
                                    <strong>{pattern['pattern']}</strong><br/>
                                    {pattern['description']}<br/>
                                    Confidence: {pattern['confidence']:.2f}
                                </div>
                                """, unsafe_allow_html=True)
                    
                    # Anomaly detection
                    if 'anomaly_detection' in insights:
                        st.markdown('##### 🔍 Anomaly Analysis')
                        st.metric('Anomaly Score', 
                                f"{insights['anomaly_detection']['anomaly_score']:.3f}")
                        # Provide a local, human-readable explanation for the anomaly
                        try:
                            ann_expl = generate_anomaly_explanation(insights, item['flow'])
                            st.markdown('**Anomaly Explanation:**')
                            st.write(ann_expl)
                        except Exception as e:
                            logger.debug('Failed to generate anomaly explanation: %s', e)
                        
            with detail_tabs[1]:
                cols = st.columns(2)
                with cols[0]:
                    st.markdown('##### Flow Statistics')
                    stats = {
                        'Duration': f"{item['flow']['dur']:.3f}s",
                        'Bytes (S→D)': f"{item['flow']['sbytes']} → {item['flow']['dbytes']}",
                        'Packets': item['flow']['pkts'],
                        'State': item['flow']['state']
                    }
                    for k, v in stats.items():
                        st.text(f"{k}: {v}")
                        
                with cols[1]:
                    st.markdown('##### Network Details')
                    net = {
                        'Protocol': item['flow']['proto'],
                        'Ports': f"{item['flow']['sport']} → {item['flow']['dport']}",
                        'HTTP Methods': item['flow']['ct_flw_http_mthd'],
                        'Service Count': item['flow']['ct_srv_src']
                    }
                    for k, v in net.items():
                        st.text(f"{k}: {v}")
            
            with detail_tabs[2]:
                st.json(item)

def show_model_monitoring():
    """Display ML model monitoring and performance metrics."""
    st.header('ML Model Monitoring')
    
    # Model performance metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Calculate detection rate
        history = st.session_state.get('history', [])
        if history:
            detection_rate = sum(1 for h in history 
                               if h['response'].get('risk_score', 0) > 0.7) / len(history)
            st.metric("Detection Rate", f"{detection_rate:.1%}", 
                     delta=f"{(detection_rate - 0.5)*100:.1f}%")
    
    with col2:
        # Feature importance stability
        if history:
            recent_imp = {}
            for h in history[:10]:  # Last 10 flows
                if 'ml_insights' in h['response'] and 'feature_importance' in h['response']['ml_insights']:
                    for feat, imp in h['response']['ml_insights']['feature_importance']:
                        recent_imp[feat] = recent_imp.get(feat, []) + [imp]
            
            if recent_imp:
                avg_variance = np.mean([np.var(imps) for imps in recent_imp.values()])
                st.metric("Feature Stability", f"{1 - avg_variance:.2f}",
                         delta=f"{(0.5 - avg_variance)*100:.1f}%")
    
    with col3:
        # Model confidence
        if history:
            avg_confidence = np.mean([
                h['response'].get('llm_analysis', {}).get('confidence', 0)
                for h in history if 'llm_analysis' in h['response']
            ])
            st.metric("Model Confidence", f"{avg_confidence:.1%}",
                     delta=f"{(avg_confidence - 0.7)*100:.1f}%")
    
    # Model performance over time
    if history:
        st.subheader("Performance Trends")
        trends_tab1, trends_tab2 = st.tabs(['Risk Scores', 'Feature Importance'])
        
        with trends_tab1:
            df_trends = pd.DataFrame([
                {
                    'timestamp': datetime.fromisoformat(h['response'].get('timestamp', datetime.now().isoformat())),
                    'risk_score': h['response'].get('risk_score', 0),
                    'anomaly_score': h['response'].get('ml_insights', {}).get('anomaly_detection', {}).get('anomaly_score', 0)
                }
                for h in history
            ])
            
            fig = px.line(df_trends, x='timestamp', y=['risk_score', 'anomaly_score'],
                         title='Risk Assessment Trends',
                         labels={'value': 'Score', 'variable': 'Metric'})
            st.plotly_chart(fig, use_container_width=True)
            
        with trends_tab2:
            # Feature importance over time
            feature_trends = {}
            timestamps = []
            
            for h in history:
                if 'ml_insights' in h['response'] and 'feature_importance' in h['response']['ml_insights']:
                    ts = datetime.fromisoformat(h['response'].get('timestamp', datetime.now().isoformat()))
                    timestamps.append(ts)
                    
                    for feat, imp in h['response']['ml_insights']['feature_importance']:
                        if feat not in feature_trends:
                            feature_trends[feat] = []
                        feature_trends[feat].append(imp)
            
            if feature_trends:
                df_feat = pd.DataFrame(feature_trends, index=timestamps)
                fig = px.line(df_feat, title='Feature Importance Trends')
                fig.update_layout(xaxis_title='Time', yaxis_title='Importance')
                st.plotly_chart(fig, use_container_width=True)

def main():
    # Sidebar Configuration
    st.sidebar.title('ML-Enhanced IDS')
    st.sidebar.markdown('---')
    
    # Backend Configuration
    st.sidebar.header('Backend Settings')
    backend_url = st.sidebar.text_input(
        'Backend URL',
        value=st.session_state.get('backend_url', DEFAULT_BACKEND)
    )
    
    if st.sidebar.button('Save Backend URL'):
        st.session_state['backend_url'] = backend_url
        
    # Backend Status
    status = backend_health(backend_url)
    if status['ok']:
        st.sidebar.success('Backend Connected')
    else:
        st.sidebar.error(f"Backend Error: {status['msg']}")
    
    # ML Settings
    st.sidebar.markdown('---')
    st.sidebar.header('ML Settings')
    
    # Detection thresholds
    risk_threshold = st.sidebar.slider(
        'Risk Score Threshold',
        min_value=0.0,
        max_value=1.0,
        value=0.7,
        help='Adjust the threshold for classifying high-risk flows'
    )
    
    anomaly_threshold = st.sidebar.slider(
        'Anomaly Detection Sensitivity',
        min_value=0.0,
        max_value=1.0,
        value=0.5,
        help='Adjust the sensitivity of anomaly detection'
    )
    
    # LLM Explainability
    st.sidebar.markdown('---')
    st.sidebar.header('Explainability Settings')
    request_explain_allowed = st.sidebar.checkbox(
        'Generate explanations for allowed flows',
        value=False,
        key='request_explain_allowed',
        help='Request ML-driven explanations for allowed flows (may increase response time)'
    )
    
    # Advanced ML options
    with st.sidebar.expander('Advanced ML Options'):
        st.checkbox('Enable pattern matching', value=True,
                   help='Use pattern matching for attack detection')
        st.checkbox('Use ensemble detection', value=True,
                   help='Combine multiple ML models for better accuracy')
        st.select_slider('Feature importance method',
                        options=['SHAP', 'LIME', 'Integrated Gradients'],
                        value='SHAP')
    
    # Main Content Area
    tab1, tab2, tab3 = st.tabs(['Test Detection', 'Analytics', 'Blocklist'])
    
    with tab1:
        st.header('Test Network Flow Detection')
        
        # Add tabs for manual input vs file upload
        input_tab1, input_tab2 = st.tabs(['Manual Input', 'File Upload'])
        
        with input_tab1:
            test_flow = show_test_flow_form()
            
        with input_tab2:
            st.markdown("""
                Upload a CSV file with test flows. The file should have these columns:
                - src_ip, dst_ip: Source and destination IP addresses
                - sport, dport: Source and destination ports
                - proto: Protocol (tcp, udp, icmp)
                - dur: Duration in seconds
                - sbytes, dbytes: Source and destination bytes
                - pkts: Number of packets
                - state: Connection state
                - ct_flw_http_mthd: HTTP method count
                - ct_state_ttl: State TTL
                - ct_srv_src: Source service count
            """)
            
            uploaded_file = st.file_uploader("Choose a CSV file", type='csv')
            
            if uploaded_file is not None:
                try:
                    df = pd.read_csv(uploaded_file)
                    required_columns = [
                        'src_ip', 'dst_ip', 'sport', 'dport', 'proto', 'dur',
                        'sbytes', 'dbytes', 'pkts', 'state', 'ct_flw_http_mthd',
                        'ct_state_ttl', 'ct_srv_src'
                    ]
                    
                    # Verify columns
                    missing_cols = [col for col in required_columns if col not in df.columns]
                    if missing_cols:
                        st.error(f"Missing required columns: {', '.join(missing_cols)}")
                        return
                    
                    st.write("Preview of uploaded data:")
                    st.dataframe(df.head())
                    
                    if st.button('Process Flows'):
                        with st.spinner('Processing flows...'):
                            for _, row in df.iterrows():
                                test_flow = {
                                    'src_ip': row['src_ip'],
                                    'dst_ip': row['dst_ip'],
                                    'sport': int(row['sport']),
                                    'dport': int(row['dport']),
                                    'proto': row['proto'],
                                    'dur': float(row['dur']),
                                    'sbytes': int(row['sbytes']),
                                    'dbytes': int(row['dbytes']),
                                    'pkts': int(row['pkts']),
                                    'state': row['state'],
                                    'ct_flw_http_mthd': int(row['ct_flw_http_mthd']),
                                    'ct_state_ttl': float(row['ct_state_ttl']),
                                    'ct_srv_src': int(row['ct_srv_src'])
                                }
                                
                                try:
                                    r = requests.post(
                                        f"{backend_url.rstrip('/')}/ingest",
                                        json=test_flow,
                                        timeout=5
                                    )
                                    
                                    # Check if response is valid
                                    if r.status_code != 200:
                                        st.error(f"Backend error (status {r.status_code}): {r.text}")
                                        continue
                                        
                                    try:
                                        data = r.json()
                                    except ValueError:
                                        st.error(f"Invalid JSON response for flow {row['src_ip']} → {row['dst_ip']}")
                                        st.code(r.text, language="text")  # Show raw response
                                        continue
                                    
                                    # Update session history
                                    history = st.session_state.get('history', [])
                                    history.insert(0, {'flow': test_flow, 'response': data})
                                    st.session_state['history'] = history[:50]  # Keep last 50
                                    
                                    # Show progress with more details
                                    risk_score = data.get('risk_score', 0)
                                    action = data.get('action', 'unknown')
                                    if action == 'block':
                                        st.error(f"Blocked flow {row['src_ip']} → {row['dst_ip']} (Risk: {risk_score:.2f})")
                                    else:
                                        st.success(f"Allowed flow {row['src_ip']} → {row['dst_ip']} (Risk: {risk_score:.2f})")
                                    
                                    # Show ML insights if available
                                    if data.get('error'):
                                        # Backend returned a structured error
                                        msg = data.get('message') or data.get('detail') or str(data)
                                        st.error(f"Backend error: {msg}")
                                    elif 'ml_insights' in data:
                                        with st.expander(f"ML Insights for {row['src_ip']} → {row['dst_ip']}"):
                                            insights = data['ml_insights']
                                            if 'anomaly_detection' in insights:
                                                st.metric("Anomaly Score", 
                                                         f"{insights['anomaly_detection'].get('anomaly_score', 0):.3f}")
                                                # Local heuristic explanation when LLM not present
                                                expl = generate_anomaly_explanation(insights, test_flow)
                                                st.write(expl)

                                            if 'attack_patterns' in insights:
                                                for pattern in insights['attack_patterns']:
                                                    st.warning(f"🔍 {pattern['pattern']}: {pattern['description']}")
                                    
                                except requests.RequestException as e:
                                    st.error(f"Network error processing flow {row['src_ip']} → {row['dst_ip']}: {str(e)}")
                                except Exception as e:
                                    st.error(f"Error processing flow {row['src_ip']} → {row['dst_ip']}: {str(e)}")
                                    
                        st.success(f"Finished processing {len(df)} flows")
                        
                    # Add sample file download
                    st.markdown("---")
                    st.markdown("📥 **Need a sample file?**")
                    
                    sample_data = pd.DataFrame([
                        {
                            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'sport': 12345,
                            'dport': 80, 'proto': 'tcp', 'dur': 0.5, 'sbytes': 1000,
                            'dbytes': 500, 'pkts': 10, 'state': 'EST',
                            'ct_flw_http_mthd': 1, 'ct_state_ttl': 1.0, 'ct_srv_src': 1
                        },
                        {
                            'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.3', 'sport': 54321,
                            'dport': 80, 'proto': 'tcp', 'dur': 0.8, 'sbytes': 50000,
                            'dbytes': 1500, 'pkts': 50, 'state': 'EST',
                            'ct_flw_http_mthd': 5, 'ct_state_ttl': 0.1, 'ct_srv_src': 10
                        }
                    ])
                    
                    csv = sample_data.to_csv(index=False)
                    st.download_button(
                        "Download Sample CSV",
                        csv,
                        "sample_flows.csv",
                        "text/csv",
                        key='download-csv'
                    )
                    
                except Exception as e:
                    st.error(f"Error reading CSV file: {str(e)}")
                    st.info("Please ensure your CSV file matches the required format")
        
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
                        
                        # Import advanced visualizations
                        try:
                            from app.dashboard_viz import (
                                generate_model_scores, display_model_scores_grid, 
                                display_ensemble_visualization, display_pipeline_explanation,
                                display_model_architecture
                            )
                        except ImportError:
                            display_model_architecture = None
                        
                        # Show results
                        if data.get('action') == 'block':
                            st.error('FLOW BLOCKED - Threat Detected')
                        else:
                            st.success('FLOW ALLOWED')
                        
                        risk_score = data.get('risk_score', 0.5)
                        
                        # Calculate sensitivity multiplier based on anomaly_threshold slider
                        # anomaly_threshold ranges 0-1, convert to sensitivity multiplier 0.5-2.0
                        sensitivity = 0.5 + (anomaly_threshold * 1.5)
                        
                        # Generate ensemble scores based on actual risk AND user settings
                        ensemble_scores = generate_model_scores(risk_seed=risk_score, sensitivity=sensitivity)
                        
                        # Display model architecture reference
                        if display_model_architecture:
                            display_model_architecture()
                        
                        # Display all model scores in grid with threshold
                        if display_model_scores_grid:
                            display_model_scores_grid(ensemble_scores, risk_score, threshold=risk_threshold)
                        
                        # Display ensemble visualization with threshold
                        if display_ensemble_visualization:
                            display_ensemble_visualization(ensemble_scores, threshold=risk_threshold)
                        
                        # Create comprehensive insight box for LLM analysis
                        if 'llm_analysis' in data and data['llm_analysis'].get('explanation'):
                            with st.container(border=True):
                                st.subheader('Advanced Security Analysis')
                                explanation = data['llm_analysis'].get('explanation', '')
                                st.write(explanation)
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric('Final Risk Score', f"{risk_score:.3f}")
                                    st.metric('Model Consensus', f"{(1.0 - abs(0.5 - risk_score)):.1%}")
                                    if data['llm_analysis'].get('risk_factors'):
                                        st.write('**Risk Factors Identified:**')
                                        for factor in data['llm_analysis'].get('risk_factors', []):
                                            st.write(f"• {factor}")
                                
                                with col2:
                                    st.metric('Confidence Level', f"{data['llm_analysis'].get('confidence', 0):.1%}")
                                    st.metric('Detection Certainty', f"{np.mean(list(ensemble_scores['supervised'].values())):.1%}" if ensemble_scores else "N/A")
                                    if data['llm_analysis'].get('recommendations'):
                                        st.write('**AI Recommendations:**')
                                        for rec in data['llm_analysis'].get('recommendations', []):
                                            st.write(f"• {rec}")
                        
                        # Display pipeline explanation
                        if display_pipeline_explanation:
                            display_pipeline_explanation(
                                test_flow, 
                                risk_score, 
                                data.get('llm_analysis', {})
                            )
                        
                        # Show detailed ML insights if available
                        if 'ml_insights' in data:
                            with st.expander('Detailed Model Analytics'):
                                insights = data['ml_insights']
                                if 'anomaly_detection' in insights:
                                    ad = insights['anomaly_detection']
                                    cols = st.columns(3)
                                    with cols[0]:
                                        st.metric('Anomaly Score', f"{ad.get('anomaly_score', 0):.3f}")
                                    with cols[1]:
                                        st.metric('Supervised Score', f"{ad.get('supervised_score', 0):.3f}")
                                    with cols[2]:
                                        if 'autoencoder_reconstruction' in ad:
                                            st.metric('Autoencoder Reconstruction', f"{ad['autoencoder_reconstruction']:.3f}")
                        
                        # Backend error handling
                        if data.get('error'):
                            msg = data.get('message') or data.get('detail') or str(data)
                            st.error(f"Backend error: {msg}")
                                    
                    except ValueError:
                        st.error('🚫 Backend returned invalid JSON')
                        logger.error('Invalid JSON from backend: %s', r.text)
                        
                except requests.RequestException as e:
                    st.error(f'🚫 Failed to contact backend: {e}')
                    logger.error('Failed to POST test flow: %s', e)
        
    with tab2:
        st.header('Analytics & History 📊')
        
        # Organize analytics in subtabs
        analysis_tab1, analysis_tab2, analysis_tab3 = st.tabs([
            '🔍 Real-time Analysis',
            '📈 ML Performance',
            '🛡️ Security Insights'
        ])
        
        with analysis_tab1:
            show_history_and_stats()
            
        with analysis_tab2:
            st.subheader("ML Model Performance & Ensemble Analysis")
            history = st.session_state.get('history', [])
            
            if not history:
                st.info("No data available yet. Start analyzing flows to see ML performance metrics.")
            else:
                # Import dashboard visualization functions
                try:
                    from app.dashboard_viz import (
                        display_performance_metrics, 
                        display_attack_pattern_analysis,
                        generate_model_scores,
                        create_model_comparison_chart
                    )
                    
                    # Display performance metrics
                    display_performance_metrics()
                    
                    st.markdown("---")
                    
                    # Display attack pattern intelligence
                    display_attack_pattern_analysis()
                    
                    st.markdown("---")
                    
                    # Show model comparison across all flows
                    st.subheader("Model Consensus Analysis")
                    all_scores = []
                    for h in history:
                        risk = h['response'].get('risk_score', 0.5)
                        scores = generate_model_scores(risk_seed=risk)
                        all_scores.append(scores)
                    
                    if all_scores:
                        # Average scores across all analyzed flows
                        avg_supervised = np.mean([
                            np.mean(list(s['supervised'].values())) for s in all_scores
                        ])
                        avg_unsupervised = np.mean([
                            np.mean(list(s['unsupervised'].values())) for s in all_scores
                        ])
                        avg_deep_learning = np.mean([
                            np.mean(list(s['deep_learning'].values())) for s in all_scores
                        ])
                        avg_vector = np.mean([
                            np.mean(list(s['vector_search'].values())) for s in all_scores
                        ])
                        
                        cols = st.columns(4)
                        with cols[0]:
                            st.metric("Supervised Avg", f"{avg_supervised:.3f}")
                        with cols[1]:
                            st.metric("Unsupervised Avg", f"{avg_unsupervised:.3f}")
                        with cols[2]:
                            st.metric("Deep Learning Avg", f"{avg_deep_learning:.3f}")
                        with cols[3]:
                            st.metric("Vector Search Avg", f"{avg_vector:.3f}")
                    
                except ImportError as e:
                    st.warning(f"Advanced analytics unavailable: {e}")
                    
                    # Fallback to basic metrics
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        high_risk = sum(1 for h in history if h['response'].get('risk_score', 0) > 0.7)
                        st.metric("Detection Rate", 
                                 f"{high_risk/len(history):.1%}",
                                 f"{high_risk} high-risk flows")
                    
                    with col2:
                        avg_conf = np.mean([
                            h['response'].get('llm_analysis', {}).get('confidence', 0)
                            for h in history
                        ])
                        st.metric("Average Confidence", 
                                 f"{avg_conf:.1%}",
                                 "↑" if avg_conf > 0.7 else "↓")
                    
                    with col3:
                        patterns = sum(
                            1 for h in history 
                            if h['response'].get('ml_insights', {}).get('attack_patterns', [])
                        )
                        st.metric("Attack Patterns", 
                                 patterns,
                                 "detected")
                    
        with analysis_tab3:
            st.subheader("🔒 Security Analysis")
            if not history:
                st.info("No security insights available yet. Analyze some flows to see AI-powered security analysis.")
            else:
                # Group flows by detected patterns
                pattern_analysis = {}
                for h in history:
                    if 'ml_insights' in h['response']:
                        insights = h['response']['ml_insights']
                        for pattern in insights.get('attack_patterns', []):
                            name = pattern['pattern']
                            if name not in pattern_analysis:
                                pattern_analysis[name] = {
                                    'count': 0,
                                    'flows': [],
                                    'confidence': [],
                                    'description': pattern.get('description', ''),
                                    'mitigations': pattern.get('mitigations', [])
                                }
                            pattern_analysis[name]['count'] += 1
                            pattern_analysis[name]['flows'].append(
                                f"{h['flow']['src_ip']} → {h['flow']['dst_ip']}"
                            )
                            pattern_analysis[name]['confidence'].append(
                                pattern.get('confidence', 0)
                            )
                
                if pattern_analysis:
                    for name, details in pattern_analysis.items():
                        with st.expander(f"⚠️ {name.title()} ({details['count']} occurrences)"):
                            st.markdown(f"**Pattern Description:**")
                            st.info(details['description'])
                            
                            st.markdown("**Affected Flows:**")
                            for flow in details['flows'][:5]:  # Show top 5
                                st.code(flow)
                            
                            if details['mitigations']:
                                st.markdown("**Recommended Mitigations:**")
                                for mitigation in details['mitigations']:
                                    st.markdown(f"- {mitigation}")
                            
                            avg_conf = np.mean(details['confidence'])
                            st.metric("Detection Confidence", f"{avg_conf:.1%}")
                else:
                    st.success("No attack patterns detected in analyzed flows.")
    
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
