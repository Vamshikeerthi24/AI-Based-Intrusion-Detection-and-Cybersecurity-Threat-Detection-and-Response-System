from typing import List, Dict, Any
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from datetime import datetime

def create_threat_analysis_visual(history):
    """Create threat analysis visualization."""
    if not history:
        return
    
    # Prepare data
    data = []
    for item in history:
        if 'response' not in item:
            continue
            
        response = item['response']
        data.append({
            'timestamp': datetime.fromisoformat(response.get('timestamp', datetime.now().isoformat())),
            'risk_score': response.get('risk_score', 0),
            'anomaly_score': response.get('ml_insights', {}).get('anomaly_detection', {}).get('anomaly_score', 0),
            'src_ip': item['flow']['src_ip'],
            'dst_ip': item['flow']['dst_ip'],
            'protocol': item['flow']['proto'],
            'bytes_total': item['flow']['sbytes'] + item['flow']['dbytes']
        })
    
    if not data:
        return None
        
    df = pd.DataFrame(data)
    
    # Create visualization
    fig = go.Figure()
    
    # Risk score line
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['risk_score'],
        name='Risk Score',
        line=dict(color='red', width=2),
        hovertemplate='Risk Score: %{y:.2f}<br>Time: %{x}'
    ))
    
    # Anomaly score line
    fig.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['anomaly_score'],
        name='Anomaly Score',
        line=dict(color='orange', width=2, dash='dash'),
        hovertemplate='Anomaly Score: %{y:.2f}<br>Time: %{x}'
    ))
    
    fig.update_layout(
        title='Threat Analysis Timeline',
        xaxis_title='Time',
        yaxis_title='Score',
        hovermode='x unified',
        showlegend=True
    )
    
    return fig

def create_network_flow_visual(history):
    """Create network flow visualization."""
    if not history:
        return
    
    # Prepare data
    edges = []
    nodes = set()
    for item in history:
        if 'flow' not in item:
            continue
            
        flow = item['flow']
        response = item.get('response', {})
        
        src = flow['src_ip']
        dst = flow['dst_ip']
        nodes.add(src)
        nodes.add(dst)
        
        edges.append({
            'source': src,
            'target': dst,
            'value': flow['sbytes'] + flow['dbytes'],
            'risk': response.get('risk_score', 0),
            'protocol': flow['proto']
        })
    
    if not edges:
        return None
        
    # Create node positions using a circular layout
    num_nodes = len(nodes)
    node_positions = {}
    for i, node in enumerate(nodes):
        angle = 2 * np.pi * i / num_nodes
        node_positions[node] = (np.cos(angle), np.sin(angle))
    
    # Create visualization
    edge_x = []
    edge_y = []
    edge_colors = []
    
    for edge in edges:
        x0, y0 = node_positions[edge['source']]
        x1, y1 = node_positions[edge['target']]
        
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_colors.extend([edge['risk']] * 3)
    
    # Create edges trace
    edges_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color=edge_colors, colorscale='RdYlBu_r'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Create nodes trace
    node_x = []
    node_y = []
    node_text = []
    
    for node in nodes:
        x, y = node_positions[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node)
    
    nodes_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition='top center',
        marker=dict(
            size=10,
            color='lightblue',
            line=dict(width=2)
        )
    )
    
    # Create figure
    fig = go.Figure(data=[edges_trace, nodes_trace])
    fig.update_layout(
        title='Network Flow Graph',
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20,l=5,r=5,t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    
    return fig

def create_attack_pattern_visual(history):
    """Create attack pattern visualization."""
    if not history:
        return
        
    # Collect attack patterns
    patterns = {}
    for item in history:
        if 'response' not in item or 'ml_insights' not in item['response']:
            continue
            
        insights = item['response']['ml_insights']
        if 'attack_patterns' in insights:
            for pattern in insights['attack_patterns']:
                name = pattern['pattern']
                if name not in patterns:
                    patterns[name] = {
                        'count': 0,
                        'confidence_sum': 0,
                        'description': pattern['description']
                    }
                patterns[name]['count'] += 1
                patterns[name]['confidence_sum'] += pattern.get('confidence', 0)
    
    if not patterns:
        return None
        
    # Prepare data for visualization
    pattern_names = list(patterns.keys())
    counts = [patterns[p]['count'] for p in pattern_names]
    avg_confidence = [patterns[p]['confidence_sum']/patterns[p]['count'] 
                     for p in pattern_names]
    
    # Create figure
    fig = go.Figure()
    
    # Add bars for count
    fig.add_trace(go.Bar(
        x=pattern_names,
        y=counts,
        name='Occurrence Count',
        marker_color='lightblue'
    ))
    
    # Add line for confidence
    fig.add_trace(go.Scatter(
        x=pattern_names,
        y=avg_confidence,
        name='Avg Confidence',
        yaxis='y2',
        line=dict(color='red', width=2)
    ))
    
    # Update layout
    fig.update_layout(
        title='Attack Pattern Analysis',
        yaxis=dict(title='Count'),
        yaxis2=dict(
            title='Average Confidence',
            overlaying='y',
            side='right'
        ),
        hovermode='x unified',
        barmode='relative'
    )
    
    return fig

def render_visuals(history: List[Dict[str, Any]]) -> None:
    """Render enhanced visualizations for IDS analysis."""
    try:
        if not history:
            st.info('No session history yet. Send some test flows to generate stats.')
            return

        st.subheader("🎯 ML-Enhanced Analysis")
        
        # Create columns for key metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            total_flows = len(history)
            high_risk = sum(1 for h in history if h['response'].get('risk_score', 0) > 0.7)
            st.metric(
                "Detection Rate",
                f"{high_risk/total_flows:.1%}",
                f"{high_risk} high-risk flows"
            )
            
        with col2:
            avg_risk = np.mean([h['response'].get('risk_score', 0) for h in history])
            st.metric(
                "Average Risk",
                f"{avg_risk:.2f}",
                "↑" if avg_risk > 0.5 else "↓"
            )
            
        with col3:
            pattern_count = sum(
                1 for h in history 
                if 'ml_insights' in h['response'] 
                and h['response']['ml_insights'].get('attack_patterns', [])
            )
            st.metric(
                "Attack Patterns",
                pattern_count,
                "detected"
            )
        
        # Show visualizations
        st.subheader("📊 ML Model Analysis")
        
        # Create tabs for different visualizations
        viz_tab1, viz_tab2, viz_tab3 = st.tabs([
            '📈 Risk Analysis',
            '🌐 Network Graph',
            '⚠️ Attack Patterns'
        ])
        
        with viz_tab1:
            # Threat timeline
            threat_fig = create_threat_analysis_visual(history)
            if threat_fig:
                st.plotly_chart(threat_fig, use_container_width=True)
                
                # Add risk distribution
                risks = [h['response'].get('risk_score', 0) for h in history]
                fig = px.histogram(
                    pd.DataFrame({'Risk Score': risks}),
                    x='Risk Score',
                    nbins=20,
                    title='Risk Score Distribution'
                )
                fig.add_vline(x=0.7, line_dash="dash", line_color="red",
                             annotation_text="High Risk Threshold")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Not enough data for risk analysis")
            
        with viz_tab2:
            # Network flow visualization
            flow_fig = create_network_flow_visual(history)
            if flow_fig:
                st.plotly_chart(flow_fig, use_container_width=True)
                
                # Add flow statistics
                st.subheader("Flow Statistics")
                col1, col2 = st.columns(2)
                
                with col1:
                    # Source IP distribution
                    src_ips = pd.DataFrame([
                        h['flow']['src_ip'] for h in history
                    ]).value_counts()
                    st.metric("Unique Source IPs", len(src_ips))
                    st.write("Top Sources:")
                    st.dataframe(src_ips.head())
                    
                with col2:
                    # Protocol distribution
                    protocols = pd.DataFrame([
                        h['flow']['proto'] for h in history
                    ]).value_counts()
                    st.metric("Protocols Used", len(protocols))
                    st.write("Protocol Distribution:")
                    st.dataframe(protocols)
            else:
                st.info("Not enough flow data for visualization")
                
        with viz_tab3:
            pattern_fig = create_attack_pattern_visual(history)
            if pattern_fig:
                st.plotly_chart(pattern_fig, use_container_width=True)
                
                # Add pattern timeline
                patterns = []
                for h in history:
                    if 'ml_insights' in h['response']:
                        insights = h['response']['ml_insights']
                        for pattern in insights.get('attack_patterns', []):
                            patterns.append({
                                'timestamp': h['response'].get('timestamp'),
                                'pattern': pattern['pattern'],
                                'confidence': pattern['confidence']
                            })
                
                if patterns:
                    df_patterns = pd.DataFrame(patterns)
                    fig = px.line(
                        df_patterns,
                        x='timestamp',
                        y='confidence',
                        color='pattern',
                        title='Attack Pattern Detection Timeline'
                    )
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No attack patterns detected yet")
        
        # AI Insights section
        st.subheader("🤖 AI Security Insights")
        
        # Group similar patterns
        pattern_groups = {}
        for item in history:
            if 'ml_insights' not in item['response']:
                continue
                
            insights = item['response']['ml_insights']
            if 'attack_patterns' in insights:
                for pattern in insights['attack_patterns']:
                    key = pattern['pattern']
                    if key not in pattern_groups:
                        pattern_groups[key] = {
                            'count': 0,
                            'description': pattern['description'],
                            'examples': [],
                            'mitigations': set()
                        }
                    pattern_groups[key]['count'] += 1
                    if len(pattern_groups[key]['examples']) < 3:  # Keep only 3 examples
                        pattern_groups[key]['examples'].append(
                            f"{item['flow']['src_ip']} → {item['flow']['dst_ip']}"
                        )
                    # Add suggested mitigations
                    if 'mitigations' in pattern:
                        pattern_groups[key]['mitigations'].update(pattern['mitigations'])
        
        if pattern_groups:
            for pattern, details in pattern_groups.items():
                with st.expander(f"🔍 {pattern} ({details['count']} occurrences)"):
                    st.markdown(f"**Description:** {details['description']}")
                    
                    if details['examples']:
                        st.markdown("**Example Flows:**")
                        for ex in details['examples']:
                            st.markdown(f"- `{ex}`")
                    
                    if details['mitigations']:
                        st.markdown("**Recommended Mitigations:**")
                        for mitigation in details['mitigations']:
                            st.markdown(f"- {mitigation}")
        else:
            st.info("No security insights available yet. Start analyzing flows to generate AI-powered insights.")
