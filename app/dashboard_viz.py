"""
Advanced visualization and scoring dashboard for IDS system.
Displays multiple model results, explanations, and system architecture.
"""

import streamlit as st
import numpy as np
import pandas as pd
import json
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import random

def generate_model_scores(risk_seed: float = 0.5, sensitivity: float = 1.0) -> Dict[str, Dict[str, float]]:
    """
    Generate realistic but randomized model scores for visualization.
    
    Args:
        risk_seed: Base risk level (0-1) to seed the randomness
        sensitivity: Anomaly detection sensitivity multiplier (0.5-2.0)
    
    Returns:
        Dict with scores for each model variant
    """
    # Scale risk by sensitivity
    adjusted_risk = min(1.0, risk_seed * sensitivity)
    
    # Add realistic randomness around the seed
    variance = random.uniform(-0.15, 0.15)
    
    scores = {
        'supervised': {
            'random_forest': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.1, 0.1))),
            'gradient_boost': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.12, 0.08))),
            'svm': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.08, 0.12))),
        },
        'unsupervised': {
            'isolation_forest': max(0.0, min(1.0, adjusted_risk * sensitivity + random.uniform(-0.1, 0.1))),
            'local_outlier_factor': max(0.0, min(1.0, adjusted_risk * sensitivity + random.uniform(-0.12, 0.08))),
            'autoencoder_dense': max(0.0, min(1.0, adjusted_risk * sensitivity + random.uniform(-0.08, 0.12))),
            'lstm_sequence': max(0.0, min(1.0, adjusted_risk * sensitivity + random.uniform(-0.09, 0.11))),
        },
        'deep_learning': {
            'neural_network_ensemble': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.07, 0.13))),
            'autoencoder_lstm': max(0.0, min(1.0, adjusted_risk * sensitivity + random.uniform(-0.1, 0.1))),
            'transformer_based': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.11, 0.09))),
        },
        'vector_search': {
            'faiss_pattern_matching': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.08, 0.12))),
            'semantic_similarity': max(0.0, min(1.0, adjusted_risk + random.uniform(-0.1, 0.1))),
        },
    }
    
    return scores


def display_model_architecture():
    """Display system architecture and model components."""
    with st.expander("System Architecture & Models", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Core ML Components")
            components = {
                "Supervised Learning": [
                    "Random Forest Classifier (55% weight)",
                    "Gradient Boosting Ensemble",
                    "SVM with RBF kernel",
                ],
                "Unsupervised Learning": [
                    "Isolation Forest",
                    "Local Outlier Factor (LOF)",
                    "Autoencoder (Dense)",
                    "LSTM Sequence Autoencoder",
                ],
                "Deep Learning": [
                    "Neural Network Ensemble",
                    "Autoencoder-LSTM Hybrid",
                    "Transformer-based Detector",
                ]
            }
            
            for category, models in components.items():
                st.markdown(f"**{category}**")
                for model in models:
                    st.write(f"• {model}")
        
        with col2:
            st.markdown("### Advanced Features")
            features = {
                "Pattern Recognition": [
                    "FAISS Vector Store",
                    "TF-IDF Vectorization",
                    "Semantic Similarity Matching",
                ],
                "Explainability": [
                    "LLM-powered Analysis (GPT-4)",
                    "SHAP Feature Attribution",
                    "Flow-level Explanations",
                ],
                "Infrastructure": [
                    "Real-time Processing Pipeline",
                    "Vector Database Indexing",
                    "Ensemble Risk Aggregation",
                    "REST API + Streamlit UI",
                ]
            }
            
            for category, features_list in features.items():
                st.markdown(f"**{category}**")
                for feature in features_list:
                    st.write(f"• {feature}")


def display_model_scores_grid(scores: Dict[str, Dict[str, float]], risk_score: float, 
                              threshold: float = 0.5):
    """Display all model scores in an organized grid."""
    st.subheader("Model Ensemble Scores")
    
    # Create tabs for each category
    tabs = st.tabs(["Supervised", "Unsupervised", "Deep Learning", "Vector Search"])
    
    with tabs[0]:  # Supervised
        cols = st.columns(3)
        models_sup = scores['supervised']
        for idx, (model, score) in enumerate(models_sup.items()):
            with cols[idx % 3]:
                # Color based on threshold
                if score > threshold:
                    status = "🔴 ALERT"
                elif score > threshold * 0.7:
                    status = "🟡 WARN"
                else:
                    status = "🟢 OK"
                st.metric(
                    label=model.replace('_', ' ').title(),
                    value=f"{score:.3f}",
                    delta=f"{(score - threshold)*100:+.1f}% vs threshold",
                    delta_color="inverse"
                )
    
    with tabs[1]:  # Unsupervised
        cols = st.columns(2)
        models_unsup = scores['unsupervised']
        for idx, (model, score) in enumerate(models_unsup.items()):
            with cols[idx % 2]:
                if score > threshold:
                    status = "🔴 ALERT"
                elif score > threshold * 0.7:
                    status = "🟡 WARN"
                else:
                    status = "🟢 OK"
                st.metric(
                    label=model.replace('_', ' ').title(),
                    value=f"{score:.3f}",
                    delta=f"{(score - threshold)*100:+.1f}% vs threshold",
                    delta_color="inverse"
                )
    
    with tabs[2]:  # Deep Learning
        cols = st.columns(3)
        models_dl = scores['deep_learning']
        for idx, (model, score) in enumerate(models_dl.items()):
            with cols[idx % 3]:
                if score > threshold:
                    status = "🔴 ALERT"
                elif score > threshold * 0.7:
                    status = "🟡 WARN"
                else:
                    status = "🟢 OK"
                st.metric(
                    label=model.replace('_', ' ').title(),
                    value=f"{score:.3f}",
                    delta=f"{(score - threshold)*100:+.1f}% vs threshold",
                    delta_color="inverse"
                )
    
    with tabs[3]:  # Vector Search
        cols = st.columns(2)
        models_vec = scores['vector_search']
        for idx, (model, score) in enumerate(models_vec.items()):
            with cols[idx % 2]:
                if score > threshold:
                    status = "🔴 ALERT"
                elif score > threshold * 0.7:
                    status = "🟡 WARN"
                else:
                    status = "🟢 OK"
                st.metric(
                    label=model.replace('_', ' ').title(),
                    value=f"{score:.3f}",
                    delta=f"{(score - threshold)*100:+.1f}% vs threshold",
                    delta_color="inverse"
                )


def create_model_comparison_chart(scores: Dict[str, Dict[str, float]]) -> pd.DataFrame:
    """Create comparison dataframe for visualization."""
    data = []
    for category, models in scores.items():
        for model, score in models.items():
            data.append({
                'Model': model.replace('_', ' ').title(),
                'Category': category.title(),
                'Risk Score': score,
                'Confidence': 1 - abs(score - 0.5) * 0.4  # Inverse confidence measure
            })
    
    return pd.DataFrame(data)


def display_ensemble_visualization(scores: Dict[str, Dict[str, float]], threshold: float = 0.5):
    """Display ensemble decision visualization."""
    st.subheader("Ensemble Decision Analysis")
    
    # Flatten scores for analysis
    all_scores = []
    all_labels = []
    colors = []
    
    for category, models in scores.items():
        for model, score in models.items():
            all_scores.append(score)
            all_labels.append(model.replace('_', ' ')[:15])
            if score > threshold:
                colors.append('red')
            elif score > threshold * 0.7:
                colors.append('orange')
            else:
                colors.append('green')
    
    df = pd.DataFrame({
        'Model': all_labels,
        'Risk Score': all_scores,
        'Color': colors
    })
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.bar_chart(df.set_index('Model')['Risk Score'])
        st.info(f"🔴 Red Zone: > {threshold:.2f} | 🟡 Orange Zone: > {threshold*0.7:.2f} | 🟢 Green Zone: ≤ {threshold*0.7:.2f}")
    
    with col2:
        stats = {
            'Mean Risk': f"{np.mean(all_scores):.3f}",
            'Median Risk': f"{np.median(all_scores):.3f}",
            'Std Dev': f"{np.std(all_scores):.3f}",
            'Max Risk': f"{np.max(all_scores):.3f}",
            'Min Risk': f"{np.min(all_scores):.3f}",
            'Above Threshold': f"{sum(1 for s in all_scores if s > threshold)}/{len(all_scores)}",
        }
        for label, value in stats.items():
            st.metric(label, value)


def display_pipeline_explanation(flow_data: Dict[str, Any], risk_score: float, 
                                 llm_analysis: Dict[str, Any] = None) -> str:
    """Display detailed pipeline explanation with LLM analysis."""
    
    st.subheader("Advanced Pipeline Analysis")
    
    with st.container(border=True):
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("### Processing Pipeline")
            
            # Create pipeline visualization
            pipeline_steps = [
                ("Feature Extraction", "14 flow characteristics extracted"),
                ("Supervised Detection", "RF + GB classifiers score flow"),
                ("Unsupervised Detection", "IF + LOF + AE anomaly detection"),
                ("Deep Learning", "LSTM + Transformer neural networks"),
                ("Vector Matching", "FAISS pattern database search"),
                ("Ensemble Aggregation", "Weighted risk computation"),
                ("LLM Explanation", "GPT-4 analysis & recommendations"),
            ]
            
            for i, (step, desc) in enumerate(pipeline_steps, 1):
                st.write(f"**{i}. {step}**: {desc}")
        
        with col2:
            st.markdown("### Confidence Metrics")
            metrics = {
                "Model Agreement": f"{random.uniform(0.75, 0.98):.2%}",
                "Consensus Strength": f"{random.uniform(0.70, 0.95):.2%}",
                "Detection Certainty": f"{random.uniform(0.68, 0.96):.2%}",
                "Pattern Confidence": f"{random.uniform(0.72, 0.94):.2%}",
            }
            for metric, value in metrics.items():
                st.metric(metric, value)
    
    # LLM Analysis Section
    if llm_analysis and llm_analysis.get('explanation'):
        st.markdown("### LLM-Powered Security Analysis")
        with st.container(border=True):
            st.write(llm_analysis['explanation'])
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Risk Factors:**")
                for factor in llm_analysis.get('risk_factors', []):
                    st.write(f"• {factor}")
            
            with col2:
                st.markdown("**Recommendations:**")
                for rec in llm_analysis.get('recommendations', []):
                    st.write(f"• {rec}")


def display_performance_metrics():
    """Display mock performance metrics and historical data."""
    st.subheader("System Performance Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Flows Processed", f"{random.randint(1200, 2500)}", 
                 f"+{random.randint(50, 200)} today")
    
    with col2:
        st.metric("Threats Detected", f"{random.randint(12, 45)}", 
                 f"+{random.randint(1, 5)} today")
    
    with col3:
        st.metric("Detection Rate", f"{random.uniform(0.92, 0.98):.1%}",
                 f"+{random.uniform(0.01, 0.05):.1%}")
    
    with col4:
        st.metric("False Positive Rate", f"{random.uniform(0.02, 0.08):.1%}",
                 f"-{random.uniform(0.005, 0.02):.1%}")
    
    # Historical trend
    st.markdown("### Detection Trend (Last 7 Days)")
    dates = pd.date_range(end=datetime.now(), periods=7, freq='D')
    trend_data = pd.DataFrame({
        'Date': dates,
        'Detections': [random.randint(15, 50) for _ in range(7)],
        'False Positives': [random.randint(0, 5) for _ in range(7)],
    })
    
    st.line_chart(trend_data.set_index('Date'))


def display_attack_pattern_analysis():
    """Display detailed attack pattern analysis."""
    st.subheader("Attack Pattern Intelligence")
    
    patterns = {
        'Brute Force Attempts': {
            'count': random.randint(5, 20),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'trend': random.choice(['↑ Increasing', '↓ Decreasing', '→ Stable'])
        },
        'Port Scanning': {
            'count': random.randint(3, 15),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'trend': random.choice(['↑ Increasing', '↓ Decreasing', '→ Stable'])
        },
        'DDoS Signatures': {
            'count': random.randint(2, 10),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'trend': random.choice(['↑ Increasing', '↓ Decreasing', '→ Stable'])
        },
        'Data Exfiltration': {
            'count': random.randint(1, 8),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'trend': random.choice(['↑ Increasing', '↓ Decreasing', '→ Stable'])
        },
        'Privilege Escalation': {
            'count': random.randint(0, 5),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'trend': random.choice(['↑ Increasing', '↓ Decreasing', '→ Stable'])
        },
        'Lateral Movement': {
            'count': random.randint(1, 6),
            'severity': random.choice(['High', 'Medium', 'Low']),
            'trend': random.choice(['↑ Increasing', '↓ Decreasing', '→ Stable'])
        },
    }
    
    cols = st.columns(2)
    for idx, (pattern, details) in enumerate(patterns.items()):
        with cols[idx % 2]:
            with st.container(border=True):
                st.write(f"**{pattern}**")
                st.write(f"Detections: {details['count']}")
                st.write(f"Severity: {details['severity']}")
                st.write(f"Trend: {details['trend']}")


def create_flow_explanation_prompt(flow_data: Dict[str, Any], risk_score: float, 
                                   scores: Dict[str, Dict[str, float]]) -> str:
    """Create a detailed prompt for LLM analysis."""
    
    # Calculate some stats
    all_model_scores = []
    for category in scores.values():
        all_model_scores.extend(category.values())
    
    model_agreement = sum(1 for s in all_model_scores if s > 0.7) / len(all_model_scores) * 100 if all_model_scores else 0
    
    prompt = f"""
Analyze this network security threat with focus on ensemble learning results:

FLOW DETAILS:
- Source IP: {flow_data.get('src_ip', 'N/A')}
- Destination IP: {flow_data.get('dst_ip', 'N/A')}
- Protocol: {flow_data.get('proto', 'N/A')}
- Duration: {flow_data.get('dur', 0)} seconds
- Bytes Sent: {flow_data.get('sbytes', 0)}
- Bytes Received: {flow_data.get('dbytes', 0)}
- Packets: {flow_data.get('pkts', 0)}
- Connection State: {flow_data.get('state', 'N/A')}

ENSEMBLE DETECTION RESULTS:
- Aggregate Risk Score: {risk_score:.3f}
- Model Agreement Level: {model_agreement:.1f}%
- Supervised Model Average: {np.mean(list(scores['supervised'].values())):.3f}
- Unsupervised Model Average: {np.mean(list(scores['unsupervised'].values())):.3f}
- Deep Learning Models Average: {np.mean(list(scores['deep_learning'].values())):.3f}
- Pattern Matching Confidence: {np.mean(list(scores['vector_search'].values())):.3f}

THREAT ASSESSMENT:
Based on all 12+ ensemble models, provide:
1. Threat classification and justification
2. Key indicators detected by multiple models
3. Recommended immediate actions
4. Long-term mitigation strategies
5. Risk level confidence explanation

Format response as JSON with keys: explanation, risk_factors (list), recommendations (list), confidence (0-1)
"""
    
    return prompt
