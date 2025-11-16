import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import os
import shap
import openai
import numpy as np
from dotenv import load_dotenv
from typing import Dict, List, Any, Tuple
from datetime import datetime
from utils.utils import load_config, setup_logging
import pandas as pd

# Load configuration
load_dotenv()
logger = setup_logging()
config = load_config()

# Configure OpenAI
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY') or config.get('openai_api_key')
OPENAI_API_BASE = os.getenv('OPENAI_API_BASE') or config.get('openai_api_base')
OPENAI_DEFAULT_MODEL = os.getenv('OPENAI_DEFAULT_MODEL') or config.get('openai_default_model') or 'gpt-4'

if not OPENAI_API_KEY:
    logger.warning('OpenAI API key not found in environment or config')

openai.api_key = OPENAI_API_KEY
if OPENAI_API_BASE:
    openai.api_base = OPENAI_API_BASE

# Common attack patterns and signatures
ATTACK_PATTERNS = {
    'port_scan': {
        'description': 'Sequential or distributed port scanning activity',
        'indicators': ['multiple ports', 'rapid succession', 'sequential ports']
    },
    'dos': {
        'description': 'Denial of Service attempt',
        'indicators': ['high packet rate', 'repeated connections', 'large byte volumes']
    },
    'c2c': {
        'description': 'Command and Control communication',
        'indicators': ['persistent connection', 'periodic beaconing', 'unusual ports']
    },
    'data_exfil': {
        'description': 'Data exfiltration attempt',
        'indicators': ['large outbound transfer', 'unusual destination', 'sensitive port']
    },
    'brute_force': {
        'description': 'Authentication brute force attempt',
        'indicators': ['repeated auth attempts', 'failed connections', 'auth ports']
    }
}

class MLInsightGenerator:
    def __init__(self, rf_model, iso_model=None):
        """Initialize with trained models."""
        self.rf_model = rf_model
        self.iso_model = iso_model
        self.explainer = shap.TreeExplainer(rf_model['model'])
        
    def get_feature_importance(self, flow_data: pd.DataFrame) -> List[Tuple[str, float]]:
        """Calculate SHAP values and feature importance."""
        shap_values = self.explainer.shap_values(flow_data)[1]
        return sorted(
            zip(flow_data.columns, np.abs(shap_values[0]).mean()),
            key=lambda x: x[1],
            reverse=True
        )
        
    def detect_anomalies(self, flow_data: pd.DataFrame) -> Dict[str, float]:
        """Detect anomalies using isolation forest."""
        if self.iso_model:
            anomaly_score = -self.iso_model['model'].score_samples(flow_data)
            return {
                'anomaly_score': float(anomaly_score[0]),
                'is_anomaly': anomaly_score[0] > 0.5
            }
        return {'anomaly_score': 0.0, 'is_anomaly': False}
        
    def identify_attack_patterns(self, flow: Dict[str, Any], risk_score: float) -> List[Dict[str, Any]]:
        """Identify potential attack patterns based on flow characteristics."""
        matches = []
        flow_str = str(flow).lower()
        
        for pattern_name, pattern in ATTACK_PATTERNS.items():
            match_count = sum(1 for ind in pattern['indicators'] if ind in flow_str)
            if match_count >= 2 or risk_score > 0.8:
                matches.append({
                    'pattern': pattern_name,
                    'description': pattern['description'],
                    'confidence': min(1.0, match_count * 0.3 + risk_score * 0.4)
                })
        
        return matches

def explain_detection(flow: Dict[str, Any], rf_model: Dict[str, Any], columns: List[str], risk_score: float) -> Dict[str, Any]:
    """Generate comprehensive ML-driven security analysis for a network flow."""
    # Initialize ML components
    ml_insights = MLInsightGenerator(rf_model)
    
    # Prepare flow data
    flow_df = pd.DataFrame([flow], columns=['src_ip', 'dst_ip'] + columns).drop(columns=['src_ip', 'dst_ip'])
    
    # Get ML insights
    feature_importance = ml_insights.get_feature_importance(flow_df)
    anomaly_info = ml_insights.detect_anomalies(flow_df)
    attack_patterns = ml_insights.identify_attack_patterns(flow, risk_score)
    
    # Prepare ML context for LLM
    ml_context = {
        'risk_score': risk_score,
        'top_features': feature_importance[:3],
        'anomaly_score': anomaly_info['anomaly_score'],
        'potential_attacks': attack_patterns,
        'flow_details': flow,
        'timestamp': datetime.now().isoformat()
    }
    
    # Generate LLM explanation
    try:
        prompt = f"""As a cybersecurity expert, analyze this network flow:

Risk Assessment:
- Risk Score: {risk_score:.2f}
- Anomaly Score: {anomaly_info['anomaly_score']:.2f}

Top Contributing Features:
{chr(10).join(f'- {feat}: {imp:.3f}' for feat, imp in feature_importance[:3])}

Potential Attack Patterns:
{chr(10).join(f'- {p["pattern"]}: {p["description"]} (Confidence: {p["confidence"]:.2f})' for p in attack_patterns)}

Flow Details:
{chr(10).join(f'- {k}: {v}' for k, v in flow.items())}

Provide a detailed security analysis including:
1. Primary security concerns
2. Technical analysis of the traffic pattern
3. Potential impact and risks
4. Mitigation recommendations
5. Confidence level in the assessment

Format the response as JSON with keys: explanation, security_concerns, technical_analysis, impact, recommendations, confidence"""

        response = openai.chat.completions.create(
            model=OPENAI_DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity analyst specializing in network intrusion detection."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            response_format={"type": "json_object"}
        )
        
        # Parse and enhance LLM response
        analysis = response.choices[0].message.content
        enhanced_response = {
            'ml_insights': {
                'feature_importance': feature_importance,
                'anomaly_detection': anomaly_info,
                'attack_patterns': attack_patterns
            },
            'llm_analysis': analysis,
            'timestamp': datetime.now().isoformat(),
            'model_version': rf_model.get('version', 'unknown')
        }
        
        logger.info(f'Generated enhanced analysis for flow from {flow["src_ip"]}')
        return enhanced_response
        
    except Exception as e:
        logger.error(f'Analysis generation error: {e}')
        return {
            'error': str(e),
            'ml_insights': {
                'feature_importance': feature_importance,
                'anomaly_detection': anomaly_info,
                'attack_patterns': attack_patterns
            },
            'timestamp': datetime.now().isoformat()
        }
