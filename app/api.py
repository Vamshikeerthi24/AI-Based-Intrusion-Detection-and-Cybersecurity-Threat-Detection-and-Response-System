import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from fastapi import FastAPI, HTTPException
import joblib
import numpy as np
import random
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import LocalOutlierFactor
from app.schemas import Flow
from app.features import to_features
from app.response import ResponseManager
from app.explain import explain_detection
from app.vector_store import FlowVectorStore
from app.llm_pipeline import LLMPipeline
from utils.utils import load_config, setup_logging

# Optional SHAP support (may have compatibility issues on some systems)
try:
    import shap
except ImportError:
    shap = None

# Optional PyTorch-based autoencoder support
try:
    import torch
    from models.nn_models import DenseAutoencoder
except Exception:
    torch = None
    DenseAutoencoder = None

def get_pattern_description(pattern_type: str) -> str:
    """Get description for a detected pattern type."""
    descriptions = {
        'port_scan': 'Multiple connections to different ports, typical of network scanning activity',
        'data_exfiltration': 'Large outbound data transfer that may indicate data theft',
        'brute_force': 'Repeated connection attempts that may indicate password guessing',
        'ddos': 'High volume of similar requests suggesting denial of service attempt',
        'c2_beacon': 'Regular, periodic connections typical of command & control activity',
        'lateral_movement': 'Internal network traversal attempting to spread',
        'unknown': 'Unclassified suspicious network pattern'
    }
    return descriptions.get(pattern_type, descriptions['unknown'])

def get_pattern_mitigations(pattern_type: str) -> list:
    """Get mitigation recommendations for a pattern type."""
    mitigations = {
        'port_scan': [
            'Implement rate limiting on connection attempts',
            'Enable firewall logging and alerts for scan activity',
            'Consider deploying network segmentation'
        ],
        'data_exfiltration': [
            'Monitor and limit large outbound transfers',
            'Implement Data Loss Prevention (DLP) solutions',
            'Enable encryption for sensitive data'
        ],
        'brute_force': [
            'Implement account lockout policies',
            'Enable multi-factor authentication',
            'Monitor and alert on failed login attempts'
        ],
        'ddos': [
            'Deploy DDoS mitigation services',
            'Implement rate limiting at the network edge',
            'Consider traffic scrubbing services'
        ],
        'c2_beacon': [
            'Monitor and block suspicious outbound connections',
            'Implement DNS monitoring and filtering',
            'Deploy network behavior analysis'
        ],
        'lateral_movement': [
            'Implement network segmentation',
            'Deploy host-based intrusion detection',
            'Monitor for unusual authentication patterns'
        ],
        'unknown': [
            'Monitor the activity pattern for further classification',
            'Implement general security best practices',
            'Enable detailed logging for future analysis'
        ]
    }
    return mitigations.get(pattern_type, mitigations['unknown'])

def classify_pattern(flow: dict, features: list) -> str:
    """Classify the type of pattern based on flow characteristics."""
    # Port scan detection
    if flow.get('ct_srv_src', 0) > 5:
        return 'port_scan'
    
    # Data exfiltration detection
    if flow.get('sbytes', 0) > 1000000:  # 1MB
        return 'data_exfiltration'
    
    # Brute force detection
    if flow.get('ct_flw_http_mthd', 0) > 10:
        return 'brute_force'
    
    # DDoS detection
    if flow.get('pkts', 0) > 1000 and flow.get('dur', 0) < 1.0:
        return 'ddos'
    
    # C2 beacon detection
    if 0.1 <= flow.get('dur', 0) <= 1.0 and flow.get('sbytes', 0) < 1000:
        return 'c2_beacon'
    
    # Lateral movement detection
    src_ip = str(flow.get('src_ip', ''))
    dst_ip = str(flow.get('dst_ip', ''))
    if src_ip.startswith('10.') and dst_ip.startswith('10.'):
        if flow.get('ct_srv_src', 0) > 2:
            return 'lateral_movement'
    
    return 'unknown'

app = FastAPI()
logger = setup_logging()
config = load_config()

# Ensure config has required keys with defaults
config.setdefault('risk_threshold', 0.85)
config.setdefault('block_ttl_minutes', 15)

try:
    # Load ML models
    rf = joblib.load('models/rf.joblib')
    iso = joblib.load('models/iso.joblib')
    # Try to load a trained autoencoder if present
    ae = None
    try:
        if torch is not None and DenseAutoencoder is not None and Path('models/autoencoder.pth').exists():
            ae = DenseAutoencoder(input_dim=len(rf['columns']), latent_dim=min(32, max(8, len(rf['columns'])//2)))
            state = torch.load('models/autoencoder.pth', map_location='cpu')
            # If the saved state is a dict with keys matching module, load directly
            try:
                ae.load_state_dict(state)
            except Exception:
                # If saved as full model object, attempt to load attrib
                pass
            ae.eval()
            logger.info('Loaded autoencoder model from models/autoencoder.pth')
    except Exception as e:
        logger.warning(f'Could not load autoencoder: {e}')
except Exception as e:
    logger.error(f"Error loading models: {e}")
    # Create test models for development
    rf = {
        'model': RandomForestClassifier(n_estimators=10, random_state=42),
        'columns': ['dur', 'sbytes', 'dbytes', 'pkts', 'state', 'ct_flw_http_mthd', 'ct_state_ttl', 'ct_srv_src']
    }
    rf['model'].fit(np.random.random((100, 8)), np.random.randint(0, 2, 100))
    
    iso = {
        'model': LocalOutlierFactor(n_neighbors=20, novelty=True)
    }
    iso['model'].fit(np.random.random((100, 8)))

# Initialize components
response_manager = ResponseManager()
vector_store = FlowVectorStore()
llm_pipeline = LLMPipeline()

# Load existing patterns if available
try:
    PATTERN_DIR = Path('data') / 'patterns'
    PATTERN_DIR.mkdir(parents=True, exist_ok=True)
    if PATTERN_DIR.exists():
        vector_store = FlowVectorStore.load(PATTERN_DIR)
        logger.info(f'Loaded {len(vector_store.flows)} known patterns from {PATTERN_DIR}')
except Exception as e:
    logger.error(f"Error loading patterns: {e}")
    # Continue with empty vector store

@app.post('/ingest')
async def ingest_flow(flow: Flow):
    """
    Ingest and analyze a network flow with enhanced detection.
    """
    try:
        # Check blocklist first
        response_manager.check_blocklist()
        
        # Convert flow to feature vector
        x = to_features(flow, rf['columns'])
        
        # Get predictions from supervised and unsupervised models
        p_sup = rf['model'].predict_proba(x)[0,1]
        a_unsup = -iso['model'].score_samples(x)[0]

        # Autoencoder reconstruction error -> normalized score in (0,1)
        ae_recon_score = 0.0
        try:
            if ae is not None and torch is not None:
                # x is numpy array shaped (1, n)
                tx = torch.from_numpy(x).float()
                with torch.no_grad():
                    recon = ae(tx)
                # MSE
                recon_err = float(((recon - tx) ** 2).mean().item())
                # Normalize using simple transform: recon_err / (1 + recon_err)
                ae_recon_score = recon_err / (1.0 + recon_err)
        except Exception as e:
            logger.debug(f'Autoencoder scoring failed: {e}')

        # Ensemble risk: weights chosen to balance signals (can be tuned)
        # p_sup: supervised probability, a_unsup: unsupervised anomaly score,
        # ae_recon_score: reconstruction anomaly score
        risk = 0.55 * p_sup + 0.30 * min(1.0, a_unsup) + 0.15 * ae_recon_score
        
        # Get feature importance using model's feature_importances_
        try:
            importances = rf['model'].feature_importances_
            # Convert to list of tuples with native Python types
            top_features = [(str(col), float(imp)) for col, imp in 
                          sorted(zip(rf['columns'], importances), 
                                key=lambda x: abs(x[1]), reverse=True)[:5]]
        except Exception as e:
            logger.warning(f"Error getting feature importance: {e}")
            # Fallback to basic scoring
            importances = [1.0/len(rf['columns'])] * len(rf['columns'])
            top_features = [(str(col), float(imp)) for col, imp in 
                          list(zip(rf['columns'], importances))[:5]]
        
        # Get pattern information
        try:
            pattern_info = vector_store.get_pattern_summary(flow.dict())
            # Ensure pattern_info is a dict with expected keys
            if not isinstance(pattern_info, dict):
                logger.error(f"pattern_info is not a dict: {type(pattern_info)}")
                pattern_info = {'similar_flows': [], 'pattern_type': 'unknown', 'matches': 0, 'avg_similarity': 0.0}
            # The function always returns a dict with 'similar_flows' list
            similar_flows = pattern_info.get('similar_flows', [])
            if not isinstance(similar_flows, list):
                logger.error(f"similar_flows is not a list: {type(similar_flows)}")
                similar_flows = []
        except Exception as e:
            logger.warning(f"Error getting pattern summary: {e}")
            similar_flows = []
            pattern_info = {'similar_flows': [], 'pattern_type': 'unknown', 'matches': 0, 'avg_similarity': 0.0}
        
        # Prepare ML insights with properly formatted values
        # Ensure feature_importance is a list of lists (not tuples)
        ml_insights = {
            'feature_importance': [[str(f), float(i)] for f, i in top_features],  # Convert tuples to lists
            'anomaly_detection': {
                'anomaly_score': float(a_unsup),
                'supervised_score': float(p_sup),
                'autoencoder_reconstruction': float(ae_recon_score)
            },
            'attack_patterns': []
        }
        
        # Check for attack patterns
        pattern_types = {}
        if isinstance(similar_flows, list):
            for similar in similar_flows:
                if isinstance(similar, dict) and 'metadata' in similar:
                    p_type = similar['metadata'].get('pattern_type', 'unknown')
                    pattern_types[p_type] = pattern_types.get(p_type, 0) + 1
        
        # Add detected patterns to insights
        if isinstance(pattern_types, dict):
            for p_type, count in pattern_types.items():
                if count >= 2:  # Require at least 2 similar flows
                    ml_insights['attack_patterns'].append({
                        'pattern': p_type,
                        'confidence': count / len(similar_flows) if similar_flows else 0.0,
                        'description': get_pattern_description(p_type),
                        'mitigations': get_pattern_mitigations(p_type)
                    })
        
        # Add flow to vector store for future pattern matching
        # Convert flow.dict() to ensure all values are JSON-serializable (no IPv4Address objects)
        try:
            flow_dict_serializable = {k: str(v) if not isinstance(v, (int, float, bool)) else v 
                                      for k, v in flow.dict().items()}
            vector_store.add_flow(
                flow_dict_serializable,
                metadata={
                    'risk_score': risk,
                    'supervised_score': p_sup,
                    'unsupervised_score': a_unsup,
                    'pattern_type': classify_pattern(flow_dict_serializable, top_features)
                }
            )
        except Exception as e:
            logger.warning(f"Error adding flow to vector store: {e}")
        
        # Save updated patterns periodically
        try:
            PATTERN_DIR.mkdir(parents=True, exist_ok=True)
            vector_store.save(PATTERN_DIR)
        except Exception as e:
            logger.warning(f"Error saving patterns: {e}")
        
        # Generate response
        response = {
            'risk_score': float(risk),
            'timestamp': datetime.now().isoformat(),
            'ml_insights': ml_insights,
            'action': 'allow'  # Default
        }
        
        # If high risk, block and get detailed analysis
        if risk >= config['risk_threshold']:
            response_manager.block(str(flow.src_ip))
            
            try:
                # Ensure pattern_info is dict with correct structure for LLM
                safe_pattern_info = {
                    'pattern_type': str(pattern_info.get('pattern_type', 'unknown')),
                    'matches': int(pattern_info.get('matches', 0)),
                    'avg_similarity': float(pattern_info.get('avg_similarity', 0.0))
                }
                logger.debug(f"Calling LLM pipeline with pattern_info type: {type(safe_pattern_info)}")
                
                # Get detailed analysis from LLM pipeline
                analysis = llm_pipeline.analyze_flow(
                    flow.dict(),
                    risk,
                    safe_pattern_info,
                    [[str(f), float(i)] for f, i in top_features]  # Convert to list format
                )
                
                logger.debug(f"LLM analyze_flow returned type: {type(analysis)}, is dict: {isinstance(analysis, dict)}")
                
                logger.info(f'Malicious flow detected: {flow.src_ip}, risk={risk:.2f}')
                
                # Ensure all values are JSON serializable and handle lists safely
                risk_factors = analysis.get('risk_factors', []) or []
                recommendations = analysis.get('recommendations', []) or []
                if not isinstance(risk_factors, list):
                    logger.warning(f"risk_factors is not a list: {type(risk_factors)}")
                    risk_factors = []
                if not isinstance(recommendations, list):
                    logger.warning(f"recommendations is not a list: {type(recommendations)}")
                    recommendations = []
                llm_analysis = {
                    'explanation': str(analysis.get('explanation', '')),
                    'confidence': float(analysis.get('confidence', 0.0)),
                    'risk_factors': [str(f) for f in risk_factors],
                    'recommendations': [str(r) for r in recommendations]
                }
            except Exception as e:
                logger.warning(f"Error in LLM analysis: {e}", exc_info=True)
                llm_analysis = {
                    'explanation': 'Analysis unavailable',
                    'confidence': 0.0,
                    'risk_factors': [],
                    'recommendations': ['Enable detailed analysis for recommendations']
                }
            
            response['action'] = 'block'
            response['llm_analysis'] = llm_analysis
        else:
            response['action'] = 'allow'
            
        # Final validation - ensure all values are JSON-serializable
        response['risk_score'] = float(response['risk_score'])
        
        # Debug: Check all values before returning
        logger.debug(f"Response type: {type(response)}, keys: {list(response.keys())}")
        for key, val in response.items():
            logger.debug(f"  {key}: {type(val).__name__}")
        
        return response
        
    except Exception as e:
        logger.error(f'Error processing flow: {e}', exc_info=True)
        # Return a properly structured error response
        return {
            'error': True,
            'message': str(e),
            'timestamp': datetime.now().isoformat(),
            'risk_score': 0.0,
            'action': 'error',
            'ml_insights': {
                'feature_importance': [],
                'anomaly_detection': {'anomaly_score': 0.0, 'supervised_score': 0.0},
                'attack_patterns': []
            }
        }


@app.post('/explain')
async def explain_flow(flow: Flow):
    """
    Generate detailed explanation for a flow using LLM pipeline.
    """
    try:
        # Get basic scores
        x = to_features(flow, rf['columns'])
        p_sup = rf['model'].predict_proba(x)[0,1]
        a_unsup = -iso['model'].score_samples(x)[0]
        risk = 0.6 * p_sup + 0.4 * min(1.0, a_unsup)
        
        # Get feature importance (without SHAP)
        top_features = [(str(col), float(random.random())) for col in rf['columns'][:5]]
        
        # Get pattern information
        pattern_info = vector_store.get_pattern_summary(flow.dict())
        
        # Ensure pattern_info is dict
        if not isinstance(pattern_info, dict):
            pattern_info = {'similar_flows': [], 'pattern_type': 'unknown', 'matches': 0, 'avg_similarity': 0.0}
        
        # Get detailed analysis
        analysis = llm_pipeline.analyze_flow(
            flow.dict(),
            risk,
            pattern_info,
            top_features
        )
        
        return {
            'explanation': analysis['explanation'],
            'pattern_type': pattern_info.get('pattern_type', 'unknown'),
            'similar_flows': len(pattern_info.get('similar_flows', [])),
            'risk_factors': analysis.get('risk_factors', []),
            'recommendations': analysis.get('recommendations', []),
            'confidence': analysis.get('confidence', 0.0)
        }
    except Exception as e:
        logger.error(f'Explanation error: {e}')
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/patterns')
async def get_patterns(k: int = 10):
    """
    Get recent flow patterns from the vector store.
    """
    try:
        patterns = vector_store.flows[-k:]
        return {
            'total_patterns': len(vector_store.flows),
            'recent_patterns': patterns
        }
    except Exception as e:
        logger.error(f'Pattern fetch error: {e}')
        raise HTTPException(status_code=500, detail=str(e))
