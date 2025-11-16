"""
Test suite for enhanced detection system.
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import pytest
import numpy as np
from app.vector_store import FlowVectorStore
from app.llm_pipeline import LLMPipeline

@pytest.fixture
def sample_flow():
    return {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'sport': 12345,
        'dport': 80,
        'proto': 'tcp',
        'dur': 0.5,
        'sbytes': 1000,
        'dbytes': 500,
        'pkts': 10,
        'state': 'EST'
    }

@pytest.fixture
def vector_store():
    return FlowVectorStore()

def test_vector_store_initialization(vector_store):
    """Test vector store initialization."""
    assert vector_store.dimension == 384
    assert len(vector_store.flows) == 0

def test_flow_to_text_conversion(vector_store, sample_flow):
    """Test flow to text conversion."""
    text = vector_store._flow_to_text(sample_flow)
    assert isinstance(text, str)
    assert '192.168.1.100' in text
    assert '10.0.0.1' in text
    assert 'tcp' in text

def test_add_and_search_flow(vector_store, sample_flow):
    """Test adding a flow and searching for similar ones."""
    # Add the sample flow
    vector_store.add_flow(sample_flow)
    assert len(vector_store.flows) == 1
    
    # Search for similar flows
    similar = vector_store.search_similar(sample_flow, k=1)
    assert len(similar) == 1
    assert similar[0]['flow']['src_ip'] == sample_flow['src_ip']
    assert 'similarity_score' in similar[0]

def test_pattern_summary(vector_store, sample_flow):
    """Test pattern summary generation."""
    # Add multiple similar flows
    for i in range(3):
        modified_flow = sample_flow.copy()
        modified_flow['sport'] = 12345 + i
        vector_store.add_flow(modified_flow)
    
    # Get pattern summary
    summary = vector_store.get_pattern_summary(sample_flow)
    assert isinstance(summary, dict)
    assert 'matches' in summary
    assert 'pattern_type' in summary
    assert summary['matches'] > 0

@pytest.mark.skipif(
    not (Path(__file__).parent.parent / '.env').exists(),
    reason="Requires .env file with OpenAI API key"
)
def test_llm_pipeline(sample_flow):
    """Test LLM pipeline analysis."""
    pipeline = LLMPipeline()
    
    # Create test inputs
    risk_score = 0.75
    pattern_info = {
        'pattern_type': 'similar',
        'matches': 2,
        'avg_similarity': 0.85
    }
    feature_importance = [
        ('duration', 0.3),
        ('bytes_sent', 0.2),
        ('protocol', 0.1)
    ]
    
    # Run analysis
    analysis = pipeline.analyze_flow(
        sample_flow,
        risk_score,
        pattern_info,
        feature_importance
    )
    
    # Verify structure
    assert isinstance(analysis, dict)
    assert 'explanation' in analysis
    assert 'risk_factors' in analysis
    assert 'recommendations' in analysis
    assert 'confidence' in analysis
    
    # Verify confidence score
    assert 0 <= analysis['confidence'] <= 1

if __name__ == '__main__':
    pytest.main([__file__, '-v'])