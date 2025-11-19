"""
Vector store for flow pattern matching using FAISS and TF-IDF.
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

import numpy as np
import faiss
from sklearn.feature_extraction.text import TfidfVectorizer
from typing import List, Dict, Any, Optional
import json
import pickle
from datetime import datetime

class FlowVectorStore:
    def __init__(self):
        """Initialize the vector store with TF-IDF vectorizer."""
        self.vectorizer = TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 3),
            max_features=128  # Use smaller, more stable dimension
        )
        self.dimension = 128
        self.index = None  # Will be initialized after first flow
        self.flows: List[Dict[str, Any]] = []
        self._is_initialized = False
        self._sample_texts = []  # Collect samples for fitting
        
    def _flow_to_text(self, flow: Dict[str, Any]) -> str:
        """Convert a flow dict to a textual representation for embedding."""
        return (f"Network flow from {flow.get('src_ip', 'unknown')} to {flow.get('dst_ip', 'unknown')} "
                f"using {flow.get('proto', 'unknown')} protocol. Source port: {flow.get('sport', 'unknown')}, "
                f"destination port: {flow.get('dport', 'unknown')}. Duration: {flow.get('dur', 0):.3f}s, "
                f"bytes sent: {flow.get('sbytes', 0)}, bytes received: {flow.get('dbytes', 0)}, "
                f"packets: {flow.get('pkts', 0)}.")
    
    def add_flow(self, flow: Dict[str, Any], metadata: Optional[Dict] = None) -> None:
        """Add a flow to the vector store with optional metadata."""
        text = self._flow_to_text(flow)
        self._sample_texts.append(text)
        
        # Store the flow data and metadata
        flow_entry = {
            'flow': flow,
            'metadata': metadata or {},
            'timestamp': datetime.now().isoformat(),
            'text_repr': text
        }
        self.flows.append(flow_entry)
        
        # Initialize after collecting 2 samples or first flow
        if len(self._sample_texts) >= 2 and not self._is_initialized:
            self.vectorizer.fit(self._sample_texts)
            self.index = faiss.IndexFlatL2(self.dimension)
            self._is_initialized = True
            # Add all collected flows to index
            for flow_entry in self.flows:
                self._add_to_index(flow_entry['text_repr'])
        elif not self._is_initialized and len(self.flows) > 0:
            # First flow - initialize with just this one
            self.vectorizer.fit(self._sample_texts)
            self.index = faiss.IndexFlatL2(self.dimension)
            self._is_initialized = True
            self._add_to_index(text)
        elif self._is_initialized:
            # Already initialized, just add this flow
            self._add_to_index(text)
    
    def _add_to_index(self, text: str) -> None:
        """Add a single text embedding to the FAISS index."""
        embedding = self.vectorizer.transform([text]).toarray()[0]
        
        # Ensure embedding has the right dimension
        if len(embedding) != self.dimension:
            if len(embedding) > self.dimension:
                embedding = embedding[:self.dimension]
            else:
                embedding = np.pad(embedding, (0, self.dimension - len(embedding)), mode='constant', constant_values=0)
        
        normalized = embedding / (np.linalg.norm(embedding) + 1e-10)
        self.index.add(np.array([normalized], dtype=np.float32))
    
    def search_similar(self, flow: Dict[str, Any], k: int = 5) -> List[Dict[str, Any]]:
        """Find k most similar flows to the given flow."""
        if not self._is_initialized:
            return []
        
        query_text = self._flow_to_text(flow)
        query_embedding = self.vectorizer.transform([query_text]).toarray()[0]
        
        # Ensure query embedding has the right dimension
        if len(query_embedding) != self.dimension:
            if len(query_embedding) > self.dimension:
                query_embedding = query_embedding[:self.dimension]
            else:
                query_embedding = np.pad(query_embedding, (0, self.dimension - len(query_embedding)), mode='constant', constant_values=0)
        
        query_normalized = query_embedding / (np.linalg.norm(query_embedding) + 1e-10)
        
        # Search the index
        distances, indices = self.index.search(
            np.array([query_normalized], dtype=np.float32), k
        )
        
        # Return matched flows with distances
        results = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx < len(self.flows):  # Guard against out-of-bounds
                match = self.flows[idx].copy()
                match['similarity_score'] = float(1.0 / (1.0 + dist))  # Convert distance to similarity
                results.append(match)
        return results
    
    def get_pattern_summary(self, flow: Dict[str, Any], k: int = 5) -> Dict[str, Any]:
        """Generate a summary of patterns similar to the given flow."""
        similar = self.search_similar(flow, k=k)
        if not similar:
            return {
                'matches': 0,
                'avg_similarity': 0.0,
                'pattern_type': 'unique',
                'similar_flows': []
            }
        
        # Calculate statistics
        scores = [m['similarity_score'] for m in similar]
        avg_score = sum(scores) / len(scores)
        
        # Determine pattern type based on similarity
        pattern_type = 'unique'
        if avg_score > 0.9:
            pattern_type = 'exact_match'
        elif avg_score > 0.7:
            pattern_type = 'similar'
        elif avg_score > 0.5:
            pattern_type = 'related'
            
        return {
            'matches': len(similar),
            'avg_similarity': avg_score,
            'pattern_type': pattern_type,
            'similar_flows': similar
        }
    
    def save(self, directory: Path) -> None:
        """Save the vector store state to disk."""
        directory.mkdir(parents=True, exist_ok=True)
        
        if self._is_initialized:
            # Save the FAISS index
            faiss.write_index(self.index, str(directory / 'flow_patterns.faiss'))
            
            # Save the vectorizer
            with open(directory / 'vectorizer.pkl', 'wb') as f:
                pickle.dump(self.vectorizer, f)
        
        # Save the flows data
        with open(directory / 'flows.json', 'w') as f:
            json.dump(self.flows, f, indent=2)
            
    @classmethod
    def load(cls, directory: Path) -> 'FlowVectorStore':
        """Load a vector store from disk."""
        instance = cls()
        
        # Load the vectorizer if it exists
        vectorizer_path = directory / 'vectorizer.pkl'
        if vectorizer_path.exists():
            with open(vectorizer_path, 'rb') as f:
                instance.vectorizer = pickle.load(f)
                instance._is_initialized = True
        
        # Load the FAISS index if it exists
        index_path = directory / 'flow_patterns.faiss'
        if index_path.exists():
            instance.index = faiss.read_index(str(index_path))
        
        # Load the flows data if it exists
        flows_path = directory / 'flows.json'
        if flows_path.exists():
            with open(flows_path) as f:
                instance.flows = json.load(f)
                
        return instance