import pandas as pd
import numpy as np
from typing import List, Dict, Any

def encode_categorical(value: str, category_map: Dict[str, int]) -> int:
    """Encode categorical value using a mapping, adding new values as needed."""
    if value not in category_map:
        category_map[value] = len(category_map)
    return category_map[value]

def to_features(flow: Any, columns: List[str]) -> np.ndarray:
    """Convert a flow to feature vector using the specified columns."""
    # Static category mappings
    proto_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
    state_map = {'EST': 0, 'CON': 1, 'REQ': 2, 'RST': 3, 'CLO': 4}
    
    # Convert flow to dict if needed
    if hasattr(flow, 'dict'):
        data = flow.dict()
    elif isinstance(flow, dict):
        data = flow
    else:
        raise ValueError("Flow must be a dictionary or have a dict() method")
        
    # Prepare feature vector
    feature_vector = []
    for col in columns:
        value = data.get(col)
        
        if col == 'proto':
            # Handle protocol encoding
            value = proto_map.get(str(value).lower(), len(proto_map))  # New protocols get next number
        elif col == 'state':
            # Handle state encoding
            value = state_map.get(str(value).upper(), len(state_map))  # New states get next number
        elif isinstance(value, (int, float)):
            # Numeric values pass through
            value = float(value)
        else:
            # Convert any other values to float, defaulting to 0.0
            try:
                value = float(value if value is not None else 0.0)
            except (ValueError, TypeError):
                value = 0.0
                
        feature_vector.append(value)
    
    # Convert to numpy array and reshape for sklearn
    feature_array = np.array(feature_vector, dtype=np.float32).reshape(1, -1)
    
    # Validate shape
    expected_cols = len(columns)
    if feature_array.shape[1] != expected_cols:
        raise ValueError(f"Feature vector has {feature_array.shape[1]} columns, expected {expected_cols}")
        
    return feature_array
