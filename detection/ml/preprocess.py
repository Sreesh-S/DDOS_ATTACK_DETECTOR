import pandas as pd
import numpy as np
import json
import os

class Preprocessor:
    def __init__(self, features_path='detection/ml/features.json'):
        # Get absolute path relative to this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        features_path = os.path.join(base_dir, 'features.json')
        
        try:
            with open(features_path, 'r') as f:
                self.feature_names = json.load(f)
        except Exception as e:
            print(f"Error loading features: {e}")
            self.feature_names = []

    def preprocess(self, input_data):
        """
        Input: Dict or JSON of traffic features.
        Output: DataFrame ready for prediction (aligned columns).
        """
        # Create DataFrame from input
        # Input might be a single dict or list of dicts
        if isinstance(input_data, dict):
            input_data = [input_data]
            
        df = pd.DataFrame(input_data)
        
        # Ensure all columns exist, fill missing with 0
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
                
        # Reorder columns to match training
        df = df[self.feature_names]
        
        # Handle NaN/Inf if any
        df.replace([np.inf, -np.inf], 0, inplace=True)
        df.fillna(0, inplace=True)
        
        return df
