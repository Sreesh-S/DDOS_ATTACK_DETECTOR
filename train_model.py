import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import json
import os

def train_model(data_path='cicids_dos_ddos_data.csv', model_dir='detection/ml'):
    """
    Trains a Random Forest model on the processed dataset.
    Saves the model to 'detection/ml/model.pkl' and features to 'features.json'.
    """
    if not os.path.exists(data_path):
        print(f"Data file {data_path} not found. Run prepare_dataset.py first or ensure data exists.")
        return

    print("Loading dataset...")
    df = pd.read_csv(data_path)
    
    # Handling Class Imbalance (Optional - can be done via sampling or class_weight='balanced')
    
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    # Identify non-numeric columns and encode them if necessary
    # CICIDS2017 is mostly numeric but might have some object columns like IPs if not removed
    # Assuming 'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp' might need handling
    # For ML, we usually drop IPs and Timestamps, keep ports and protocol depending on feature selection
    
    # Dropping identifiers for generalization
    cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    # Check if they exist before dropping
    existing_drop = [c for c in cols_to_drop if c in X.columns]
    X.drop(columns=existing_drop, inplace=True)
    
    # One-hot encode or Label encode categorical features if any remaining
    # Destination Port and Protocol are numeric but categorical in nature. keeping them as is for RF is usually fine or OHE.
    
    print(f"Features used: {list(X.columns)}")
    
    # Save feature names for inference
    os.makedirs(model_dir, exist_ok=True)
    feature_names = list(X.columns)
    with open(os.path.join(model_dir, 'features.json'), 'w') as f:
        json.dump(feature_names, f)
        
    print("Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    print("Evaluating...")
    y_pred = clf.predict(X_test)
    
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
    
    print(f"Saving model to {model_dir}/model.pkl...")
    joblib.dump(clf, os.path.join(model_dir, 'model.pkl'))
    print("Model saved.")

if __name__ == "__main__":
    train_model()
