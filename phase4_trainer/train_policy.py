#!/usr/bin/env python3
# phase4_trainer/train_policy.py
# Phase 4: Policy Learning System
# Trains a safety classifier from telemetry data

import argparse
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import pathlib
import sys

def load_csv(path: str) -> pd.DataFrame:
    """Load telemetry CSV and prepare for training"""
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        print(f"Error: CSV file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except pd.errors.EmptyDataError:
        print(f"Error: CSV file is empty: {path}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(df)} telemetry events")
    
    # Ensure required fields exist
    df['command'] = df['command'].fillna('')
    df['exit_code'] = df['exit_code'].fillna(-999)
    df['safety_score'] = df['safety_score'].fillna(-1)
    
    # Derive labels from safety_score if safety_label not present
    # 0 = safe, 1 = unsafe, 2 = unknown
    if 'safety_label' not in df.columns:
        print("No safety_label column found - deriving from safety_score...")
        df['safety_label'] = df['safety_score'].apply(
            lambda x: 0 if x >= 80 else (1 if x < 40 else 2)
        )
    
    # Filter to only events with commands
    df = df[df['command'] != '']
    print(f"Filtered to {len(df)} events with commands")
    
    # Show label distribution
    print("\\nLabel distribution:")
    print(df['safety_label'].value_counts())
    print("  0 = safe, 1 = unsafe, 2 = unknown\\n")
    
    return df

def featurize_and_train(df: pd.DataFrame, out_model: str):
    """Train classifier on command text"""
    # Keep only rows with known safe/unsafe for supervised training
    train_df = df[df['safety_label'].isin([0, 1])]
    
    if len(train_df) < 10:
        print(f"Error: Not enough labeled training data ({len(train_df)} samples)", file=sys.stderr)
        print("Need at least 10 samples with safety_label in [0, 1]", file=sys.stderr)
        sys.exit(1)
    
    print(f"Training on {len(train_df)} labeled examples")
    
    X = train_df['command']
    y = train_df['safety_label'].astype(int)
    
    # Check if we have both classes
    unique_labels = y.unique()
    if len(unique_labels) < 2:
        print(f"Warning: Only one class present in training data: {unique_labels}", file=sys.stderr)
        print("Classifier may not be useful. Consider collecting more diverse data.", file=sys.stderr)
    
    # Simple pipeline: TF-IDF on command text -> RandomForest
    print("\\nBuilding pipeline: TF-IDF + RandomForest...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 3), min_df=1, max_features=500)),
        ('clf', RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, max_depth=10))
    ])
    
    # Split data
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
    except ValueError:
        # Not enough samples for stratification
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train model
    print("\\nTraining model...")
    pipeline.fit(X_train, y_train)
    
    # Evaluate
    print("\\nEvaluating on test set...")
    preds = pipeline.predict(X_test)
    acc = accuracy_score(y_test, preds)
    
    print(f"\\n{'='*50}")
    print(f"Accuracy: {acc:.2%}")
    print(f"{'='*50}\\n")
    
    print("Classification Report:")
    print(classification_report(y_test, preds, target_names=['safe', 'unsafe']))
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))
    print()
    
    # Save model
    pathlib.Path(out_model).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, out_model)
    print(f"✅ Model saved to: {out_model}")
    
    # Feature importance (top command patterns)
    tfidf = pipeline.named_steps['tfidf']
    clf = pipeline.named_steps['clf']
    feature_names = tfidf.get_feature_names_out()
    importances = clf.feature_importances_
    
    top_indices = np.argsort(importances)[-10:]
    print("\\nTop 10 Most Important Features:")
    for idx in reversed(top_indices):
        print(f"  {feature_names[idx]}: {importances[idx]:.4f}")

def main():
    parser = argparse.ArgumentParser(
        description="Train safety policy classifier from telemetry CSV"
    )
    parser.add_argument('--csv', required=True, help="Telemetry CSV exported from telemetry module")
    parser.add_argument('--out', default='./policy_model/policy_model.pkl', help="Output model path")
    args = parser.parse_args()
    
    print("="*50)
    print("Phase 4 Policy Trainer")
    print("="*50)
    print()
    
    df = load_csv(args.csv)
    featurize_and_train(df, args.out)
    
    print("\\n" + "="*50)
    print("Training Complete")
    print("="*50)

if __name__ == '__main__':
    main()
