# phase4_trainer/phase6_train_plans.py
"""
Phase 6: Long-term plan-based ML model trainer
Extends Phase 4 telemetry analysis for multi-day workflows
"""
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from pathlib import Path
import argparse

def train_plan_model(csv_path: str, out_model: str):
    """Train a model on telemetry data for plan execution safety"""
    df = pd.read_csv(csv_path)
    
    # Prepare features
    df['command'] = df['command'].fillna('')
    df['status_label'] = df['status'].map({'safe': 0, 'unsafe': 1, 'unknown': 2}).fillna(2)
    
    X = df['command']
    y = df['status_label'].astype(int)

    # Create pipeline with TF-IDF and RandomForest
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1,3), max_features=1000)),
        ('clf', RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1))
    ])
    
    pipeline.fit(X, y)
    
    # Save model
    Path(out_model).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, out_model)
    print(f"✅ Saved plan model to {out_model}")
    print(f"📊 Trained on {len(X)} commands")
    
    # Print feature importance summary
    clf = pipeline.named_steps['clf']
    tfidf = pipeline.named_steps['tfidf']
    feature_names = tfidf.get_feature_names_out()
    importances = clf.feature_importances_
    
    # Get top 10 features
    top_indices = importances.argsort()[-10:][::-1]
    print("\n🎯 Top 10 Features:")
    for idx in top_indices:
        print(f"  {feature_names[idx]}: {importances[idx]:.4f}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train Phase 6 plan safety model')
    parser.add_argument('--csv', required=True, help='Path to telemetry CSV')
    parser.add_argument('--out', default='./plan_model.pkl', help='Output model path')
    args = parser.parse_args()
    
    train_plan_model(args.csv, args.out)
