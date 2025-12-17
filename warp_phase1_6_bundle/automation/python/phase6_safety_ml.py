#!/usr/bin/env python3
"""
phase6_safety_ml.py
Machine Learning Safety Scoring for Warp Phase 6 Plans

Provides predictive safety scoring to enable auto-approval of safe operations.
Uses RandomForest classifier trained on historical telemetry data.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json
import sys
from pathlib import Path
from datetime import datetime

# Model configuration
MODEL_PATH = "phase6_safety_model.pkl"
FEATURE_SCALER_PATH = "phase6_feature_scaler.pkl"
MIN_TRAINING_SAMPLES = 100
SAFETY_THRESHOLD = 0.8

class Phase6SafetyPredictor:
    """Predictive model for Phase 6 plan safety scoring"""
    
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.feature_columns = [
            "command_type",
            "agent_id", 
            "previous_failures",
            "safety_score",
            "batch_size",
            "dependency_count",
            "execution_time_avg"
        ]
        
    def load_training_data(self, csv_path="phase6_telemetry.csv"):
        """Load and prepare training data from telemetry CSV"""
        try:
            df = pd.read_csv(csv_path)
            print(f"Loaded {len(df)} records from {csv_path}")
            
            # Feature engineering
            df = self._engineer_features(df)
            
            # Prepare features and labels
            X = df[self.feature_columns]
            y = df["safe_to_advance"]
            
            return X, y
        except FileNotFoundError:
            print(f"Error: Training data file not found: {csv_path}")
            return None, None
        except Exception as e:
            print(f"Error loading training data: {e}")
            return None, None
    
    def _engineer_features(self, df):
        """Engineer features from raw telemetry data"""
        # Encode command types as numeric
        if "command_type" in df.columns:
            df["command_type"] = pd.factorize(df["command_type"])[0]
        
        # Encode agent IDs
        if "agent_id" in df.columns:
            df["agent_id"] = pd.factorize(df["agent_id"])[0]
        
        # Fill missing values
        for col in self.feature_columns:
            if col in df.columns:
                df[col] = df[col].fillna(0)
        
        # Add derived features if not present
        if "batch_size" not in df.columns:
            df["batch_size"] = 1
        
        if "dependency_count" not in df.columns:
            df["dependency_count"] = 0
        
        if "execution_time_avg" not in df.columns:
            df["execution_time_avg"] = 1.0
        
        return df
    
    def train(self, csv_path="phase6_telemetry.csv", test_size=0.2):
        """Train the safety prediction model"""
        print("=" * 60)
        print("Training Phase 6 Safety Prediction Model")
        print("=" * 60)
        
        # Load data
        X, y = self.load_training_data(csv_path)
        
        if X is None or y is None:
            print("Failed to load training data")
            return False
        
        if len(X) < MIN_TRAINING_SAMPLES:
            print(f"Warning: Only {len(X)} samples available. Recommend at least {MIN_TRAINING_SAMPLES}")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        print(f"\nTraining set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        print(f"Positive class (safe): {sum(y_train)} ({sum(y_train)/len(y_train)*100:.1f}%)")
        
        # Train model
        print("\nTraining RandomForest classifier...")
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        print("\nEvaluating model...")
        y_pred = self.model.predict(X_test)
        y_pred_proba = self.model.predict_proba(X_test)[:, 1]
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=["Unsafe", "Safe"]))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        # Feature importance
        print("\nFeature Importance:")
        for feature, importance in zip(self.feature_columns, self.model.feature_importances_):
            print(f"  {feature:25s}: {importance:.4f}")
        
        # Save model
        self.save_model()
        
        return True
    
    def save_model(self):
        """Save trained model to disk"""
        if self.model is None:
            print("Error: No model to save")
            return False
        
        try:
            joblib.dump(self.model, self.model_path)
            print(f"\n✓ Model saved to {self.model_path}")
            
            # Save metadata
            metadata = {
                "created_at": datetime.now().isoformat(),
                "features": self.feature_columns,
                "model_type": "RandomForestClassifier",
                "n_estimators": self.model.n_estimators,
                "safety_threshold": SAFETY_THRESHOLD
            }
            
            metadata_path = self.model_path.replace(".pkl", "_metadata.json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            print(f"✓ Metadata saved to {metadata_path}")
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    def load_model(self):
        """Load trained model from disk"""
        try:
            self.model = joblib.load(self.model_path)
            print(f"✓ Model loaded from {self.model_path}")
            return True
        except FileNotFoundError:
            print(f"Error: Model file not found: {self.model_path}")
            return False
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict_safety(self, plan_step):
        """
        Predict safety score for a plan step
        
        Args:
            plan_step: dict with keys matching feature_columns
        
        Returns:
            float: Safety score between 0 and 1
        """
        if self.model is None:
            if not self.load_model():
                return 0.0
        
        try:
            # Prepare features
            features = [plan_step.get(col, 0) for col in self.feature_columns]
            features_array = np.array([features])
            
            # Predict probability
            proba = self.model.predict_proba(features_array)[0][1]
            
            return float(proba)
        except Exception as e:
            print(f"Error predicting safety: {e}")
            return 0.0
    
    def predict_batch(self, plan_steps):
        """
        Predict safety scores for multiple plan steps
        
        Args:
            plan_steps: list of dicts
        
        Returns:
            list of floats: Safety scores
        """
        if self.model is None:
            if not self.load_model():
                return [0.0] * len(plan_steps)
        
        try:
            features_list = []
            for step in plan_steps:
                features = [step.get(col, 0) for col in self.feature_columns]
                features_list.append(features)
            
            features_array = np.array(features_list)
            probas = self.model.predict_proba(features_array)[:, 1]
            
            return probas.tolist()
        except Exception as e:
            print(f"Error predicting batch safety: {e}")
            return [0.0] * len(plan_steps)
    
    def is_safe_to_advance(self, plan_step, threshold=SAFETY_THRESHOLD):
        """
        Check if a plan step is safe to auto-advance
        
        Args:
            plan_step: dict with plan step features
            threshold: minimum safety score (default 0.8)
        
        Returns:
            bool: True if safe to advance
        """
        score = self.predict_safety(plan_step)
        return score >= threshold


def main():
    """CLI interface for training and prediction"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Phase 6 Safety Prediction ML Model")
    parser.add_argument("--train", action="store_true", help="Train a new model")
    parser.add_argument("--data", default="phase6_telemetry.csv", help="Training data CSV path")
    parser.add_argument("--predict", help="Predict safety for plan step (JSON file)")
    parser.add_argument("--predict-batch", help="Predict safety for multiple steps (JSON file)")
    parser.add_argument("--threshold", type=float, default=SAFETY_THRESHOLD, help="Safety threshold")
    
    args = parser.parse_args()
    
    predictor = Phase6SafetyPredictor()
    
    if args.train:
        # Train mode
        success = predictor.train(csv_path=args.data)
        sys.exit(0 if success else 1)
    
    elif args.predict:
        # Single prediction mode
        try:
            with open(args.predict, "r") as f:
                plan_step = json.load(f)
            
            score = predictor.predict_safety(plan_step)
            is_safe = score >= args.threshold
            
            result = {
                "safety_score": score,
                "is_safe": is_safe,
                "threshold": args.threshold,
                "plan_step": plan_step
            }
            
            print(json.dumps(result, indent=2))
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    elif args.predict_batch:
        # Batch prediction mode
        try:
            with open(args.predict_batch, "r") as f:
                plan_steps = json.load(f)
            
            scores = predictor.predict_batch(plan_steps)
            
            results = []
            for step, score in zip(plan_steps, scores):
                results.append({
                    "safety_score": score,
                    "is_safe": score >= args.threshold,
                    "plan_step": step
                })
            
            print(json.dumps(results, indent=2))
            sys.exit(0)
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()


# Usage Examples:
#
# 1. Train a new model:
#    python phase6_safety_ml.py --train --data phase6_telemetry.csv
#
# 2. Predict single plan step:
#    echo '{"command_type": 0, "agent_id": 1, "previous_failures": 0, 
#           "safety_score": 95, "batch_size": 1, "dependency_count": 0,
#           "execution_time_avg": 1.5}' > step.json
#    python phase6_safety_ml.py --predict step.json
#
# 3. Predict batch of steps:
#    python phase6_safety_ml.py --predict-batch steps.json
#
# 4. Integration with Rust (via subprocess):
#    let output = Command::new("python3")
#        .arg("phase6_safety_ml.py")
#        .arg("--predict")
#        .arg("plan_step.json")
#        .output()?;
#    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
#    let safety_score = result["safety_score"].as_f64().unwrap();
