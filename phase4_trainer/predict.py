#!/usr/bin/env python3
# phase4_trainer/predict.py
# Predict safety score for a command using trained model

import joblib
import sys
import argparse

def predict_command(model_path: str, command: str):
    """Predict safety for a single command"""
    try:
        model = joblib.load(model_path)
    except FileNotFoundError:
        print(f"Error: Model file not found: {model_path}", file=sys.stderr)
        sys.exit(1)
    
    pred = model.predict([command])[0]
    proba = model.predict_proba([command])[0]
    
    label_names = ['safe', 'unsafe']
    pred_label = label_names[pred] if pred < len(label_names) else 'unknown'
    confidence = proba.max()
    
    print(f"Command: {command}")
    print(f"Prediction: {pred_label}")
    print(f"Confidence: {confidence:.2%}")
    print(f"Probabilities: safe={proba[0]:.2%}, unsafe={proba[1]:.2%}")
    
    return pred, confidence

def main():
    parser = argparse.ArgumentParser(description="Predict command safety")
    parser.add_argument('--model', default='./policy_model/policy_model.pkl', help="Path to trained model")
    parser.add_argument('command', nargs='+', help="Command to predict")
    args = parser.parse_args()
    
    command = ' '.join(args.command)
    predict_command(args.model, command)

if __name__ == '__main__':
    main()
