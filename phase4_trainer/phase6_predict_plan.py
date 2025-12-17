# phase4_trainer/phase6_predict_plan.py
"""Phase 6: Predict safety of plan execution steps"""
import joblib
import sys
import argparse

def predict_plan_safety(model_path: str, command: str):
    """Predict whether a command in a plan is safe to execute"""
    model = joblib.load(model_path)
    pred = model.predict([command])[0]
    proba = model.predict_proba([command])[0].max()
    
    status_map = {0: 'safe', 1: 'unsafe', 2: 'unknown'}
    status = status_map.get(pred, 'unknown')
    
    return status, proba

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Predict plan step safety')
    parser.add_argument('--model', default='./plan_model.pkl', help='Path to trained model')
    parser.add_argument('command', nargs='+', help='Command to predict')
    args = parser.parse_args()
    
    cmd = ' '.join(args.command)
    status, confidence = predict_plan_safety(args.model, cmd)
    
    print(f"Command: {cmd}")
    print(f"Prediction: {status}")
    print(f"Confidence: {confidence:.2%}")
