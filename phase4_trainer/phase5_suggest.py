#!/usr/bin/env python3
# phase4_trainer/phase5_suggest.py
# Phase 5: Policy Diff Suggestion Generator

import argparse
import pandas as pd
import numpy as np
import joblib
import json
import re
from datetime import datetime

def suggest_policy_diff(csv_path: str, model_path: str, out_json: str, top_n: int = 20):
    """
    Generate policy diff suggestions from trained model
    
    This script analyzes feature importance from the trained RandomForest model
    to propose new deny rules based on patterns that predict unsafe commands.
    
    Security: Output is never auto-applied. Human review required.
    """
    
    print(f"[PHASE 5 SUGGEST] Loading data from {csv_path}")
    df = pd.read_csv(csv_path)
    
    print(f"[PHASE 5 SUGGEST] Loading model from {model_path}")
    model = joblib.load(model_path)
    
    # Extract feature importance from pipeline
    vect = model.named_steps['tfidf']
    clf = model.named_steps['clf']
    feature_names = vect.get_feature_names_out()
    importances = clf.feature_importances_
    
    print(f"[PHASE 5 SUGGEST] Analyzing {len(feature_names)} features")
    
    # Get top features that predict unsafe
    # We want features that are strong indicators of unsafe commands
    top_features = sorted(
        zip(feature_names, importances), 
        key=lambda x: x[1], 
        reverse=True
    )[:top_n * 2]  # Get 2x to filter for quality
    
    suggestions = []
    seen_patterns = set()
    
    for term, score in top_features:
        # Skip very short or very generic terms
        if len(term) < 3:
            continue
        
        # Skip if already seen similar pattern
        if term in seen_patterns:
            continue
        
        # Create safe regex pattern (escape special chars)
        # Use word boundaries for whole-word matches
        pattern = r'\b' + re.escape(term) + r'\b'
        
        # Avoid duplicate patterns
        if pattern not in seen_patterns:
            suggestions.append({
                'pattern': pattern,
                'effect': 'deny',
                'score': float(score),
                'reason': f'Feature importance: {score:.4f}'
            })
            seen_patterns.add(pattern)
        
        # Stop when we have enough unique suggestions
        if len(suggestions) >= top_n:
            break
    
    # Generate policy diff
    policy_diff = {
        'add': suggestions,
        'remove': [],  # Could add logic to suggest removing low-confidence rules
        'meta': {
            'proposed_by': 'trainer_v1',
            'model_version': 'v1',
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'total_features_analyzed': len(feature_names),
            'suggestions_count': len(suggestions)
        }
    }
    
    # Write to output file
    with open(out_json, 'w') as f:
        json.dump(policy_diff, f, indent=2)
    
    print(f"[PHASE 5 SUGGEST] Generated {len(suggestions)} policy suggestions")
    print(f"[PHASE 5 SUGGEST] Saved to: {out_json}")
    print(f"[PHASE 5 SUGGEST] ⚠️  SECURITY: These suggestions require human approval before applying")
    
    # Print top 5 for preview
    print("\n[PHASE 5 SUGGEST] Top 5 suggestions:")
    for i, sugg in enumerate(suggestions[:5], 1):
        print(f"  {i}. Pattern: {sugg['pattern']} (score: {sugg['score']:.4f})")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Generate policy diff suggestions from trained model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 -m phase4_trainer.phase5_suggest \\
    --csv ~/.warp_open/telemetry_export.csv \\
    --model ./policy_model/policy_model.pkl \\
    --out /tmp/policy_suggestions.json \\
    --top-n 20

Security:
  - Suggestions are NEVER auto-applied
  - Human review required via PolicyReviewer UI
  - Apply requires explicit "APPLY" confirmation token
        """
    )
    parser.add_argument('--csv', required=True, help="Telemetry CSV file path")
    parser.add_argument('--model', required=True, help="Trained model .pkl file path")
    parser.add_argument('--out', required=True, help="Output JSON file path")
    parser.add_argument('--top-n', type=int, default=20, help="Number of suggestions to generate")
    args = parser.parse_args()
    
    try:
        suggest_policy_diff(args.csv, args.model, args.out, args.top_n)
    except Exception as e:
        print(f"[PHASE 5 SUGGEST] ERROR: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
