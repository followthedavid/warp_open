#!/usr/bin/env python3
"""
Generate Warp Phase 1-6 Automation Bundle
Creates a compressed archive with all automation components
"""

import os
import sys
import tarfile
import zipfile
from pathlib import Path
from datetime import datetime

def create_bundle(bundle_type='tar.gz'):
    """Create automation bundle archive"""
    
    # Determine paths
    script_dir = Path(__file__).parent
    bundle_dir = script_dir.parent
    automation_dir = bundle_dir / 'automation'
    dashboard_dir = bundle_dir / 'dashboard'
    scripts_dir = bundle_dir / 'scripts'
    
    # Output filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if bundle_type == 'zip':
        output_file = f"warp_phase1_6_automation_bundle_{timestamp}.zip"
    else:
        output_file = f"warp_phase1_6_automation_bundle_{timestamp}.tar.gz"
    
    print("="*70)
    print("Warp Phase 1-6 Automation Bundle Generator")
    print("="*70)
    print()
    print(f"Bundle directory: {bundle_dir}")
    print(f"Output file: {output_file}")
    print()
    
    # Files to include
    files_to_include = []
    
    # Automation components
    if automation_dir.exists():
        for root, dirs, files in os.walk(automation_dir):
            for file in files:
                if not file.startswith('.'):
                    filepath = Path(root) / file
                    arcname = filepath.relative_to(bundle_dir)
                    files_to_include.append((filepath, arcname))
    
    # Dashboard files
    if dashboard_dir.exists():
        for file in ['dashboard_automation.html', 'parallel_dashboard.html']:
            filepath = dashboard_dir / file
            if filepath.exists():
                arcname = filepath.relative_to(bundle_dir)
                files_to_include.append((filepath, arcname))
    
    # Scripts
    if scripts_dir.exists():
        for file in ['warp_phase1_6_event_server.py', 'launch_parallel_automation.sh']:
            filepath = scripts_dir / file
            if filepath.exists():
                arcname = filepath.relative_to(bundle_dir)
                files_to_include.append((filepath, arcname))
    
    # Root documentation
    for file in ['README.md', 'VERIFICATION.md', 'COMPLETION_SUMMARY.txt']:
        for search_dir in [automation_dir, bundle_dir]:
            filepath = search_dir / file
            if filepath.exists():
                # Place in root of archive
                arcname = Path(file)
                files_to_include.append((filepath, arcname))
                break
    
    if not files_to_include:
        print("❌ No files found to include in bundle!")
        return 1
    
    print(f"Including {len(files_to_include)} files:")
    print()
    
    # Create archive
    try:
        if bundle_type == 'zip':
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for filepath, arcname in files_to_include:
                    print(f"  + {arcname}")
                    zf.write(filepath, arcname)
        else:
            with tarfile.open(output_file, 'w:gz') as tf:
                for filepath, arcname in files_to_include:
                    print(f"  + {arcname}")
                    tf.add(filepath, arcname=arcname)
        
        print()
        print("="*70)
        print(f"✅ Bundle created successfully: {output_file}")
        
        # Show file size
        size_mb = os.path.getsize(output_file) / (1024 * 1024)
        print(f"   Size: {size_mb:.2f} MB")
        print("="*70)
        print()
        print("📦 Bundle Contents:")
        print("   - Rust scheduler automation")
        print("   - Tauri integration commands")
        print("   - JavaScript alert store")
        print("   - Python ML safety predictor")
        print("   - Live automation dashboard")
        print("   - Parallel execution dashboard")
        print("   - WebSocket event server")
        print("   - Launch scripts")
        print("   - Complete documentation")
        print()
        print("🚀 Quick Start:")
        print(f"   1. Extract: tar -xzf {output_file}")
        print("   2. Install dependencies: pip install websockets pandas numpy scikit-learn joblib")
        print("   3. Launch: ./scripts/launch_parallel_automation.sh")
        print("   4. Open dashboard in browser")
        print()
        
        return 0
        
    except Exception as e:
        print(f"❌ Error creating bundle: {e}")
        return 1

if __name__ == '__main__':
    bundle_type = sys.argv[1] if len(sys.argv) > 1 else 'tar.gz'
    sys.exit(create_bundle(bundle_type))
