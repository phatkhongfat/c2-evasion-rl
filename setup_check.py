#!/usr/bin/env python3
"""
Environment setup validation script.
Checks all dependencies and paths before training.
"""
import sys
import os
from pathlib import Path

def check_python_version():
    """Verify Python 3.10+"""
    if sys.version_info < (3, 10):
        print(f"❌ Python 3.10+ required (current: {sys.version_info.major}.{sys.version_info.minor})")
        return False
    print(f"✓ Python {sys.version_info.major}.{sys.version_info.minor}")
    return True

def check_dependencies():
    """Check core ML dependencies."""
    deps = [
        'gymnasium', 'stable_baselines3', 'torch', 'numpy', 'pandas',
        'sklearn', 'scapy', 'flask', 'tensorboard', 'joblib'
    ]
    missing = []
    for dep in deps:
        try:
            __import__(dep)
            print(f"✓ {dep}")
        except ImportError:
            print(f"❌ {dep} NOT FOUND")
            missing.append(dep)
    
    if missing:
        print(f"\n⚠️  Missing dependencies: {', '.join(missing)}")
        print("   Run: pip install -r requirements.txt")
        return False
    return True

def check_data_files():
    """Verify data structure."""
    base = Path(__file__).parent
    required = [
        'data/malicious_ctu13.parquet',
        'data/archive',
        'ai_agent/config.py',
        'blue_team/train_surrogate.ipynb',
    ]
    missing = []
    for path in required:
        if not (base / path).exists():
            print(f"❌ Missing: {path}")
            missing.append(path)
        else:
            print(f"✓ {path}")
    
    return len(missing) == 0

def check_model_files():
    """Check if pre-trained models exist."""
    base = Path(__file__).parent
    models = [
        'data/surrogate_ids_ctu13.pkl',
        'data/label_encoder_proto.pkl',
        'data/label_encoder_state.pkl',
    ]
    missing = []
    for path in models:
        if not (base / path).exists():
            missing.append(path)
    
    if missing:
        print("\n⚠️  Pre-trained models not found:")
        for m in missing:
            print(f"   - {m}")
        print("\n   Generate them by running:")
        print("   1. cd blue_team")
        print("   2. jupyter notebook train_surrogate.ipynb")
        print("   3. Execute all cells")
        return False
    
    print("\n✓ All pre-trained models present")
    return True

def create_missing_dirs():
    """Create models/ directory if missing."""
    base = Path(__file__).parent
    models_dir = base / 'models'
    models_dir.mkdir(exist_ok=True)
    gitkeep = models_dir / '.gitkeep'
    gitkeep.touch()
    print(f"✓ Created {models_dir}/")

if __name__ == '__main__':
    print("=" * 60)
    print("C2 EVASION RL – ENVIRONMENT VALIDATION")
    print("=" * 60)
    
    print("\n[1/4] Python Version")
    py_ok = check_python_version()
    
    print("\n[2/4] Dependencies")
    deps_ok = check_dependencies()
    
    print("\n[3/4] Data Files")
    data_ok = check_data_files()
    
    print("\n[4/4] Model Files")
    create_missing_dirs()
    models_ok = check_model_files()
    
    print("\n" + "=" * 60)
    if all([py_ok, deps_ok, data_ok, models_ok]):
        print("✅ ENVIRONMENT READY – Run: python3 ai_agent/train_agent.py")
    else:
        print("❌ SETUP INCOMPLETE – See issues above")
    print("=" * 60)
    
    sys.exit(0 if all([py_ok, deps_ok, data_ok]) else 1)
