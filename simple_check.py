#!/usr/bin/env python3
"""
Simple dependency verification script for Command Line Threat Analyzer
"""

def check_core_dependencies():
    print("🔍 Checking core dependencies for Command Line Threat Analyzer...\n")
    
    # Core dependencies needed for the main functionality
    dependencies = [
        ("pandas", "pd"),
        ("streamlit", "st"),
        ("plotly", "plotly"),
        ("sklearn.feature_extraction.text", "TfidfVectorizer"),
        ("sklearn.cluster", "KMeans"),
        ("numpy", "np"),
        ("json", "json"),
        ("re", "re"),
        ("time", "time"),
        ("unicodedata", "unicodedata"),
        ("collections", "defaultdict"),
        ("requests", "requests")
    ]
    
    missing_deps = []
    
    for dep, alias in dependencies:
        try:
            if '.' in dep:
                # Handle submodules like plotly.express
                parts = dep.split('.')
                module = __import__(parts[0])
                for part in parts[1:]:
                    module = getattr(module, part)
                globals()[alias] = module
            else:
                module = __import__(dep)
                globals()[alias] = module
            print(f"✅ {dep}")
        except ImportError as e:
            print(f"❌ {dep} - {str(e)}")
            missing_deps.append(dep)
    
    # Special handling for plotly.express
    try:
        import plotly.express as px
        globals()['px'] = px
        print("✅ plotly.express")
    except ImportError as e:
        print(f"❌ plotly.express - {str(e)}")
        missing_deps.append("plotly.express")
    
    print(f"\n📊 Summary: {len(dependencies) - len(missing_deps) + 1}/{len(dependencies) + 1} core dependencies available")
    
    if missing_deps:
        print(f"\n❌ Missing dependencies: {missing_deps}")
        print("\nTo install missing dependencies, run:")
        print("pip install -r requirements.txt")
        return False
    else:
        print("\n🎉 All core dependencies are available!")
        return True

def check_custom_modules():
    print("\n🔍 Checking custom modules...\n")
    
    modules_to_check = [
        "log_analyzer",
        "threat_intel", 
        "behavioral_analyzer"
    ]
    
    for mod in modules_to_check:
        try:
            __import__(mod)
            print(f"✅ {mod}")
        except ImportError as e:
            print(f"❌ {mod} - {str(e)}")
            return False
    
    return True

if __name__ == "__main__":
    print("🚀 Command Line Threat Analyzer - Dependency Verification")
    print("="*60)
    
    core_success = check_core_dependencies()
    custom_success = check_custom_modules()
    
    print("\n" + "="*60)
    if core_success and custom_success:
        print("🎉 ALL DEPENDENCIES ARE AVAILABLE!")
        print("\n🚀 Command Line Threat Analyzer is ready to use!")
        print("You can start the web application with: python3 -m streamlit run web_app.py")
        print("Or run the analyzer directly: python3 log_analyzer.py")
    else:
        print("⚠️  Some dependencies are missing. Please install them before using the application.")
        print("Run: pip install -r requirements.txt")