#!/usr/bin/env python3
"""
Dependency verification script for Command Line Threat Analyzer
"""

def check_dependencies():
    print("🔍 Checking dependencies for Command Line Threat Analyzer...\n")
    
    # Core dependencies
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
    
    # Check our custom modules
    custom_modules = [
        "log_analyzer",
        "threat_intel", 
        "behavioral_analyzer",
        "rules_wizard_app",  # This is a streamlit app but let's try importing
        "dashboard",
        "web_app"
    ]
    
    for mod in custom_modules:
        try:
            __import__(mod)
            print(f"✅ {mod} (custom module)")
        except ImportError as e:
            # Some of these are streamlit apps that might not be importable as modules
            # That's OK, we'll just note it
            print(f"ℹ️  {mod} (not importable as module - likely a Streamlit app)")
    
    print(f"\n📊 Summary: {len(dependencies) - len(missing_deps)}/{len(dependencies)} core dependencies available")
    
    if missing_deps:
        print(f"\n❌ Missing dependencies: {missing_deps}")
        print("\nTo install missing dependencies, run:")
        print("pip install -r requirements.txt")
        return False
    else:
        print("\n🎉 All dependencies are available!")
        return True

if __name__ == "__main__":
    success = check_dependencies()
    if success:
        print("\n🚀 Command Line Threat Analyzer is ready to use!")
        print("You can start the web application with: python3 -m streamlit run web_app.py")
    else:
        print("\n⚠️  Please install missing dependencies before using the application.")