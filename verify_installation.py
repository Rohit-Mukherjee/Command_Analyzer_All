#!/usr/bin/env python3
"""
Installation verification script for Command Line Threat Analyzer
"""

def test_imports():
    """Test that all required modules can be imported"""
    print("🔍 Testing module imports...")
    
    modules_to_test = [
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
    
    failed_imports = []
    
    for module, alias in modules_to_test:
        try:
            if '.' in module:
                # Handle submodules like sklearn.feature_extraction.text
                parts = module.split('.')
                mod = __import__(parts[0])
                for part in parts[1:]:
                    mod = getattr(mod, part)
                globals()[alias] = mod
            else:
                mod = __import__(module)
                globals()[alias] = mod
            print(f"  ✅ {module}")
        except ImportError as e:
            print(f"  ❌ {module} - {str(e)}")
            failed_imports.append(module)
    
    # Test plotly express specifically
    try:
        import plotly.express as px
        globals()['px'] = px
        print("  ✅ plotly.express")
    except ImportError as e:
        print(f"  ❌ plotly.express - {str(e)}")
        failed_imports.append("plotly.express")
    
    return len(failed_imports) == 0

def test_custom_modules():
    """Test that custom modules can be imported"""
    print("\n🔍 Testing custom modules...")
    
    custom_modules = [
        "log_analyzer",
        "threat_intel", 
        "behavioral_analyzer",
        "dashboard",
        "rules_wizard_app",
        "web_app"
    ]
    
    failed_modules = []
    
    for module in custom_modules:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError as e:
            print(f"  ❌ {module} - {str(e)}")
            failed_modules.append(module)
    
    return len(failed_modules) == 0

def test_basic_functionality():
    """Test basic functionality of the analyzer"""
    print("\n🔍 Testing basic functionality...")
    
    try:
        from log_analyzer import generate_narrative_summary
        import pandas as pd
        
        # Create a simple test dataframe
        test_df = pd.DataFrame({
            'commandline': ['dir', 'net user', 'whoami'],
            'Analysis': ['Unknown Activity', 'User Account Creation', 'Current User Context Check']
        })
        
        # Test the narrative summary function
        summary = generate_narrative_summary(test_df)
        print("  ✅ Narrative summary generation")
        
        return True
    except Exception as e:
        print(f"  ❌ Basic functionality test failed - {str(e)}")
        return False

def main():
    print("🚀 Command Line Threat Analyzer - Installation Verification")
    print("="*60)
    
    all_passed = True
    
    # Test imports
    if not test_imports():
        all_passed = False
    
    # Test custom modules
    if not test_custom_modules():
        all_passed = False
    
    # Test basic functionality
    if not test_basic_functionality():
        all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 All tests passed! Installation is successful.")
        print("\n📋 You can now run the application:")
        print("   python log_analyzer.py                    # Command line analyzer")
        print("   streamlit run web_app.py                 # Web application")
        print("   streamlit run dashboard.py               # Dashboard")
        print("   streamlit run rules_wizard_app.py        # Rules wizard")
    else:
        print("❌ Some tests failed. Please check your installation.")
        print("   Run: pip install -r requirements.txt")
        print("   Or: ./install.sh (Linux/macOS) / install.bat (Windows)")
    
    return all_passed

if __name__ == "__main__":
    main()