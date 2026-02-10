import sys
import subprocess
import importlib.util

def check_python_version():
    """Check if Python version is 3.8+"""
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        print(f"❌ Python version {major}.{minor} is too old. Need 3.8 or higher.")
        return False
    print(f"✅ Python {major}.{minor} detected")
    return True

def check_package_installed(package_name):
    """Check if a package is installed"""
    try:
        importlib.import_module(package_name)
        print(f"✅ {package_name} is installed")
        return True
    except ImportError:
        print(f"❌ {package_name} is not installed")
        return False

def check_pip_available():
    """Check if pip is available"""
    try:
        import pip
        print(f"✅ pip {pip.__version__} is available")
        return True
    except ImportError:
        print("❌ pip is not available")
        return False

def check_executable(cmd):
    """Check if a command-line executable is available"""
    try:
        result = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ {cmd} is available")
            return True
        else:
            print(f"❌ {cmd} is not available or failed to run")
            return False
    except FileNotFoundError:
        print(f"❌ {cmd} is not available")
        return False
    except Exception as e:
        print(f"❌ Error checking {cmd}: {str(e)}")
        return False

def main():
    print("🔍 Checking Command Line Threat Analyzer installation...")
    print()
    
    # Check Python version
    python_ok = check_python_version()
    print()
    
    # Check pip
    pip_ok = check_pip_available()
    print()
    
    # Check required packages
    required_packages = ['pandas', 'streamlit', 'plotly', 'sklearn', 'numpy', 'requests']
    packages_ok = []
    
    for pkg in required_packages:
        packages_ok.append(check_package_installed(pkg))
    print()
    
    # Check executables
    executables_ok = []
    executables_to_check = ['python']
    
    for exe in executables_to_check:
        executables_ok.append(check_executable(exe))
    print()
    
    # Summary
    all_checks = [python_ok, pip_ok] + packages_ok + executables_ok
    total_checks = len(all_checks)
    passed_checks = sum(all_checks)
    
    print(f"📊 Installation check summary: {passed_checks}/{total_checks} checks passed")
    
    if all(all_checks):
        print("🎉 All checks passed! Installation appears successful.")
        print()
        print("🚀 You can now run the Command Line Threat Analyzer:")
        print("   - python log_analyzer.py")
        print("   - streamlit run web_app.py")
        print("   - streamlit run rules_wizard_app.py")
        print("   - streamlit run dashboard.py")
    else:
        print("❌ Some checks failed. Please review the output above and fix any issues.")
        print("💡 Try running install.bat again or check WINDOWS_INSTALLATION.md for troubleshooting tips.")

if __name__ == "__main__":
    main()