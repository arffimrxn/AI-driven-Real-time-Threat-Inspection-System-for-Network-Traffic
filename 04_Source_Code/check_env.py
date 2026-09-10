import sys

print(f"Python Version: {sys.version.split()[0]}\n")

libraries = {
    "Django": "django",
    "Pandas": "pandas",
    "Scikit-Learn": "sklearn",
    "Joblib": "joblib",
    "Scapy": "scapy",
    "NumPy": "numpy"
}

for name, module_name in libraries.items():
    try:
        # Dynamically import the module
        module = __import__(module_name)
        version = getattr(module, '__version__', 'Version hidden')
        print(f"[OK] {name} is installed (Version: {version})")
    except ImportError:
        print(f"[MISSING] {name} is NOT installed.")