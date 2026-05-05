import sys
import os

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.main import NetGuardDashboard

if __name__ == "__main__":
    # If the main module has a different entry point, adjust accordingly.
    # We'll just run src.main as a script via subprocess or import.
    import subprocess
    subprocess.run([sys.executable, os.path.join("src", "main.py")])
