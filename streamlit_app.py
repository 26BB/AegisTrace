"""
AegisTrace: Cyberstalking Detection & Forensic Incident Analysis Platform
Streamlit Community Cloud Deployment Entry Point.
"""
import os
import sys
import runpy

# Ensure repository root is on sys.path for backend imports on Streamlit Cloud
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

if __name__ == "__main__" or True:
    dashboard_path = os.path.join(REPO_ROOT, "dashboard.py")
    runpy.run_path(dashboard_path, run_name="__main__")
