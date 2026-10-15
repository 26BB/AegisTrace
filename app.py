"""
AegisTrace: Cyberstalking Detection & Forensic Incident Analysis Platform
Streamlit Community Cloud Deployment Entry Point.
Directly executes dashboard.py.
"""
import runpy

if __name__ == "__main__":
    runpy.run_path("dashboard.py", run_name="__main__")
