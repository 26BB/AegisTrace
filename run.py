import argparse
import os
import subprocess
import sys
import time


def run_backend(port: int = 8000):
    print(f"[*] Starting AegisTrace FastAPI backend on http://127.0.0.1:{port}...")
    cmd = [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(port), "--reload"]
    return subprocess.Popen(cmd)


def run_dashboard(port: int = 8501):
    print(f"[*] Starting AegisTrace Streamlit dashboard on http://localhost:{port}...")
    cmd = [sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.port", str(port)]
    return subprocess.Popen(cmd)


def main():
    parser = argparse.ArgumentParser(description="AegisTrace: Cyberstalking Detection & Forensic Incident Analysis Platform")
    parser.add_argument("--backend-only", action="store_true", help="Launch only the FastAPI backend server")
    parser.add_argument("--dashboard-only", action="store_true", help="Launch only the Streamlit dashboard")
    parser.add_argument("--backend-port", type=int, default=8000, help="Port for FastAPI backend (default 8000)")
    parser.add_argument("--dashboard-port", type=int, default=8501, help="Port for Streamlit dashboard (default 8501)")

    args = parser.parse_args()

    processes = []
    try:
        if args.backend_only:
            proc = run_backend(args.backend_port)
            proc.wait()
        elif args.dashboard_only:
            proc = run_dashboard(args.dashboard_port)
            proc.wait()
        else:
            print("=================================================================")
            print("  🛡️  AEGISTRACE: CYBERSTALKING DETECTION & FORENSICS PLATFORM  ")
            print("=================================================================")
            b_proc = run_backend(args.backend_port)
            processes.append(b_proc)
            time.sleep(2)  # Give backend a moment to bind

            d_proc = run_dashboard(args.dashboard_port)
            processes.append(d_proc)

            print("\n[*] AegisTrace is active!")
            print(f"[*] Backend Swagger API Docs: http://127.0.0.1:{args.backend_port}/docs")
            print(f"[*] Streamlit Dark UI:        http://localhost:{args.dashboard_port}")
            print("[*] Press Ctrl+C to terminate both servers safely.\n")

            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down AegisTrace services...")
        for p in processes:
            p.terminate()
        print("[*] Services stopped cleanly.")


if __name__ == "__main__":
    main()
