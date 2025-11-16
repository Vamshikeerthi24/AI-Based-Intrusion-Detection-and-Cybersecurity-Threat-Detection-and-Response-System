"""
Top-level runner to start both the FastAPI backend and the Streamlit frontend
from a single command. This script:

- starts the FastAPI app defined in `app.api` using uvicorn in a background thread
- starts Streamlit via `python -m streamlit run app/streamlit_app.py` as a subprocess
- opens the Streamlit UI in the default browser and handles graceful shutdown

Usage:
    & "path\to\python.exe" app.py

Notes:
- We run uvicorn without the autoreload option here because autoreload spawns
  child processes which complicate graceful shutdown from this script.
- Streamlit must be available in the same Python environment.
"""
import os
import sys
import threading
import subprocess
import time
import signal
import webbrowser
from pathlib import Path
import argparse


ROOT = Path(__file__).parent


def ensure_pythonpath():
    """Ensure project root is on PYTHONPATH so local imports work for subprocesses."""
    p = str(ROOT)
    existing = os.environ.get('PYTHONPATH', '')
    if p not in existing.split(os.pathsep):
        os.environ['PYTHONPATH'] = p + (os.pathsep + existing if existing else '')


def start_uvicorn_in_thread(host: str = '0.0.0.0', port: int = 8000, log_level: str = 'info'):
    """Start uvicorn.Server in a background thread and return the Server object."""
    import uvicorn
    # Import the FastAPI app lazily so environment is set up first
    from app import api as api_module

    config = uvicorn.Config(api_module.app, host=host, port=port, log_level=log_level, loop='asyncio')
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, name='uvicorn-thread', daemon=True)
    thread.start()

    # Wait briefly for server to start (uvicorn logs will show up in stdout)
    timeout = 10
    start = time.time()
    while time.time() - start < timeout:
        if server.started:
            break
        time.sleep(0.1)

    return server


def start_streamlit_subprocess(python_exe: str = sys.executable, app_path: str = 'app/streamlit_app.py'):
    """Start Streamlit as a subprocess and return the Popen object."""
    cmd = [python_exe, '-m', 'streamlit', 'run', app_path, '--server.headless', 'true']
    # Force working directory to project root so relative paths resolve
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=os.environ)
    return proc


def main(argv=None):
    ensure_pythonpath()

    parser = argparse.ArgumentParser(description='Run backend (FastAPI) and frontend (Streamlit) together')
    parser.add_argument('--no-streamlit', action='store_true', help='Do not start the Streamlit frontend')
    parser.add_argument('--backend-host', default='0.0.0.0', help='Backend host (uvicorn)')
    parser.add_argument('--backend-port', type=int, default=8000, help='Backend port (uvicorn)')
    parser.add_argument('--streamlit-host', default='127.0.0.1', help='Streamlit host')
    parser.add_argument('--streamlit-port', type=int, default=8501, help='Streamlit port')
    parser.add_argument('--open-browser', action='store_true', help='Open the Streamlit UI in the default browser')
    parser.add_argument('--python-exe', default=sys.executable, help='Python executable to run Streamlit with')
    parser.add_argument('--log-level', default='info', help='uvicorn log level')
    args = parser.parse_args(argv)

    print('Starting combined app: backend (uvicorn) + frontend (streamlit)')

    # Start backend
    server = start_uvicorn_in_thread(host=args.backend_host, port=args.backend_port, log_level=args.log_level)
    backend_url = f'http://{args.backend_host}:{args.backend_port}'
    if not getattr(server, 'started', False):
        print('Warning: uvicorn server did not report started state immediately. Check logs.')
    else:
        print(f'Backend started on {backend_url}')

    streamlit_proc = None
    if not args.no_streamlit:
        # Start frontend
        streamlit_proc = start_streamlit_subprocess(python_exe=args.python_exe, app_path='app/streamlit_app.py')
        print('Streamlit process started (PID=%s). UI available at http://%s:%s' % (streamlit_proc.pid, args.streamlit_host, args.streamlit_port))

        # Open Streamlit in browser optionally
        if args.open_browser:
            try:
                webbrowser.open_new_tab(f'http://{args.streamlit_host}:{args.streamlit_port}')
            except Exception:
                pass

    # Graceful shutdown handling
    def _shutdown(signum=None, frame=None):
        print('\nShutting down combined app...')
        try:
            # stop uvicorn
            server.should_exit = True
        except Exception:
            pass
        try:
            if streamlit_proc is not None and streamlit_proc.poll() is None:
                streamlit_proc.terminate()
                # give it a moment
                try:
                    streamlit_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    streamlit_proc.kill()
        except Exception:
            pass
        print('Shutdown complete.')
        # allow other handlers to run then exit
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Wait until either process exits
    try:
        while True:
            if streamlit_proc is not None and streamlit_proc.poll() is not None:
                print('Streamlit exited with code', streamlit_proc.returncode)
                break
            # if server exited, the should_exit flag will be true and server.stopped will be set
            time.sleep(0.5)
    except KeyboardInterrupt:
        _shutdown()


if __name__ == '__main__':
    main()
