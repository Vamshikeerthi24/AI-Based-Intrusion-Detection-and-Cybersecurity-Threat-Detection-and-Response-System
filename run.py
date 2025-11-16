"""
Runner that starts both FastAPI backend and Streamlit frontend.

Use this script instead of `app.py` to avoid name collision with the `app` package.
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
import importlib


ROOT = Path(__file__).parent


def ensure_pythonpath():
    p = str(ROOT)
    existing = os.environ.get('PYTHONPATH', '')
    if p not in existing.split(os.pathsep):
        os.environ['PYTHONPATH'] = p + (os.pathsep + existing if existing else '')


def start_uvicorn_in_thread(host: str = '0.0.0.0', port: int = 8000, log_level: str = 'info'):
    import uvicorn
    # Load the FastAPI app module from file to avoid name-shadowing issues
    api_path = ROOT / 'app' / 'api.py'
    if not api_path.exists():
        raise RuntimeError(f"Cannot find backend module at {api_path}")
    import importlib.util
    spec = importlib.util.spec_from_file_location('backend_api', str(api_path))
    api_module = importlib.util.module_from_spec(spec)
    # Ensure the `app` package name maps to the local `app` directory so
    # imports like `from app.schemas import Flow` inside api.py work even if
    # a top-level `app.py` file exists that would otherwise shadow the package.
    import types
    pkg = types.ModuleType('app')
    pkg.__path__ = [str(ROOT / 'app')]
    sys.modules['app'] = pkg

    spec.loader.exec_module(api_module)

    config = uvicorn.Config(api_module.app, host=host, port=port, log_level=log_level, loop='asyncio')
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, name='uvicorn-thread', daemon=True)
    thread.start()

    # wait briefly for server to start
    timeout = 10
    start = time.time()
    while time.time() - start < timeout:
        if getattr(server, 'started', False):
            break
        time.sleep(0.1)

    return server


def start_streamlit_subprocess(python_exe: str, app_path: str, host: str = '127.0.0.1', port: int = 8501):
    cmd = [python_exe, '-m', 'streamlit', 'run', app_path, '--server.headless', 'true', '--server.address', host, '--server.port', str(port)]
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

    server = start_uvicorn_in_thread(host=args.backend_host, port=args.backend_port, log_level=args.log_level)
    backend_url = f'http://{args.backend_host}:{args.backend_port}'
    if not getattr(server, 'started', False):
        print('Warning: uvicorn server did not report started state immediately. Check logs.')
    else:
        print(f'Backend started on {backend_url}')

    streamlit_proc = None
    if not args.no_streamlit:
        streamlit_proc = start_streamlit_subprocess(python_exe=args.python_exe, app_path='app/streamlit_app.py', host=args.streamlit_host, port=args.streamlit_port)
        print('Streamlit process started (PID=%s). UI available at http://%s:%s' % (streamlit_proc.pid, args.streamlit_host, args.streamlit_port))

        if args.open_browser:
            try:
                webbrowser.open_new_tab(f'http://{args.streamlit_host}:{args.streamlit_port}')
            except Exception:
                pass

    def _shutdown(signum=None, frame=None):
        print('\nShutting down combined app...')
        try:
            server.should_exit = True
        except Exception:
            pass
        try:
            if streamlit_proc is not None and streamlit_proc.poll() is None:
                streamlit_proc.terminate()
                try:
                    streamlit_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    streamlit_proc.kill()
        except Exception:
            pass
        print('Shutdown complete.')
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        while True:
            if streamlit_proc is not None and streamlit_proc.poll() is not None:
                print('Streamlit exited with code', streamlit_proc.returncode)
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        _shutdown()


if __name__ == '__main__':
    main()
