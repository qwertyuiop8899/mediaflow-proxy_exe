import os
import sys
from dotenv import load_dotenv

# ✅ Determine base path whether running as EXE or .py
base_path = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)

# ✅ Load .env next to EXE or script
dotenv_path = os.path.join(base_path, ".env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    print("⚠️ No .env file found")

# ✅ Set fallback values
os.environ.setdefault("API_PASSWORD", "mfp")

# ✅ Optional: Show API_PASSWORD if DEBUG=true
if os.getenv("DEBUG", "false").lower() == "true":
    print(f"🔐 API_PASSWORD: {os.getenv('API_PASSWORD')}")

# ✅ Import the FastAPI app AFTER env setup
from mediaflow_proxy.main import app

def run():
    import uvicorn

    # Check if running as frozen EXE
    is_frozen = getattr(sys, 'frozen', False)

    # Try to load HTTPS certs from the same folder
    cert_file = os.path.join(base_path, "cert.pem")
    key_file = os.path.join(base_path, "key.pem")

    ssl_args = {}
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_args["ssl_certfile"] = cert_file
        ssl_args["ssl_keyfile"] = key_file
        print("🔐 HTTPS enabled (cert.pem + key.pem)")
    else:
        print("⚠️ HTTPS certs not found, running on plain HTTP")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8888,
        reload=not is_frozen,
        workers=1,
        log_level="info",
        **ssl_args
    )

if __name__ == "__main__":
    run()
