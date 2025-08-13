#!/usr/bin/env python3
import os
import sys
import ipaddress
import logging
import signal
import socket
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

import uvicorn
from dotenv import load_dotenv


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def get_runtime_base() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def prepare_env_paths(base_path: Path) -> None:
    bin_path = base_path / "bin"
    if bin_path.exists():
        os.environ["PATH"] = f"{str(bin_path)}{os.pathsep}{os.environ.get('PATH','')}"


def validate_config() -> Tuple[int, bool]:
    """Validate PORT and API_PASSWORD, show warnings, return (port, debug)."""
    try:
        port = int(os.getenv("PORT", "8888"))
        if not (1 <= port <= 65535):
            raise ValueError(f"{port} out of valid range (1–65535)")
    except ValueError as e:
        print(f"❌ Invalid PORT: {e}")
        port = 8888
        print(f"🔄 Using default PORT: {port}")

    api_pw = os.getenv("API_PASSWORD")
    if not api_pw:
        print("⚠️ WARNING: API_PASSWORD is not set!")
    elif api_pw == "changeme":
        print("⚠️ WARNING: You are using the default API password 'changeme'!")

    debug = parse_bool(os.getenv("DEBUG"), default=False)
    if debug:
        print("🐛 Debug mode enabled")
        print(f"🔐 API_PASSWORD: {api_pw or '<not set>'}")
        print(f"🌐 PORT: {port}")

    return port, debug


def show_startup_info(base_path: Path, protocol: str, host: str, port: int) -> None:
    """Print startup banner with working directory and listen URLs."""
    print("=" * 50)
    print("🎬 MediaFlow Proxy Server")
    print("=" * 50)
    print(f"📁 Working directory: {base_path}")
    print(f"🌐 Serving on: {protocol}://{host}:{port}")
    if host in ("0.0.0.0", "::"):
        print(f"   • Local:   {protocol}://127.0.0.1:{port}")
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"   • Network: {protocol}://{local_ip}:{port}")
        except Exception:
            pass
    print("=" * 50)


def ensure_cert(cert_base: Path) -> Tuple[Dict[str, Any], str]:
    """Dynamically generate SSL certificates with auto-detected IPs."""
    disable_https = parse_bool(os.getenv("DISABLE_HTTPS"), default=False)
    if disable_https:
        print("🔓 HTTPS disabled via DISABLE_HTTPS environment variable")
        print("🌐 Starting in HTTP mode")
        return {}, "HTTP"

    dist_bin = cert_base / "bin"
    dist_bin.mkdir(parents=True, exist_ok=True)
    cert_file = dist_bin / "server.pem"
    key_file = dist_bin / "server.key"

    if cert_file.exists() and key_file.exists():
        try:
            if cert_file.stat().st_size and key_file.stat().st_size:
                print(f"🔐 Using existing certificates at {cert_file} + {key_file}")
                return ({"ssl_certfile": str(cert_file), "ssl_keyfile": str(key_file)}, "HTTPS")
        except Exception as e:
            print(f"⚠️ Error reading certs: {e}; regenerating...")

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MediaFlow Proxy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        # Start with basic localhost entries
        san_list = [
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.IPAddress(ipaddress.IPv6Address("::1")),
        ]
        
        # Dynamically detect local network IP
        detected_ips = []
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip != "127.0.0.1":
                san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
                detected_ips.append(local_ip)
        except Exception:
            pass
            
        # Try to get primary network interface IP
        try:
            # Connect to a remote address to determine the best local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                primary_ip = s.getsockname()[0]
                if primary_ip not in ["127.0.0.1"] + detected_ips:
                    san_list.append(x509.IPAddress(ipaddress.IPv4Address(primary_ip)))
                    detected_ips.append(primary_ip)
        except Exception:
            pass

        # Optional: Add custom IPs from environment variable
        custom_ips = os.getenv("CERT_ADDITIONAL_IPS", "").strip()
        if custom_ips:
            for ip in custom_ips.split(","):
                ip = ip.strip()
                if ip:
                    try:
                        san_list.append(x509.IPAddress(ipaddress.IPv4Address(ip)))
                        detected_ips.append(ip)
                    except Exception as e:
                        print(f"⚠️ Invalid IP in CERT_ADDITIONAL_IPS: {ip}")

        san = x509.SubjectAlternativeName(san_list)

        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(san, critical=False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        print(f"🔐 Generated self-signed cert at {cert_file} + {key_file}")
        if detected_ips:
            print(f"   Certificate includes detected IPs: {', '.join(detected_ips)}")
        return ({"ssl_certfile": str(cert_file), "ssl_keyfile": str(key_file)}, "HTTPS")
        
    except ImportError:
        print("⚠️ cryptography not available; falling back to HTTP")
        return {}, "HTTP"
    except Exception as e:
        print(f"⚠️ Error generating certs: {e}; falling back to HTTP")
        return {}, "HTTP"


def configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    if debug:
        logging.getLogger("uvicorn").setLevel(logging.DEBUG)
        logging.getLogger("uvicorn.error").setLevel(logging.DEBUG)
        logging.getLogger("uvicorn.access").setLevel(logging.DEBUG)


def build_uvicorn_config(
    port: int,
    host: str,
    ssl_config: Dict[str, Any],
    enable_http2: bool,
    debug: bool,
) -> Dict[str, Any]:
    config: Dict[str, Any] = {
        "app": "mediaflow_proxy.main:app",
        "host": host,
        "port": port,
        "log_level": "debug" if debug else "info",
        "proxy_headers": True,
        "forwarded_allow_ips": "*",
        "http": "h11" if (ssl_config and enable_http2) else "auto",
    }
    config.update(ssl_config)
    return config


def main() -> None:
    runtime_base = get_runtime_base()
    prepare_env_paths(runtime_base)
    sys.path.insert(0, str(runtime_base))
    load_dotenv(dotenv_path=runtime_base / ".env")

    port, debug = validate_config()
    host = os.getenv("HOST", "0.0.0.0")
    enable_http2 = parse_bool(os.getenv("UVICORN_HTTP2"), default=True)

    configure_logging(debug)

    ssl_config, protocol = ensure_cert(runtime_base)
    show_startup_info(runtime_base, protocol, host, port)

    uvicorn_cfg = build_uvicorn_config(port, host, ssl_config, enable_http2, debug)

    def handle_signal(signum, frame):
        logging.info(f"Received signal {signum}. Shutting down...")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handle_signal)
        except Exception:
            pass

    uvicorn.run(**uvicorn_cfg)


if __name__ == "__main__":
    main()
