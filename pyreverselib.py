import datetime
import functools
import http.server
import os
import socket
import socketserver
import ssl
import threading

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from requests import get

from mylogger import logger, logging


class ReverseProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, target_host, target_port, *args, **kwargs):
        self.target_host = target_host
        self.target_port = target_port
        self.session = requests.Session()
        super().__init__(*args, **kwargs)

    def do_request(self):
        target_url = f"http://{self.target_host}:{self.target_port}{self.path}"
        # logger.debug(target_url)
        method = self.command.lower()
        data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        headers = self.headers
        # logger.debug(headers) # NOTE: worked with this enabled?!?!

        try:
            response = requests.request(
                method, target_url, data=data, headers=headers, allow_redirects=False
            )
            if 300 <= response.status_code < 400:
                # Redirect response, send appropriate status code and location header
                self.send_response(response.status_code)
                self.send_header("Location", response.headers["Location"])
                self.end_headers()
            else:
                self.send_response(response.status_code)
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response.content)
        except requests.RequestException as e:
            self.send_error(500, str(e))

    def debug_http_response(self, response):
        logger.debug(response.status)
        for header, value in response.getheaders():
            logger.debug(f"{header}: {value}")
        logger.debug("Content:")
        content = response.read()
        logger.debug(content.decode("utf-8"))  # Assuming content is text, adjust decoding as needed

    def _send_response_and_write_file(self, response):
        # self.debug_http_response(response)
        self.send_response(response.status)
        self.send_header("Access-Control-Allow-Origin", "*")  # Allow requests from any origin
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"
        )
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, Authorization"
        )  # Include any other headers as needed
        for key, value in response.getheaders():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response.read())

    def do_GET(self):
        self.do_request()

    def do_POST(self):
        self.do_request()

    def do_PUT(self):
        self.do_request()

    def do_DELETE(self):
        self.do_request()

    def do_PATCH(self):
        self.do_request()

    def do_HEAD(self):
        self.do_request()

    def do_OPTIONS(self):
        self.do_request()

    def do_CONNECT(self):
        self.do_request()


class Proxy:
    def __init__(self, host, http_port, https_port, mapping):
        self.host = host
        self.http_port = http_port
        self.https_port = https_port
        self.stop_event = threading.Event()
        self.proxy_thread = None
        self.running = False
        self.mapping = mapping

    def start(self):
        if not self.running:
            self.stop_event.clear()
            self.proxy_thread = threading.Thread(
                target=run_proxy, args=(self.host, self.http_port, self.https_port, self.stop_event)
            )
            self.proxy_thread.start()
            self.running = True

    def stop(self):
        if self.running:
            self.stop_event.set()
            assert self.proxy_thread
            self.proxy_thread.join()
            self.running = False


def check_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
            return True
        except socket.error:
            return False


def get_public_ip():
    try:
        ip = get("https://api.ipify.org").text
    except requests.exceptions.RequestException:
        ip = "N/A"
    return ip


def get_local_ips():
    local_ips = []
    hostname = socket.gethostname()
    for ip in socket.getaddrinfo(hostname, None):
        local_ips.append(ip[4][0])
    return list(set(local_ips))


def run_proxy(host, http_port, https_port, stop_event):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("socketserver").setLevel(logging.WARNING)
    if not check_port(host, http_port):
        print(f"No application running on {host}:{http_port}. Skipping proxy setup.")
        return

    cert_dir = os.path.join("certificates", str(https_port))
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        os.makedirs(cert_dir, exist_ok=True)

        print("Generating SSL certificate and key...")
        print(f"Certificate path: {cert_file}")
        print(f"Key path: {key_file}")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        public_key = private_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "FI"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Oulu"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Oulu"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "MyDept"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        with open(cert_file, "wb") as f:
            f.write(builder.public_bytes(serialization.Encoding.PEM))

        with open(key_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

    HandlerClass = functools.partial(ReverseProxyHTTPRequestHandler, host, http_port)
    httpd = socketserver.TCPServer(("0.0.0.0", https_port), HandlerClass)  # Bind to all interfaces
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.timeout = 1  # Add this line to set a timeout for handle_request

    local_ips = get_local_ips()
    public_ip = get_public_ip()

    print("Serving HTTPS on the following addresses:")
    for local_ip in local_ips:
        if ":" not in local_ip:  # Filter out IPv6 addresses
            print(f"- https://{local_ip}:{https_port}")
    print(f"- Public IP: https://{public_ip}:{https_port}")

    try:
        while not stop_event.is_set():
            httpd.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
