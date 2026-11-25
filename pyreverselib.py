import ipaddress
import datetime
import functools
import http.server
import os
import socket
import socketserver
import ssl
import threading
import yaml
from urllib.parse import urlparse, urlsplit, urlunsplit

import httpx2


import atexit

import httpx2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mylogger import logger, logging


# Hop-by-hop headers must not be forwarded either direction (RFC 9110 section 7.6.1).
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

WEBSOCKET_EXCLUDED = {
        "host",
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        "sec-websocket-protocol",
        "content-length",
        "transfer-encoding",
    }


class ReverseProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Keep-alive by default; the WebSocket path sets this True before handing
    # the connection to its bridge thread so the socket is not reused or closed
    # by BaseHTTPRequestHandler.
    close_connection = False

    # Shared by every thread created by this process: marks worker threads so
    # atexit handlers (ssl encryption-shutdown teardown) can wait for them.
    _PROXY_THREADS = []

    def __init__(self, target_host, target_port, target_mappings, *args, **kwargs):
        self.target_host = target_host
        self.target_port = target_port
        self.target_mappings = target_mappings
        self.local_ips = get_local_ips()
        # trust_env=False: the proxy connects to LAN backends over the plain
        # loopback/LAN link and must never be hijacked by HTTP(S)_PROXY
        # environment variables (a stray system proxy would swallow or alter
        # upstream requests, e.g. WebSocket upgrades).
        self.session = httpx2.Client(trust_env=False)
        super().__init__(*args, **kwargs)


    def finish(self):
        # BaseHTTPRequestHandler runs the whole request inside __init__, so this
        # is the last hook that runs once the response has been flushed. Free the
        # connection pool instead of leaking it on every request.
        try:
            self.session.close()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError) as e:
            logger.debug("Error closing session: %s", e)
        try:
            super().finish()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError) as e:
            # Abort during teardown is expected when the browser disconnects.
            logger.debug("Client disconnected during finish(): %s", e)
        logger.debug("Handler finish: conn=%s thread=%s",
             id(self.connection), threading.get_ident())

    def rewrite_location(self, loc):
        parts = urlsplit(loc)
        if parts.hostname not in (*self.local_ips, "localhost", "127.0.0.1", "::1"):
            return loc                       # external — leave alone
        public = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        pub_host, _, pub_port = public.partition(":")
        scheme = self.headers.get("X-Forwarded-Proto", "https")
        netloc = f"{pub_host}:{pub_port}" if pub_port else pub_host
        return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))

    def get_target(self):
        host_header = self.headers.get("Host", "")
        if host_header.startswith("["):
            requested_host = host_header.split("]")[0][1:].lower()
        else:
            requested_host = host_header.split(":", 1)[0].lower()
        host, port = self.target_host, self.target_port
        if self.target_mappings:
            for subdomain, details in self.target_mappings.items():
                sub = str(subdomain).lower()
                if requested_host == sub or requested_host.startswith(sub + "."):
                    host = details.get("addr", host)
                    port = details.get("port", port)
                    logger.debug("mapping %s -> %s:%s", subdomain, host, port)
                    break
        return host, port


    def do_request(self):
        logger.info("conn=%s thread=%s %s %s CL=%r TE=%r",
            id(self.connection), threading.get_ident(), self.command, self.path,
            self.headers.get("Content-Length"), self.headers.get("Transfer-Encoding"))
        try:
            logger.debug(
                "REQUEST %s %s Upgrade=%r Connection=%r",
                self.command,
                self.path,
                self.headers.get("Upgrade"),
                self.headers.get("Connection"),
            )
            if self.headers.get("Upgrade", "").lower() == "websocket":
                return self.do_websocket()

            target_host, target_port = self.get_target()
            target_url = f"http://{target_host}:{target_port}{self.path}"
            logger.debug(target_url)
            return self.do_http(target_url)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError) as e:
            # Client disconnected during request processing - log at debug level
            logger.debug("Client disconnected during request processing: %s", e)
        except Exception as e:
            logger.exception("Error processing request: %s", e)


        #self.rewrite_location(request_headers["Location"])

    def do_websocket(self):
        import socket
        import threading

        from wsproto import WSConnection, ConnectionType
        from wsproto.events import (
            Request, AcceptConnection, TextMessage, BytesMessage,
            Ping, CloseConnection,
        )
        from httpx2.websockets import (
            WebSocketDisconnect,
            WebSocketUpgradeError,
        )

        target_host, target_port = self.get_target()
        target_url = f"ws://{target_host}:{target_port}{self.path}"

        excluded_headers = {
            "host", "connection", "upgrade",
            "sec-websocket-key", "sec-websocket-version",
            "sec-websocket-extensions", "sec-websocket-protocol",
            "content-length", "transfer-encoding",
        }

        headers = {
            key: value
            for key, value in self._build_headers().items()
            if key.lower() not in excluded_headers
        }

        requested_protocols = [
            protocol.strip()
            for protocol in self.headers.get(
                "Sec-WebSocket-Protocol", ""
            ).split(",")
            if protocol.strip()
        ]

        ws = WSConnection(ConnectionType.SERVER)
        ws_lock = threading.Lock()
        write_lock = threading.Lock()
        stop = threading.Event()

        def send_client(event):
            with ws_lock:
                data = ws.send(event)

            if data:
                with write_lock:
                    self.wfile.write(data)
                    self.wfile.flush()

        def close_client():
            stop.set()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def client_to_upstream(upstream):
            try:
                pending_text = None
                pending_bytes = None

                while not stop.is_set():
                    data = self.rfile.read1(65536)
                    if not data:
                        break

                    with ws_lock:
                        ws.receive_data(data)
                        events = list(ws.events())

                    for event in events:
                        if isinstance(event, TextMessage):
                            if pending_text is None:
                                pending_text = ""

                            pending_text += event.data

                            if event.message_finished:
                                upstream.send_text(pending_text)
                                pending_text = None

                        elif isinstance(event, BytesMessage):
                            if pending_bytes is None:
                                pending_bytes = bytearray()

                            pending_bytes.extend(event.data)

                            if event.message_finished:
                                upstream.send_bytes(bytes(pending_bytes))
                                pending_bytes = None

                        elif isinstance(event, Ping):
                            send_client(event.response())

                        elif isinstance(event, CloseConnection):
                            send_client(event.response())
                            return

            except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError):
                logger.debug("WebSocket client disconnected")
            except Exception:
                logger.exception("WebSocket client-to-upstream relay failed")
            finally:
                stop.set()
                try:
                    upstream.close()
                except Exception:
                    pass

        logger.debug("WebSocket target: %s", target_url)

        try:
            with self.session.websocket(
                target_url,
                headers=headers,
                subprotocols=requested_protocols or None,
            ) as upstream:

                # Reconstruct the already-parsed browser handshake for wsproto.
                request = (
                    f"GET {self.path} HTTP/1.1\r\n"
                    + "".join(
                        f"{key}: {value}\r\n"
                        for key, value in self.headers.items()
                    )
                    + "\r\n"
                ).encode("latin-1")

                ws.receive_data(request)
                events = list(ws.events())

                if not any(isinstance(event, Request) for event in events):
                    raise RuntimeError("wsproto did not accept the browser handshake")

                send_client(AcceptConnection(subprotocol=upstream.subprotocol))

                self.close_connection = True

                logger.debug(
                    "WebSocket established: %s, subprotocol=%r",
                    target_url,
                    upstream.subprotocol,
                )

                sender = threading.Thread(
                    target=client_to_upstream,
                    args=(upstream,),
                    daemon=True,
                )
                sender.start()

                try:
                    while not stop.is_set():
                        try:
                            message = upstream.receive_text()
                            send_client(TextMessage(data=message))
                        except WebSocketDisconnect:
                            break

                finally:
                    close_client()
                    try:
                        upstream.close()
                    except Exception:
                        pass

                    sender.join(timeout=6)

        except WebSocketUpgradeError as exc:
            logger.warning(
                "WebSocket upgrade rejected: %s",
                exc.response.status_code,
            )
            if not self.close_connection:
                self.send_error(exc.response.status_code, "Upstream WebSocket upgrade failed")

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            logger.debug("WebSocket connection closed")

        except Exception:
            logger.exception("WebSocket proxy failed")
            if not self.close_connection:
                raise

    def _send_upstream_headers(self, response, body_len):
        """Write the status line and headers for a fully-buffered body of
        ``body_len`` bytes, with Content-Length computed to match."""
        self.send_response(response.status_code)
        for key, value in response.headers.multi_items():
            lk = key.lower()
            if lk in HOP_BY_HOP_HEADERS or lk in ("content-length", "content-encoding", "server", "date"):
                continue
            if lk in ("location", "content-location"):
                value = self.rewrite_location(value)
            self.send_header(key, value)
        self.send_header("Content-Length", str(body_len))
        self.end_headers()

    def _build_headers(self):
        # Drop hop-by-hop headers and Content-Length (httpx recomputes it
        # from the body we actually pass, which also fixes chunked requests).
        return {
            k: v for k, v in self.headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "content-length"
        }

    def _read_exact(self, n):
        data = self.rfile.read(n)          # buffered rfile: blocks until n bytes or EOF
        if len(data) < n:
            raise ConnectionResetError("client closed mid-body")
        return data

    def _read_chunk_line(self, max_bytes=1024 * 1024):
        buf = bytearray()
        while True:
            part = self.rfile.readline(min(65537, max_bytes - len(buf) + 1))
            if not part:
                break
            buf += part
            if part.endswith(b"\n"):
                break
            if len(buf) >= max_bytes:
                raise ValueError("chunk header/trailer line too long")
        return bytes(buf)

    def _read_chunked(self):
        out = bytearray()
        while True:
            line = self._read_chunk_line()
            if not line:
                raise ConnectionResetError("unexpected EOF reading chunk size")
            size_token = line.split(b";", 1)[0].strip()
            if not size_token:
                raise ValueError("empty chunk size")
            size = int(size_token, 16)
            if size < 0:
                raise ValueError("negative chunk size")
            if size == 0:
                while True:
                    trailer = self._read_chunk_line()
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            out += self._read_exact(size)
            crlf = self._read_exact(2)
            if crlf != b"\r\n":
                raise ValueError("missing CRLF after chunk data")
        return bytes(out)

    def _read_body(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self._read_chunked()
        return self._read_exact(int(self.headers.get("Content-Length") or 0))

    def do_http(self, target_url):
        try:
            data = self._read_body()
        except (ValueError, ConnectionError, OSError):
            self.close_connection = True
            return

        headers_sent = False
        try:
            with self.session.stream(
                self.command,
                target_url,
                content=data or None,
                headers=self._build_headers(),
                follow_redirects=False,
            ) as response:
                status = response.status_code
                head = self.command == "HEAD"
                has_body = not head and status >= 200 and status not in (204, 304)
                upstream_len = response.headers.get("content-length")

                self.send_response(status)
                for key, value in response.headers.multi_items():
                    lk = key.lower()
                    if lk in HOP_BY_HOP_HEADERS or lk in ("content-length", "server", "date"):
                        continue
                    if lk in ("location", "content-location"):
                        value = self.rewrite_location(value)
                    self.send_header(key, value)

                chunked = False
                if upstream_len is not None and (has_body or head):
                    self.send_header("Content-Length", upstream_len)
                elif has_body:
                    if self.request_version == "HTTP/1.1":
                        chunked = True
                        self.send_header("Transfer-Encoding", "chunked")
                    else:
                        self.close_connection = True   # HTTP/1.0: body ends at close
                self.end_headers()
                headers_sent = True

                if not has_body:
                    return

                for chunk in response.iter_raw():
                    if not chunk:
                        continue
                    if chunked:
                        #logger.debug("writing chunk len=%d (0x%x) to %s", len(chunk), len(chunk), target_url)
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        self.wfile.flush()
                    else:
                        self.wfile.write(chunk)
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()

        except httpx2.HTTPError as e:
            if headers_sent:
                # Too late for an error page. Drop the connection with no chunk
                # terminator so the client sees a truncated body, not a clean end.
                self.close_connection = True
                logger.debug("Upstream failed mid-body: %s", e)
            else:
                self.send_error(502, str(e))
        except OSError as e:
            # Client went away (very common when a video player seeks).
            self.close_connection = True
            logger.debug("Client disconnected during response: %s", e)

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


def load_mappings(filename):
    logger.debug(filename)
    with open(filename, "r") as f:
        mappings = yaml.safe_load(f)
    return mappings


class Proxy:
    def __init__(self, host, http_port, https_port, mapping):
        self.host = host
        self.http_port = http_port
        self.https_port = https_port
        self.stop_event = threading.Event()
        self.proxy_thread = None
        self.running = False
        self.mapping = mapping
        self.local_ips = get_local_ips()
        if mapping:
            self.mappings = load_mappings(mapping)
            logger.debug(self.mappings)

    def start(self):
        if not self.running:
            self.stop_event.clear()
            self.proxy_thread = threading.Thread(
                target=run_proxy,
                args=(self.host, self.http_port, self.https_port, self.mappings, self.stop_event),
                daemon=True,
            )
            self.proxy_thread.start()
            self.running = True

    def stop(self):
        if self.running:
            logger.info("Proxy stop requested")
            self.stop_event.set()
            start = datetime.datetime.now()
            self.proxy_thread.join()
            logger.info("Proxy thread stopped after %s",
                        datetime.datetime.now() - start)
            for t in threading.enumerate():
                logger.warning(
                    "THREAD name=%s ident=%s daemon=%s alive=%s",
                    t.name, t.ident, t.daemon, t.is_alive()
                    )
            #import faulthandler
            #import sys

            #faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
            self.running = False

def check_mappings(mappings):
    service_status = {}

    for service, details in mappings.items():
        addr = details.get("addr")
        port = details.get("port")

        assert addr and port
        addr = urlparse(addr).path

        # Check if the port is available
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((addr, port))
            service_status[service] = result == 0

    return service_status


def check_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((host, port))
            return True
        except socket.error:
            return False


def get_public_ip():
    try:
        ip = httpx2.get("https://api.ipify.org").text
    except httpx2.HTTPError:
        ip = "N/A"
    return ip


def get_local_ips():
    local_ips = []
    hostname = socket.gethostname()
    for ip in socket.getaddrinfo(hostname, None):
        local_ips.append(ip[4][0])
    return list(set(local_ips))


def make_private_key(key_file, cert_file):

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
    utcnow = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(utcnow)
        .not_valid_after(utcnow + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("*.localhost"),
                x509.DNSName("senevri.dy.fi"),
                x509.DNSName("*.senevri.dy.fi")
                ]),
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



class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.active_requests = set()
        self.active_requests_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        with self.active_requests_lock:
            self.active_requests.add(request)

        try:
            super().process_request(request, client_address)
        except Exception:
            with self.active_requests_lock:
                self.active_requests.discard(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.active_requests_lock:
                self.active_requests.discard(request)

    def close_active_requests(self):
        with self.active_requests_lock:
            requests = list(self.active_requests)

        logger.info("Closing %d active client connections", len(requests))

        for conn in requests:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            try:
                conn.close()
            except OSError:
                pass


def run_proxy(host, http_port, https_port, mappings, stop_event):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("socketserver").setLevel(logging.WARNING)

    # TODO: Check for mappings services
    if not check_port(host, http_port):
        if not all(check_mappings(mappings)):
            print(f"No application running on {host}:{http_port}. Skipping proxy setup.")
            return

    cert_dir = os.path.join("certificates", str(https_port))
    cert_file = os.path.join(cert_dir, "cert.pem")
    key_file = os.path.join(cert_dir, "key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        os.makedirs(cert_dir, exist_ok=True)
        make_private_key(key_file, cert_file)

    HandlerClass = functools.partial(ReverseProxyHTTPRequestHandler, host, http_port, mappings)
    httpd = ThreadingTCPServer(("0.0.0.0", https_port), HandlerClass)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.timeout = 6  # Add this line to set a timeout for handle_request

    local_ips = get_local_ips()
    public_ip = get_public_ip()

    print("Serving HTTPS on the following addresses:")
    for local_ip in local_ips:
        if ":" not in local_ip:  # Filter out IPv6 addresses
            print(f"- https://{local_ip}:{https_port}")
    print(f"- Public IP: https://{public_ip}:{https_port}")

    try:
        while not stop_event.is_set():
            try:
                httpd.handle_request()
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError) as e:
                # Client disconnected during request handling - log at debug level
                logger.debug("Client disconnected during request: %s", e)
            except Exception as e:
                logger.exception("Error handling request: %s", e)
    except KeyboardInterrupt:
        pass
    finally:
        # httpd.shutdown() Threading server, no need?
        httpd.close_active_requests()
        httpd.server_close()
