"""
Local stand-in for the threat-intel API service, used only by tests.

It serves responses in the service's real JSON contract (success envelope,
pagination, error envelope) from a background thread on 127.0.0.1, so the
real HTTP client code runs end to end without the actual service.

ALL RECORDS HERE ARE SYNTHETIC TEST DATA (reserved example.* domains),
not real threat intelligence.
"""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

NOW = "2026-10-07T12:00:00Z"


def make_record(rid, url, hostname, sources=("openphish",), threat_type="phishing", confidence=None,
                last_seen=NOW, status=None):
    return {
        "id": rid, "url": url, "scheme": url.split(":")[0], "hostname": hostname, "domain": hostname,
        "registered_domain": hostname, "tld": hostname.rsplit(".", 1)[-1], "path": "/", "is_ip": False,
        "sources": list(sources), "threat_type": threat_type, "threat_types": [threat_type],
        "confidence": confidence, "status": status, "tags": [], "first_seen": "2026-10-01T08:00:00Z",
        "last_seen": last_seen, "created_at": "2026-10-01T09:00:00Z", "updated_at": last_seen,
        "port": None,
        "sightings": [{"source": s, "source_reference": None, "threat_type": threat_type,
                       "confidence": confidence, "status": status, "tags": [],
                       "source_first_seen": "2026-10-01T08:00:00Z", "first_collected_at": "2026-10-01T09:00:00Z",
                       "last_collected_at": last_seen, "metadata": {}} for s in sources],
    }


LISTED = make_record(1, "http://secure-login.example.com/verify", "secure-login.example.com")
ON_LISTED_HOST = make_record(2, "http://shared.example.net/a", "shared.example.net")


def ok(data, **extra):
    return 200, {"success": True, **extra, "data": data}


def page(items, total=None, page_no=1, limit=20):
    total = len(items) if total is None else total
    pages = (total + limit - 1) // limit if total else 0
    return ok(items, count=len(items), pagination={"page": page_no, "limit": limit, "total": total,
                                                    "total_pages": pages, "has_next": page_no < pages})


def error(status, code, message):
    return status, {"success": False, "error": {"code": code, "message": message}}


class StubState:
    def __init__(self):
        self.records = {LISTED["url"]: LISTED}
        self.host_records = {"shared.example.net": [ON_LISTED_HOST]}
        self.latest = [LISTED, ON_LISTED_HOST]
        self.override = None      # (status, body | raw bytes) returned for every request
        self.delay = 0.0
        self.required_key = None
        self.requests = []


def _handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, status, body, headers=None):
            raw = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parts = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(parts.query).items()}
            state.requests.append({"path": parts.path, "query": q, "headers": dict(self.headers)})
            if state.delay:
                time.sleep(state.delay)
            if state.override is not None:
                status, body, *hdrs = state.override
                return self._send(status, body, hdrs[0] if hdrs else None)
            if state.required_key and self.headers.get("X-API-Key") != state.required_key:
                return self._send(*error(401, "unauthorized", "A valid X-API-Key header is required."))
            if parts.path == "/api/health":
                return self._send(*ok({"status": "ok", "database": "ok", "version": "1.0.0",
                                       "time": NOW, "scheduler": "disabled"}))
            if parts.path == "/api/urls/lookup":
                url = q.get("url", "")
                if url.startswith("http://192.168.") or url.startswith("http://localhost"):
                    return self._send(*error(422, "invalid_url", "IP address is not publicly routable."))
                rec = state.records.get(url)
                return self._send(*ok({"found": rec is not None, "normalized_url": url, "record": rec}))
            if parts.path == "/api/urls":
                items = state.host_records.get(q.get("hostname"), [])
                return self._send(*page(items, limit=int(q.get("limit", 20))))
            if parts.path == "/api/urls/latest":
                return self._send(*page(state.latest, limit=int(q.get("limit", 20))))
            return self._send(*error(404, "not_found", "The requested resource does not exist."))

    return Handler


class ThreatIntelStub:
    def __init__(self):
        self.state = StubState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(self.state))
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def unused_port_url():
    """A local URL where nothing is listening (connection refused)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"
