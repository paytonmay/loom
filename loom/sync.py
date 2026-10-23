"""Relays and sync.

A relay knows hashes and signatures, not documents. It stores a blob only if
the blob is a structurally valid, correctly signed op whose hash matches.
Two implementations share one interface: a directory, and an HTTP server.

The two are the same layout. A directory relay is a folder holding
`blobs/<hex>` (op bytes) and `docs/<hex>` (one op hash per line). The HTTP
relay serves those files verbatim and adds one POST route. So any static
host that serves the folder, with no code at all, is a read-only relay:
peers pull from it; the owner pushes to the folder and publishes it.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request, error

from .canon import sha256, is_hash, hex_of, from_hex
from .ops import verify_op, action_kind
from .store import Store

MAX_BLOB = 1_000_000  # bytes; an op is a few KB, a relay that sends more is lying


def accept_blob(store: Store, data: bytes) -> str:
    """Store an op blob after verifying it. Raises ValueError if it is not acceptable."""
    if len(data) > MAX_BLOB:
        raise ValueError("too large")
    try:
        op = json.loads(data)
    except (ValueError, RecursionError):
        raise ValueError("not JSON")
    ok, why = verify_op(op)
    if not ok:
        raise ValueError(why)
    h = store.put(data)
    doc = h if action_kind(op["action"]) == "genesis" else op["doc"]
    store.add_to_doc(doc, h)
    return h


class DirRelay:
    def __init__(self, path: Path):
        self.store = Store(Path(path))

    def list(self, doc_id: str) -> set[str]:
        return self.store.doc_ops(doc_id)

    def get(self, h: str) -> bytes:
        return self.store.get(h)

    def put(self, data: bytes) -> str:
        return accept_blob(self.store, data)


class HttpRelay:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")

    def list(self, doc_id: str) -> set[str]:
        try:
            with request.urlopen(f"{self.base}/docs/{hex_of(doc_id)}", timeout=10) as r:
                text = r.read(64 * MAX_BLOB).decode("utf-8", "replace").strip()
        except error.HTTPError as e:
            if e.code == 404:
                return set()  # a static host has no index for a document it has never seen
            raise
        if text.startswith("["):  # a relay that answers in JSON
            found = json.loads(text)
        else:
            found = [line.strip() for line in text.splitlines()]
        return {h for h in found if is_hash(h)}

    def get(self, h: str) -> bytes:
        with request.urlopen(f"{self.base}/blobs/{hex_of(h)}", timeout=10) as r:
            data = r.read(MAX_BLOB + 1)
        if len(data) > MAX_BLOB:
            raise ValueError(f"relay returned an oversized blob for {h}")
        if sha256(data) != h:
            raise ValueError(f"relay returned wrong content for {h}")
        return data

    def put(self, data: bytes) -> str:
        req = request.Request(f"{self.base}/blobs", data=data, method="POST",
                              headers={"Content-Type": "application/json"})
        try:
            with request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())["hash"]
        except error.HTTPError as e:
            if e.code in (403, 404, 405, 501):
                raise ValueError(
                    f"{self.base} is read-only (a static host?). "
                    "Push to a folder instead and publish that folder.")
            raise ValueError(e.read().decode() or str(e))


def open_relay(target: str):
    if target.startswith("http://") or target.startswith("https://"):
        return HttpRelay(target)
    return DirRelay(Path(target))


def push(store: Store, doc_id: str, relay) -> int:
    missing = store.doc_ops(doc_id) - relay.list(doc_id)
    for h in sorted(missing):
        relay.put(store.get(h))
    return len(missing)


def pull(store: Store, doc_id: str, relay) -> int:
    missing = relay.list(doc_id) - store.doc_ops(doc_id)
    for h in sorted(missing):
        data = relay.get(h)
        if sha256(data) != h:
            raise ValueError(f"relay returned wrong content for {h}")
        accept_blob(store, data)
    return len(missing)


# ---- HTTP relay server --------------------------------------------------

def make_handler(store: Store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # quiet
            pass

        def _send(self, code: int, body: bytes, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parts = self.path.strip("/").split("/")
            if len(parts) == 2 and parts[0] == "docs":
                p = store.docs / parts[1]  # the index file, verbatim, as a static host would
                if not is_hash(from_hex(parts[1])) or not p.exists():
                    return self._send(404, b'{"error":"not found"}')
                return self._send(200, p.read_bytes(), "text/plain")
            if len(parts) == 2 and parts[0] == "blobs":
                h = from_hex(parts[1])
                if not store.has(h):
                    return self._send(404, b'{"error":"not found"}')
                return self._send(200, store.get_raw(h))  # a relay need not verify; peers do
            if self.path == "/":
                return self._send(200, json.dumps({"loom-relay": True, "docs": store.doc_ids()}).encode())
            self._send(404, b'{"error":"no such route"}')

        def do_POST(self):
            if self.path.rstrip("/") != "/blobs":
                return self._send(404, b'{"error":"no such route"}')
            try:
                n = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._send(400, b'{"error":"Content-Length required"}')
            if n < 0:
                return self._send(400, b'{"error":"bad Content-Length"}')
            if n > MAX_BLOB:
                return self._send(413, b'{"error":"too large"}')
            data = self.rfile.read(n)
            try:
                h = accept_blob(store, data)
            except ValueError as e:
                return self._send(400, json.dumps({"error": str(e)}).encode())
            self._send(201, json.dumps({"hash": h}).encode())

    return Handler


def serve(path: Path, host: str = "127.0.0.1", port: int = 7700) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(Store(Path(path))))
    return server


def serve_in_thread(path: Path, host="127.0.0.1", port=0) -> tuple[ThreadingHTTPServer, str]:
    server = serve(path, host, port)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://{host}:{server.server_address[1]}"
