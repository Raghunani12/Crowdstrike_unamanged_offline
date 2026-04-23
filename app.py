#!/usr/bin/env python3

import socket
import threading
import webbrowser
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(__file__)

# ───────── DNS RESOLUTION ─────────

def resolve_hostname(hostname, timeout=3):
    hostname = hostname.strip()
    if not hostname or hostname == '—':
        return {'hostname': hostname, 'status': 'skipped', 'resolved_ip': '', 'reverse': '', 'error': 'Empty hostname'}

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    result = {'hostname': hostname, 'status': 'unresolved', 'resolved_ip': '', 'reverse': '', 'error': ''}

    try:
        infos = socket.getaddrinfo(hostname, None)
        if infos:
            ip = infos[0][4][0]
            result['resolved_ip'] = ip
            result['status'] = 'resolved'
            try:
                rev = socket.gethostbyaddr(ip)
                result['reverse'] = rev[0]
                print(f"Resolved {hostname} -> {ip} (reverse: {rev[0]})")
            except Exception:
                pass
    except socket.gaierror as e:
        result['error'] = str(e)
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
    finally:
        socket.setdefaulttimeout(old_timeout)

    return result


def resolve_batch(hostnames, timeout=3):
    results = [None] * len(hostnames)

    def worker(idx, hn):
        results[idx] = resolve_hostname(hn, timeout)

    threads = []
    for i, hn in enumerate(hostnames):
        t = threading.Thread(target=worker, args=(i, hn), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout + 1)

    for i, r in enumerate(results):
        if r is None:
            results[i] = {
                'hostname': hostnames[i],
                'status': 'timeout',
                'resolved_ip': '',
                'reverse': '',
                'error': 'Thread timeout'
            }

    return results


# ───────── HTTP SERVER ─────────

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.serve_file("templates/index.html", "text/html")
        elif parsed.path.startswith("/static/"):
            self.serve_file(parsed.path.lstrip("/"))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/resolve":
            length = int(self.headers.get('Content-Length'))
            body = self.rfile.read(length)
            data = json.loads(body)
            hostnames = data.get("hostnames", [])

            results = resolve_batch(hostnames)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"results": results}).encode())
        else:
            self.send_error(404)

    def serve_file(self, relative_path, content_type=None):
        try:
            full_path = os.path.join(BASE_DIR, relative_path)
            with open(full_path, "rb") as f:
                content = f.read()

            self.send_response(200)

            if full_path.endswith(".css"):
                self.send_header("Content-Type", "text/css")
            elif full_path.endswith(".js"):
                self.send_header("Content-Type", "application/javascript")
            elif full_path.endswith(".html"):
                self.send_header("Content-Type", "text/html")

            self.end_headers()
            self.wfile.write(content)
        except Exception:
            self.send_error(404)


if __name__ == "__main__":
    threading.Timer(1, lambda: webbrowser.open("http://localhost:5000")).start()
    server = HTTPServer(("localhost", 5000), Handler)
    print("Running at http://localhost:5000")
    server.serve_forever()