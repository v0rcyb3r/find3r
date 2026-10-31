"""Minimal local read-only web dashboard for the Intelligence Console.

Serves a single-page view of the evidence store and the reports directory on
127.0.0.1 only (local mode: no ports beyond loopback).

Interim surface. It is scheduled for replacement by the React app and carries
two known limitations until then: no authentication (loopback only is the
whole of its access control), and Mermaid is loaded from a CDN, which is an
external request from a tool that is otherwise air-gappable. Do not expose
this beyond loopback. AUDIT.md B4.
"""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from neesha.evidence.store import EvidenceStore

_STYLE = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; color: #1a1a1a; background: #f6f7f9; }
header { background: #111827; color: #fff; padding: 18px 28px; }
header h1 { margin: 0; font-size: 20px; }
header a { color: #93c5fd; text-decoration: none; }
main { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 18px 20px; margin: 16px 0; }
h2 { font-size: 16px; margin: 0 0 10px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
th { color: #6b7280; font-weight: 600; }
.grade { font-weight: 700; font-size: 26px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; }
.green { background: #dcfce7; color: #166534; }
.yellow { background: #fef9c3; color: #854d0e; }
.red { background: #fee2e2; color: #991b1b; }
.gray { background: #f3f4f6; color: #374151; }
.muted { color: #6b7280; }
ul { margin: 6px 0; padding-left: 20px; }
"""


def _read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _escape(value) -> str:
    return html.escape(str(value))


def _page(title: str, body: str, back: bool = True) -> str:
    back_link = f'<header><h1>Neesha Console <a href="/" style="font-size:13px;">← targets</a></h1></header>' if back else \
        '<header><h1>Neesha — Intelligence Console</h1></header>'
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{_escape(title)}</title><style>{_STYLE}</style>"
        "<script src='https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js'></script>"
        "</head><body>" + back_link + f"<main>{body}</main>"
        "<script>mermaid.initialize({startOnLoad:true, theme:'neutral'});</script></body></html>"
    )


def _home(data_dir: Path) -> str:
    with EvidenceStore(data_dir / "evidence.sqlite3") as store:
        targets = store.list_targets()
    if not targets:
        body = "<div class='card'><h2>No data yet</h2><p class='muted'>Run <code>neesha run &lt;domain&gt;</code> to collect a target, then reload.</p></div>"
        return _page("Neesha", body, back=False)
    rows = "".join(
        f"<li><a href='/target/{_escape(t)}'>{_escape(t)}</a></li>" for t in targets
    )
    body = f"<div class='card'><h2>Targets</h2><ul>{rows}</ul></div>"
    return _page("Neesha", body, back=False)


def known_targets(data_dir: Path) -> list[str]:
    with EvidenceStore(data_dir / "evidence.sqlite3") as store:
        return store.list_targets()


def _target_page(data_dir: Path, reports_dir: Path, target: str) -> str:
    cards = []

    posture = _read_json(reports_dir / target / "posture.json")
    if posture:
        overall = posture.get("overall", {})
        cats = posture.get("categories", {})
        cat_rows = "".join(
            f"<tr><td>{_escape(k)}</td><td><b>{_escape(v.get('letter','?'))}</b></td><td>{_escape(v.get('score',''))}</td></tr>"
            for k, v in cats.items()
        )
        flags = "".join(f"<span class='badge gray'>{_escape(f)}</span> " for f in posture.get("flags", []))
        cards.append(
            f"<div class='card'><h2>Posture</h2>"
            f"<span class='grade'>{_escape(overall.get('letter','?'))}</span> "
            f"<span class='muted'>({_escape(overall.get('score',''))}/100)</span><br>{flags}"
            f"<table><tr><th>Category</th><th>Grade</th><th>Score</th></tr>{cat_rows}</table></div>"
        )

    with EvidenceStore(data_dir / "evidence.sqlite3") as store:
        evidence = store.list_by_target(target)
    if evidence:
        rows = "".join(
            f"<tr><td class='muted'>{_escape(e.evidence_id[:8])}</td>"
            f"<td><b>{_escape(e.admiralty_source_grade.value + e.admiralty_claim_grade.value)}</b></td>"
            f"<td>{_escape(e.confidence.value)}</td>"
            f"<td>{_escape(e.collection_mode.value)}</td>"
            f"<td>{_escape(e.source_type)}</td>"
            f"<td>{_escape(e.claim)}</td></tr>"
            for e in evidence
        )
        cards.append(
            f"<div class='card'><h2>Evidence ({len(evidence)})</h2>"
            f"<table><tr><th>id</th><th>grade</th><th>conf</th><th>mode</th><th>source</th><th>claim</th></tr>{rows}</table></div>"
        )

    entities = _read_json(reports_dir / target / "entities.json")
    relationships = _read_json(reports_dir / target / "relationships.json")
    graph = None
    graph_path = reports_dir / target / "graph.mmd"
    if graph_path.exists():
        graph = graph_path.read_text()

    if entities:
        ent_rows = "".join(
            f"<tr><td>{_escape(e.get('type',''))}</td><td><b>{_escape(e.get('canonical_name',''))}</b></td>"
            f"<td>{_escape(e.get('confidence',''))}</td></tr>" for e in entities
        )
        rel_rows = "".join(
            f"<li>{_escape(r.get('relationship_type',''))} (evidence: {len(r.get('evidence_ids', []))})</li>"
            for r in (relationships or [])
        )
        graph_html = f"<pre class='mermaid'>{_escape(graph)}</pre>" if graph else ""

        cards.append(
            f"<div class='card'><h2>Entities ({len(entities)})</h2>"
            f"<table><tr><th>type</th><th>name</th><th>conf</th></tr>{ent_rows}</table>"
            f"<h2>Relationships ({len(relationships or [])})</h2><ul>{rel_rows}</ul>{graph_html}</div>"
        )

    guardrail = _read_json(reports_dir / target / "guardrail.json")
    if guardrail:
        cards.append(
            f"<div class='card'><h2>Guardrail</h2>"
            f"<span class='badge green'>{_escape(guardrail.get('kept'))} kept</span> "
            f"<span class='badge yellow'>{_escape(guardrail.get('downgraded'))} downgraded</span> "
            f"<span class='badge red'>{_escape(guardrail.get('dropped'))} dropped</span></div>"
        )

    return _page(target, "".join(cards))


def make_handler(data_dir: Path, reports_dir: Path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = unquote(urlparse(self.path).path)
            if path in ("/", "/index.html"):
                self._send(_home(data_dir))
            elif path.startswith("/target/"):
                requested = path[len("/target/"):]
                # Allowlist, not sanitization: the only readable targets are
                # ones the evidence store actually knows about, so a crafted
                # path cannot escape the reports directory. AUDIT.md B2.
                if requested not in known_targets(data_dir):
                    self.send_error(404)
                    return
                self._send(_target_page(data_dir, reports_dir, requested))
            else:
                self.send_error(404)

        def _send(self, body: str):
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):  # silence request logs
            pass

    return Handler


def serve(data_dir: str | Path, reports_dir: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    server = HTTPServer((host, port), make_handler(Path(data_dir), Path(reports_dir)))
    print(f"Neesha console: http://{host}:{port}  (Ctrl-C to stop)")
    server.serve_forever()
