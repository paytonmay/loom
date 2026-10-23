"""Render a document as an HTML page that links back to its signed ops.

Humans get a normal page. Peers and agents follow `<link rel="loom">` to the
op set and verify every byte themselves. The page is a view, never a source
of truth: it says so, and it carries the hash of the document it was made
from so a stale page is detectable.
"""
import html
import json
from html.parser import HTMLParser
from urllib.parse import urljoin

from .canon import hex_of, is_hash, from_hex
from .doc import Document


def loom_href(relay_prefix: str, doc_id: str) -> str:
    """The back-link target: the document's index file inside the relay."""
    return relay_prefix.rstrip("/") + "/docs/" + hex_of(doc_id)


def parse_loom_href(href: str) -> tuple[str, str]:
    """Split a back-link into (relay base, doc id). Raises ValueError."""
    base, sep, rest = href.rpartition("/docs/")
    if not sep or not is_hash(from_hex(rest)):
        raise ValueError(f"not a loom back-link: {href!r}")
    return base, from_hex(rest)


def short(s: str) -> str:
    return hex_of(s)[:12] if s.startswith("sha256:") else s[:15]


def render_html(doc: Document, relay_prefix: str = "loom/") -> str:
    """A self-contained page: state with provenance, roles, verification report."""
    e = html.escape
    href = loom_href(relay_prefix, doc.id)
    state, prov, roles = doc.state(), doc.provenance(), doc.roles()
    rows = "".join(
        f"<tr><th>{e(k)}</th><td><code>{e(json.dumps(v, ensure_ascii=False))}</code></td>"
        f"<td title='{e(prov[k]['author'])}'>{e(short(prov[k]['author']))}</td>"
        f"<td>{prov[k]['lamport']}</td>"
        f"<td title='{e(prov[k]['op'])}'><code>{e(short(prov[k]['op']))}</code></td></tr>"
        for k, v in state.items()) or "<tr><td colspan=5><em>empty</em></td></tr>"
    role_rows = "".join(
        f"<tr><td title='{e(who)}'>{e(short(who))}</td><td>{e(role)}"
        f"{' (owner)' if who == doc.owner else ''}</td></tr>"
        for who, role in sorted(roles.items()))
    r = doc.report
    rejected = "".join(f"<li><code>{e(short(h))}</code>: {e(why)}</li>" for h, why in r.rejected)
    machine = {"loom": 1, "id": doc.id, "title": doc.title(), "open": doc.open, "ops": href,
               "state": state, "provenance": prov, "roles": roles,
               "frontier": doc.frontier(),
               "report": {"seen": r.seen, "valid": r.valid, "rejected": r.rejected}}
    machine_json = json.dumps(machine, ensure_ascii=False, indent=1).replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(doc.title() or short(doc.id))}</title>
<link rel="loom" href="{e(href)}" type="text/plain">
<meta name="loom-document" content="{e(doc.id)}">
<style>
 body{{font:16px/1.5 system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;color:#222;background:#fff}}
 table{{border-collapse:collapse;width:100%;margin:1rem 0}} th,td{{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #ddd;vertical-align:top}}
 th{{font-weight:600}} code{{font-size:.9em}} small,footer{{color:#666}}
 #loom-verify{{padding:.6rem .8rem;border-radius:4px;margin-bottom:1rem;font-size:.95em;border:1px solid #bbb;background:#f4f4f4}}
 #loom-verify.loom-ok{{border-color:#2a7;background:#e8f8ef}} #loom-verify.loom-bad{{border-color:#c33;background:#fdecec}}
 @media (prefers-color-scheme:dark){{body{{color:#ddd;background:#111}} th,td{{border-color:#333}} small,footer{{color:#999}}
  #loom-verify{{background:#1c1c1c;border-color:#444}} #loom-verify.loom-ok{{background:#10281a}} #loom-verify.loom-bad{{background:#301414}}}}
</style>
</head>
<body>
<div id="loom-verify">This page carries its signed source; a browser with JavaScript verifies it here, or run <code>loom verify</code> on this URL.</div>
<h1>{e(doc.title() or "untitled")}</h1>
<p><small>document <code>{e(doc.id)}</code><br>owner <code>{e(doc.owner or "none")}</code></small></p>
<table>
<thead><tr><th>key</th><th>value</th><th>by</th><th>t</th><th>op</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<h2>Who may write</h2>
{"<p>This is an open thread. Nobody owns it; anyone may write, only under their own id. Nobody can silence you and nobody can speak as you.</p>" if doc.open else f"<table><tbody>{role_rows}</tbody></table>"}
<h2>Verification</h2>
<p>ops seen {r.seen}, valid {r.valid}, rejected {len(r.rejected)}</p>
{f"<ul>{rejected}</ul>" if rejected else ""}
<footer>
<p>This page is a rendering, not the document. The document is the set of signed
operations at <a href="{e(href)}">{e(href)}</a>. Anyone can fetch them and verify
every field, its author and its history with no trust in this host:
<code>loom verify &lt;this page's URL&gt;</code>.</p>
</footer>
<script type="application/loom+json" id="loom">
{machine_json}
</script>
<script type="module" src="{e(relay_prefix.rstrip("/"))}/verify.js"></script>
</body>
</html>
"""


class _LinkFinder(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag != "link":
            return
        a = dict(attrs)
        rels = (a.get("rel") or "").lower().split()
        if "loom" in rels and a.get("href"):
            self.hrefs.append(a["href"])


def find_loom_link(page: str, page_url: str) -> tuple[str, str]:
    """From a page's HTML, the (relay base, doc id) of its first loom back-link.

    `page_url` is where the page was fetched from; relative hrefs resolve against it.
    """
    f = _LinkFinder()
    f.feed(page)
    for href in f.hrefs:
        try:
            return parse_loom_href(urljoin(page_url, href))
        except ValueError:
            continue
    raise ValueError("page has no <link rel=\"loom\"> back-link")
