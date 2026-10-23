"""Command-line interface."""
import argparse
import json
import os
import sys
import shutil
import tempfile
from pathlib import Path
from urllib import request
from urllib.parse import urlparse
from urllib.request import url2pathname

from . import __version__
from .canon import hex_of
from .doc import Document, create_document, append
from .identity import Identity, identity_id
from .ops import set_action, del_action, grant_action, revoke_action, action_kind, ROLE_ADMIN, ROLE_WRITE, new_read_key, READ_KEY_BYTES
from .page import render_html, find_loom_links
from .store import Store
from .sync import open_relay, push, pull, pull_many, serve, DirRelay


def home() -> Path:
    return Path(os.environ.get("LOOM_HOME", Path.home() / ".loom"))


def short(h: str) -> str:
    return hex_of(h)[:12] if h.startswith("sha256:") else h[:15]


def parse_value(s: str):
    try:
        v = json.loads(s)
    except ValueError:
        return s
    if isinstance(v, float):
        return s  # floats are not allowed in signed structures; keep as text
    return v


def load_identity(args) -> Identity:
    try:
        ident = Identity.load(home(), args.key)
    except FileNotFoundError:
        sys.exit(f"no key named {args.key!r} in {home()}; run: loom keygen {args.key}")
    if ident.seckey is None:
        sys.exit(f"key {args.key!r} in {home()} is public only; sign from the home that holds its secret")
    return ident


RECOVERY = "recovery"


def readkey_path(doc_id: str) -> Path:
    return home() / "readkeys" / hex_of(doc_id)


def load_readkey(doc_id: str) -> bytes | None:
    p = readkey_path(doc_id)
    return bytes.fromhex(p.read_text().strip()) if p.exists() else None


def save_readkey(doc_id: str, key: bytes) -> Path:
    p = readkey_path(doc_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex() + "\n")
    return p


def load_doc(store: Store, doc_id: str) -> Document:
    return Document.load(store, doc_id, load_readkey(doc_id))


def recovery_key() -> Identity | None:
    """The public half of an admin key kept offline, if one is configured."""
    try:
        return Identity.load(home(), RECOVERY)
    except FileNotFoundError:
        return None


def cmd_keygen(args):
    ident = Identity.generate(args.name or args.key)
    p = ident.save(home())
    print(f"{ident.id}\nsaved {p}")


def cmd_id(args):
    ident = load_identity(args)
    if args.export:
        print(json.dumps({"id": ident.id, "pubkey": ident.pubkey.hex()}))
    else:
        print(ident.id)


def cmd_create(args):
    store, ident = Store(home() / "store"), load_identity(args)
    key = new_read_key() if args.sealed else None
    h = create_document(store, ident, args.title, open=args.open, key=key)
    print(h)
    if key:
        save_readkey(h, key)
        print(f"sealed: contents are encrypted; share the read key with: loom readkey {short(h)}", file=sys.stderr)
    rec = recovery_key()
    if rec and not args.no_recovery and not args.open:  # an open thread has no admins
        append(store, ident, h, grant_action(rec.pubkey, ROLE_ADMIN), key)
        print(f"granted admin to recovery key {short(rec.id)}", file=sys.stderr)


def cmd_readkey(args):
    """Show a sealed document's read key, or import one you were given out of band."""
    store = Store(home() / "store")
    doc_id = args.doc if (args.doc.startswith("sha256:") and len(args.doc) == 71) else store.resolve_doc(args.doc)
    if args.key:
        key = bytes.fromhex(args.key)
        if len(key) != READ_KEY_BYTES:
            sys.exit(f"a read key is {READ_KEY_BYTES} bytes ({READ_KEY_BYTES * 2} hex characters)")
        print(f"saved {save_readkey(doc_id, key)}")
        return
    key = load_readkey(doc_id)
    if key is None:
        sys.exit("no read key for this document here")
    print(key.hex())


def cmd_recovery(args):
    """Set or show the recovery key: an admin key whose secret lives somewhere else."""
    if args.pubkey:
        pk = bytes.fromhex(args.pubkey)
        ident = Identity(RECOVERY, pk)  # public half only; never a secret here
        p = ident.save(home())
        print(f"{ident.id}\nsaved {p}\nnew documents will grant it admin; for existing ones: loom grant <doc> {args.pubkey[:12]}... --admin")
        return
    rec = recovery_key()
    if not rec:
        sys.exit("no recovery key set. Generate one in a home you keep offline, then:\n"
                 "  LOOM_HOME=/path/to/offline loom keygen default\n"
                 "  loom recovery $(LOOM_HOME=/path/to/offline loom id --export | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"pubkey\"])')")
    print(rec.id)


def cmd_set(args):
    store, ident = Store(home() / "store"), load_identity(args)
    doc = store.resolve_doc(args.doc)
    h = append(store, ident, doc, set_action(args.key_name, parse_value(args.value)), load_readkey(doc))
    print(h)


def cmd_del(args):
    store, ident = Store(home() / "store"), load_identity(args)
    doc = store.resolve_doc(args.doc)
    print(append(store, ident, doc, del_action(args.key_name), load_readkey(doc)))


def cmd_grant(args):
    store, ident = Store(home() / "store"), load_identity(args)
    doc = store.resolve_doc(args.doc)
    pk = bytes.fromhex(args.pubkey)
    role = ROLE_ADMIN if args.admin else ROLE_WRITE
    h = append(store, ident, doc, grant_action(pk, role), load_readkey(doc))
    print(f"{h}\ngranted {role} to {identity_id(pk)}")


def cmd_revoke(args):
    store, ident = Store(home() / "store"), load_identity(args)
    doc = store.resolve_doc(args.doc)
    print(append(store, ident, doc, revoke_action(args.who), load_readkey(doc)))


def print_doc(doc: Document, as_json: bool = False):
    if as_json:
        print(json.dumps({"id": doc.id, "title": doc.title(), "state": doc.state(),
                          "provenance": doc.provenance(), "roles": doc.roles(),
                          "report": {"seen": doc.report.seen, "valid": doc.report.valid,
                                     "rejected": doc.report.rejected}}, indent=2))
        return
    flags = ("  (open thread)" if doc.open else "") + ("  (sealed)" if doc.sealed else "")
    print(f"document {short(doc.id)}  \"{doc.title()}\"{flags}")
    print(f"{'started' if doc.open else 'owner  '}  {short(doc.owner) if doc.owner else 'none (no valid genesis)'}")
    print()
    state, prov = doc.state(), doc.provenance()
    if doc.locked:
        print(f"  (sealed: {doc.report.sealed} op(s) verified, contents encrypted; no read key here)")
    elif not state:
        print("  (empty)")
    for k, v in state.items():
        p = prov[k]
        print(f"  {k} = {json.dumps(v)}    [by {short(p['author'])} at t={p['lamport']}]")
    print()
    print("roles" if not doc.open else "roles: none. Anyone may write, only under their own id.")
    for who, role in sorted(doc.roles().items()):
        print(f"  {short(who)}  {role}{'  (owner)' if who == doc.owner else ''}")
    print()
    r = doc.report
    print(f"ops seen {r.seen}, valid {r.valid}, rejected {len(r.rejected)}")
    for h, why in r.rejected:
        print(f"  rejected {short(h)}: {why}")


def cmd_say(args):
    """Post a message in an open thread: key <my id>/<seq>, value {text, re}."""
    store, ident = Store(home() / "store"), load_identity(args)
    doc_id = store.resolve_doc(args.doc)
    doc = load_doc(store, doc_id)
    if not doc.open:
        sys.exit("not an open thread; use `loom set` on a document you may write to")
    key = f"{ident.id}/{doc.next_seq(ident.id)}"
    value = {"text": args.text, "re": args.re}
    print(append(store, ident, doc_id, set_action(key, value), load_readkey(doc_id)))


def cmd_thread(args):
    """Messages of an open thread in causal order."""
    store = Store(home() / "store")
    doc = load_doc(store, store.resolve_doc(args.doc))
    print(f"thread {short(doc.id)}  \"{doc.title()}\"  {'open' if doc.open else 'owned'}")
    for h in doc.order:
        op = doc.valid[h]
        if action_kind(op["action"]) != "set":
            continue
        v = op["action"]["value"]
        if not (isinstance(v, dict) and isinstance(v.get("text"), str)):
            continue
        re = f"  (re {short(v['re'])})" if v.get("re") else ""
        print(f"t={op['lamport']:<3} {short(h)}  {short(op['author'])}: {v['text']}{re}")


def cmd_show(args):
    store = Store(home() / "store")
    print_doc(load_doc(store, store.resolve_doc(args.doc)), args.json)


def cmd_log(args):
    store = Store(home() / "store")
    doc = load_doc(store, store.resolve_doc(args.doc))
    for h in doc.order:
        op = doc.valid[h]
        kind = action_kind(op["action"])
        body = op["action"]
        if kind == "sealed":
            desc = "sealed (encrypted; no read key here)"
        elif kind == "set":
            desc = f"set {body['set']} = {json.dumps(body['value'])}"
        elif kind == "del":
            desc = f"del {body['del']}"
        elif kind == "grant":
            desc = f"grant {body['grant']['role']} to {short(body['grant']['to'])}"
        elif kind == "revoke":
            desc = f"revoke {short(body['revoke']['id'])}"
        else:
            desc = f"genesis \"{body['genesis'].get('title', '')}\""
        deps = ",".join(short(d) for d in op["deps"]) or "-"
        print(f"t={op['lamport']:<3} {short(h)}  {short(op['author'])}#{op['seq']:<2} {desc}   deps {deps}")


def cmd_docs(args):
    store = Store(home() / "store")
    for d in store.doc_ids():
        doc = load_doc(store, d)
        print(f"{short(d)}  \"{doc.title()}\"  ops {doc.report.valid}/{doc.report.seen}{'  sealed' if doc.sealed else ''}")


def cmd_push(args):
    store = Store(home() / "store")
    doc = store.resolve_doc(args.doc)
    n = push(store, doc, open_relay(args.relay))
    print(f"pushed {n} op(s)")


def cmd_pull(args):
    store = Store(home() / "store")
    doc = args.doc if args.doc.startswith("sha256:") and len(args.doc) == 71 else store.resolve_doc(args.doc)
    if len(args.relay) == 1:
        print(f"pulled {pull(store, doc, open_relay(args.relay[0]))} op(s)")
        return
    n, outcomes = pull_many(store, doc, [open_relay(r) for r in args.relay])
    print(f"pulled {n} op(s) from {len(args.relay)} source(s)")
    for name, outcome in outcomes:
        print(f"  {name}: {outcome}")


def cmd_publish(args):
    """Push a document into <site>/<relay-dir> and write an HTML page beside it."""
    store = Store(home() / "store")
    doc_id = store.resolve_doc(args.doc)
    site = Path(args.site)
    n = push(store, doc_id, DirRelay(site / args.relay_dir))
    for js in (Path(__file__).parent / "static").glob("*.js"):
        shutil.copy(js, site / args.relay_dir / js.name)  # the browser verifier, beside the ops
    doc = Document.load(store, doc_id)  # never with the read key: a published page holds no plaintext
    page = site / (args.page or f"{short(doc_id)}.html")
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(render_html(doc, args.relay_dir + "/", args.mirror or []))
    print(f"pushed {n} op(s) to {site / args.relay_dir}\nwrote {page}"
          + (f"\nmirrors: {', '.join(args.mirror)}" if args.mirror else ""))


def _relay_for(base: str):
    if base.startswith("file://"):
        return DirRelay(Path(url2pathname(urlparse(base).path)))
    return open_relay(base)


def resolve_verify_target(target: str, doc_arg: str | None):
    """Turn what the user pointed at into ([relays], doc id).

    Accepts: a page URL with <link rel="loom"> back-links (every link becomes a
    source), a relay URL plus a doc id, a local .html file, or a folder plus a doc id.
    """
    if target.startswith(("http://", "https://")):
        with request.urlopen(target, timeout=15) as r:
            body = r.read(16 * 1024 * 1024)
            ctype = r.headers.get("Content-Type", "")
        if "html" in ctype or body.lstrip().startswith(b"<"):
            bases, doc_id = find_loom_links(body.decode("utf-8", "replace"), target)
            return [_relay_for(b) for b in bases], doc_id
        if not doc_arg:
            raise ValueError(f"{target} is a relay, not a page; give the document id too")
        return [open_relay(target)], doc_arg
    path = Path(target)
    if path.is_file():
        bases, doc_id = find_loom_links(path.read_text(), path.resolve().as_uri())
        return [_relay_for(b) for b in bases], doc_id
    if not doc_arg:
        raise ValueError(f"{target} is a folder, not a page; give the document id too")
    return [DirRelay(path)], doc_arg


def cmd_verify(args):
    """Fetch a document into a scratch store and report on it. Touches nothing in LOOM_HOME."""
    relays, doc_id = resolve_verify_target(args.target, args.doc)
    if not (doc_id.startswith("sha256:") and len(doc_id) == 71):
        raise ValueError("verify needs a full document id")
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "store")
        n, outcomes = pull_many(store, doc_id, relays)
        doc = Document.load(store, doc_id, bytes.fromhex(args.readkey) if args.readkey else None)
        log = sys.stderr if args.json else sys.stdout  # keep --json output pure JSON
        print(f"fetched {n} op(s) from {len(relays)} source(s)", file=log)
        for name, outcome in outcomes:
            print(f"  {name}: {outcome}", file=log)
        print_doc(doc, args.json)
        if any(o.startswith("wrong content") for _, o in outcomes):
            sys.exit("a source returned content that does not match its hash; see above")
        if doc.owner is None:
            sys.exit("no valid genesis: this is not a verifiable document")


def cmd_serve(args):
    server = serve(Path(args.dir), args.host, args.port)
    print(f"loom relay on http://{args.host}:{server.server_address[1]}  storing in {args.dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv=None):
    p = argparse.ArgumentParser(prog="loom", description="a document that needs no server")
    p.add_argument("--version", action="version", version=f"loom {__version__}")
    p.add_argument("--key", default="default", help="which identity to use (default: default)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="create an identity"); s.add_argument("name", nargs="?", help="key name (default: default)"); s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("id", help="print your identity id"); s.add_argument("--export", action="store_true", help="also print the public key as hex"); s.set_defaults(fn=cmd_id)
    s = sub.add_parser("create", help="create a document (grants admin to the recovery key, if set)"); s.add_argument("title"); s.add_argument("--no-recovery", action="store_true", help="do not grant the recovery key"); s.add_argument("--open", action="store_true", help="an open thread: no owner, anyone writes under their own id"); s.add_argument("--sealed", action="store_true", help="encrypt contents; only holders of the read key can read or write"); s.set_defaults(fn=cmd_create)
    s = sub.add_parser("readkey", help="show a sealed document's read key, or import one (hex) you were given"); s.add_argument("doc"); s.add_argument("key", nargs="?"); s.set_defaults(fn=cmd_readkey)
    s = sub.add_parser("say", help="post a message in an open thread"); s.add_argument("doc"); s.add_argument("text"); s.add_argument("--re", help="op hash of the message you reply to"); s.set_defaults(fn=cmd_say)
    s = sub.add_parser("thread", help="print an open thread's messages in causal order"); s.add_argument("doc"); s.set_defaults(fn=cmd_thread)
    s = sub.add_parser("recovery", help="set (hex pubkey) or show the recovery key: an admin key whose secret you keep offline"); s.add_argument("pubkey", nargs="?"); s.set_defaults(fn=cmd_recovery)
    s = sub.add_parser("set", help="set a key"); s.add_argument("doc"); s.add_argument("key_name", metavar="key"); s.add_argument("value", help="JSON or plain text"); s.set_defaults(fn=cmd_set)
    s = sub.add_parser("del", help="delete a key"); s.add_argument("doc"); s.add_argument("key_name", metavar="key"); s.set_defaults(fn=cmd_del)
    s = sub.add_parser("grant", help="grant write (or admin) to a public key"); s.add_argument("doc"); s.add_argument("pubkey", help="hex public key from `loom id --export`"); s.add_argument("--admin", action="store_true"); s.set_defaults(fn=cmd_grant)
    s = sub.add_parser("revoke", help="revoke an identity"); s.add_argument("doc"); s.add_argument("who", help="identity id"); s.set_defaults(fn=cmd_revoke)
    s = sub.add_parser("show", help="show state, provenance, roles, and the verification report"); s.add_argument("doc"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_show)
    s = sub.add_parser("log", help="list valid ops in causal order"); s.add_argument("doc"); s.set_defaults(fn=cmd_log)
    s = sub.add_parser("docs", help="list documents in this store"); s.set_defaults(fn=cmd_docs)
    s = sub.add_parser("push", help="send ops to a relay: a folder (publish it anywhere as static files) or an http URL"); s.add_argument("doc"); s.add_argument("relay"); s.set_defaults(fn=cmd_push)
    s = sub.add_parser("pull", help="fetch ops from a relay: a folder, a `loom serve` URL, or any static host serving a pushed folder"); s.add_argument("doc", help="full id for a document you do not have yet"); s.add_argument("relay", nargs="+", help="one or more; the union is kept"); s.set_defaults(fn=cmd_pull)
    s = sub.add_parser("publish", help="push to <site>/loom and write an HTML page with a back-link to the ops"); s.add_argument("doc"); s.add_argument("site", help="folder to publish as static files"); s.add_argument("--page", help="page file name inside <site> (default: <doc prefix>.html)"); s.add_argument("--relay-dir", default="loom", help="relay folder name inside <site> (default: loom)"); s.add_argument("--mirror", action="append", metavar="URL", help="another relay base holding this document; repeatable"); s.set_defaults(fn=cmd_publish)
    s = sub.add_parser("verify", help="fetch a document from a page URL, .html file, relay URL or folder, and verify it"); s.add_argument("target"); s.add_argument("doc", nargs="?", help="full document id (needed when target is a relay, not a page)"); s.add_argument("--json", action="store_true"); s.add_argument("--readkey", help="hex read key for a sealed document"); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("serve", help="run an HTTP relay"); s.add_argument("dir"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=7700); s.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    try:
        args.fn(args)
    except KeyError as e:
        sys.exit(str(e.args[0]) if e.args else str(e))
    except ValueError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
