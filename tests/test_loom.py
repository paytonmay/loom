import json
import random

import pytest

from loom.canon import canonical, CanonError
from loom.doc import Document, create_document, append
from loom.identity import Identity, identity_id
from loom.ops import set_action, del_action, grant_action, revoke_action, verify_op, build_op
from loom.store import Store, IntegrityError
from loom.sync import DirRelay, HttpRelay, push, pull, serve_in_thread
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from functools import partial
import threading


@pytest.fixture(scope="session")
def keys():
    # keygen is slow in pure Python; share three identities across tests
    return {n: Identity.generate(n) for n in ("alice", "bob", "carol")}


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


# ---- phase 0: canon + store ----------------------------------------------

def test_canonical_is_deterministic_and_rejects_floats():
    a = canonical({"b": 1, "a": [1, {"z": "é"}]})
    b = canonical({"a": [1, {"z": "é"}], "b": 1})
    assert a == b == b'{"a":[1,{"z":"\xc3\xa9"}],"b":1}'
    with pytest.raises(CanonError):
        canonical({"x": 1.5})


def test_store_round_trip_and_tamper_detection(store):
    h = store.put(b"hello")
    assert store.get(h) == b"hello"
    assert store.put(b"hello") == h  # idempotent
    (store.blobs / h.split(":")[1]).write_bytes(b"hellp")
    with pytest.raises(IntegrityError):
        store.get(h)


# ---- phase 1: identity ---------------------------------------------------

def test_identity_sign_verify_and_persist(tmp_path, keys):
    a = keys["alice"]
    assert a.id == identity_id(a.pubkey) and a.id.startswith("id:")
    sig = a.sign(b"msg")
    from loom.identity import verify
    assert verify(a.pubkey, b"msg", sig)
    assert not verify(a.pubkey, b"msh", sig)
    a.save(tmp_path)
    b = Identity.load(tmp_path, "alice")
    assert b.id == a.id and b.seckey == a.seckey


# ---- phase 2: ops + document ---------------------------------------------

def test_op_structural_and_signature_checks(keys):
    a = keys["alice"]
    g = build_op(a, None, 1, 1, [], {"genesis": {"title": "t"}})
    assert verify_op(g) == (True, "ok")
    bad = dict(g); bad["action"] = {"genesis": {"title": "changed"}}
    assert verify_op(bad)[1] == "signature invalid"
    bad = dict(g); bad["author"] = keys["bob"].id
    assert verify_op(bad)[1] == "author does not match pubkey"


def test_document_lww_and_convergence_from_shuffled_order(store, keys):
    a = keys["alice"]
    d = create_document(store, a, "notes")
    append(store, a, d, set_action("title", "first"))
    append(store, a, d, set_action("title", "second"))
    append(store, a, d, set_action("count", 3))
    append(store, a, d, del_action("count"))
    doc = Document.load(store, d)
    assert doc.state() == {"title": "second"}
    assert doc.report.rejected == []
    # same ops, any order, same result
    ops = {h: json.loads(store.get(h)) for h in store.doc_ops(d)}
    for _ in range(5):
        items = list(ops.items()); random.shuffle(items)
        assert Document(d, dict(items)).state() == {"title": "second"}


def test_missing_dependency_is_rejected_not_crashed(store, keys):
    a = keys["alice"]
    d = create_document(store, a, "x")
    append(store, a, d, set_action("k", 1))  # the dropped dependency
    h2 = append(store, a, d, set_action("k", 2))
    ops = {h: json.loads(store.get(h)) for h in (d, h2)}  # drop h1
    doc = Document(d, ops)
    assert doc.state() == {}
    assert any("missing" in why for _, why in doc.report.rejected)


# ---- phase 3: capabilities -----------------------------------------------

def _copy_ops(src: Store, dst: Store, d: str):
    for h in src.doc_ops(d):
        dst.put(src.get(h)); dst.add_to_doc(d, h)


def test_unauthorized_write_is_rejected_then_grant_enables(tmp_path, keys):
    a, b = keys["alice"], keys["bob"]
    sa, sb = Store(tmp_path / "a"), Store(tmp_path / "b")
    d = create_document(sa, a, "shared")
    _copy_ops(sa, sb, d)
    # Bob writes without a grant: structurally valid, but unauthorized
    hb = append(sb, b, d, set_action("intruder", True))
    _copy_ops(sb, sa, d)
    doc = Document.load(sa, d)
    assert doc.state() == {}
    assert (hb, "unauthorized") in doc.report.rejected
    # Alice grants Bob write; Bob's later writes are valid
    append(sa, a, d, grant_action(b.pubkey, "write"))
    _copy_ops(sa, sb, d)
    append(sb, b, d, set_action("hello", "from bob"))
    _copy_ops(sb, sa, d)
    doc = Document.load(sa, d)
    assert doc.state() == {"hello": "from bob"}
    assert doc.roles()[b.id] == "write"
    # the pre-grant write stays rejected: authority is judged by causal past
    assert (hb, "unauthorized") in doc.report.rejected


def test_writer_cannot_grant_and_admin_can(tmp_path, keys):
    a, b, c = keys["alice"], keys["bob"], keys["carol"]
    s = Store(tmp_path / "s")
    d = create_document(s, a, "doc")
    append(s, a, d, grant_action(b.pubkey, "write"))
    bad = append(s, b, d, grant_action(c.pubkey, "write"))   # writer granting: rejected
    doc = Document.load(s, d)
    assert (bad, "unauthorized") in doc.report.rejected
    append(s, a, d, grant_action(b.pubkey, "admin"))
    ok = append(s, b, d, grant_action(c.pubkey, "write"))    # now admin: fine
    doc = Document.load(s, d)
    assert ok in doc.valid and doc.roles()[c.id] == "write"


def test_revocation_is_causal(tmp_path, keys):
    a, b = keys["alice"], keys["bob"]
    sa, sb = Store(tmp_path / "a"), Store(tmp_path / "b")
    d = create_document(sa, a, "doc")
    append(sa, a, d, grant_action(b.pubkey, "write"))
    _copy_ops(sa, sb, d)
    # Alice revokes; concurrently Bob (unaware) writes
    append(sa, a, d, revoke_action(b.id))
    concurrent = append(sb, b, d, set_action("race", "bob"))
    _copy_ops(sb, sa, d)
    doc = Document.load(sa, d)
    assert concurrent in doc.valid            # revoke not in its causal past
    assert b.id not in doc.roles()
    # After Bob sees the revoke, his writes are rejected
    _copy_ops(sa, sb, d)
    late = append(sb, b, d, set_action("race", "bob again"))
    _copy_ops(sb, sa, d)
    doc = Document.load(sa, d)
    assert (late, "unauthorized") in doc.report.rejected
    assert doc.state() == {"race": "bob"}


def test_owner_is_the_first_admin_not_an_immune_one(tmp_path, keys):
    """Admin is full trust. An admin may revoke the owner; that is what makes recovery possible."""
    a, b = keys["alice"], keys["bob"]
    s = Store(tmp_path / "s")
    d = create_document(s, a, "doc")
    append(s, a, d, grant_action(b.pubkey, "admin"))
    h = append(s, b, d, revoke_action(a.id))
    doc = Document.load(s, d)
    assert h in doc.valid and a.id not in doc.roles() and doc.roles() == {b.id: "admin"}
    assert doc.owner == a.id  # still the author of record for the genesis
    bad = append(s, a, d, set_action("x", 1))
    assert (bad, "unauthorized") in Document.load(s, d).report.rejected
    # a writer still cannot revoke anyone
    c = keys["carol"]
    append(s, b, d, grant_action(c.pubkey, "write"))
    h2 = append(s, c, d, revoke_action(b.id))
    assert (h2, "unauthorized") in Document.load(s, d).report.rejected


# ---- phase 4: sync -------------------------------------------------------

def test_two_peers_converge_through_directory_relay(tmp_path, keys):
    a, b = keys["alice"], keys["bob"]
    sa, sb = Store(tmp_path / "a"), Store(tmp_path / "b")
    relay = DirRelay(tmp_path / "relay")
    d = create_document(sa, a, "doc")
    append(sa, a, d, grant_action(b.pubkey, "write"))
    append(sa, a, d, set_action("from", "alice"))
    assert push(sa, d, relay) == 3
    assert pull(sb, d, relay) == 3
    append(sb, b, d, set_action("and", "bob"))
    push(sb, d, relay); pull(sa, d, relay)
    assert Document.load(sa, d).state() == Document.load(sb, d).state() == {"from": "alice", "and": "bob"}


def test_relay_refuses_garbage_and_tampering(tmp_path, keys):
    relay = DirRelay(tmp_path / "relay")
    with pytest.raises(ValueError):
        relay.put(b"not json")
    a = keys["alice"]
    g = build_op(a, None, 1, 1, [], {"genesis": {"title": "t"}})
    g["action"]["genesis"]["title"] = "tampered"
    with pytest.raises(ValueError, match="signature invalid"):
        relay.put(canonical(g))


def test_two_peers_converge_through_http_relay(tmp_path, keys):
    a, b = keys["alice"], keys["bob"]
    sa, sb = Store(tmp_path / "a"), Store(tmp_path / "b")
    server, url = serve_in_thread(tmp_path / "relay")
    try:
        relay = HttpRelay(url)
        d = create_document(sa, a, "doc")
        append(sa, a, d, grant_action(b.pubkey, "write"))
        push(sa, d, relay)
        pull(sb, d, relay)
        append(sb, b, d, set_action("via", "http"))
        push(sb, d, relay); pull(sa, d, relay)
        assert Document.load(sa, d).state() == {"via": "http"}
        with pytest.raises(ValueError):
            relay.put(b"{}")
    finally:
        server.shutdown()


def test_a_static_host_is_a_read_only_relay(tmp_path, keys):
    """Push to a folder, serve the folder with a dumb file server, pull through it."""
    a, b = keys["alice"], keys["bob"]
    sa, sb = Store(tmp_path / "a"), Store(tmp_path / "b")
    site = tmp_path / "site"
    d = create_document(sa, a, "published")
    append(sa, a, d, set_action("hello", "world"))
    assert push(sa, d, DirRelay(site / "loom")) == 2

    # python -m http.server, in process: no loom code runs on the host
    handler = partial(SimpleHTTPRequestHandler, directory=str(site))
    handler.log_message = lambda *_: None
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        relay = HttpRelay(f"http://127.0.0.1:{server.server_address[1]}/loom")
        assert pull(sb, d, relay) == 2
        assert Document.load(sb, d).state() == {"hello": "world"}
        assert pull(sb, d, relay) == 0  # nothing new
        assert relay.list("sha256:" + "0" * 64) == set()  # unknown doc: 404 becomes empty
        append(sb, b, d, set_action("x", 1))
        with pytest.raises(ValueError, match="read-only"):
            push(sb, d, relay)
    finally:
        server.shutdown()


# ---- adoption: publish a page, verify from its URL -----------------------

def test_publish_page_then_verify_from_url_and_file(tmp_path, keys, capsys):
    from loom.cli import main
    from loom.page import find_loom_link, loom_href, parse_loom_href
    a = keys["alice"]
    home = tmp_path / "home"
    a.save(home)
    sa = Store(home / "store")
    d = create_document(sa, a, "A page")
    append(sa, a, d, set_action("greeting", "hi <there>"))

    import os
    os.environ["LOOM_HOME"] = str(home)
    site = tmp_path / "site"
    main(["publish", d, str(site), "--page", "index.html"])
    page = (site / "index.html").read_text()
    assert "hi &lt;there&gt;" in page and '<link rel="loom" href="loom/docs/' in page
    assert (site / "loom" / "docs").exists()

    # the back-link round-trips, relative to wherever the page lives
    base, doc_id = find_loom_link(page, "https://example.com/notes/index.html")
    assert (base, doc_id) == ("https://example.com/notes/loom", d)
    assert parse_loom_href(loom_href("x/", d)) == ("x", d)

    # from the local file
    main(["verify", str(site / "index.html")])
    out = capsys.readouterr().out
    assert "fetched 2 op(s)" in out and "greeting" in out and "rejected 0" in out

    # from a dumb file server
    handler = partial(SimpleHTTPRequestHandler, directory=str(site))
    handler.log_message = lambda *_: None
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/index.html"
        main(["verify", url, "--json"])
        got = json.loads(capsys.readouterr().out.split("\n", 1)[1])
        assert got["state"] == {"greeting": "hi <there>"} and got["report"]["valid"] == 2

        # a tampered blob on the host is caught, not trusted, even though the page looks fine
        blob = next((site / "loom" / "blobs").iterdir())
        blob.write_bytes(b'{"forged":1}')
        with pytest.raises(SystemExit):
            main(["verify", url])
    finally:
        server.shutdown()


# ---- adoption: the lost-laptop scenario ----------------------------------

def test_recovery_key_survives_a_lost_laptop(tmp_path, keys, capsys, monkeypatch):
    from loom.cli import main
    daily, recovery, fresh = keys["alice"], keys["bob"], keys["carol"]
    laptop, usb, new_laptop = tmp_path / "laptop", tmp_path / "usb", tmp_path / "new"
    relay_dir = tmp_path / "relay"

    # the recovery secret lives on the usb stick; the laptop holds only its public half
    recovery.save(usb)
    daily.save(laptop)
    monkeypatch.setenv("LOOM_HOME", str(laptop))
    main(["recovery", recovery.pubkey.hex()])
    assert not json.loads((laptop / "keys" / "recovery.json").read_text()).get("seckey")
    with pytest.raises(SystemExit, match="public only"):
        main(["--key", "recovery", "create", "nope"])

    capsys.readouterr()
    main(["--key", "alice", "create", "my notes"])
    d = capsys.readouterr().out.strip().splitlines()[0]
    main(["--key", "alice", "set", d, "k", "v"])
    main(["push", d, str(relay_dir)])
    doc = Document.load(Store(laptop / "store"), d)
    assert doc.roles() == {daily.id: "admin", recovery.id: "admin"}

    # laptop is lost. On a new machine: fresh daily key, pull the doc, recover with the usb key.
    sn = Store(new_laptop / "store")
    relay = DirRelay(relay_dir)
    pull(sn, d, relay)
    append(sn, recovery, d, grant_action(fresh.pubkey, "admin"))
    append(sn, recovery, d, revoke_action(daily.id))
    append(sn, fresh, d, set_action("k", "v2"))
    push(sn, d, relay)

    # the old laptop, in a thief's hands, syncs and then writes: rejected everywhere
    sl = Store(laptop / "store")
    pull(sl, d, relay)
    append(sl, daily, d, set_action("k", "stolen"))
    push(sl, d, relay)
    for st in (sl, sn):
        pull(st, d, relay)
        got = Document.load(st, d)
        assert got.state() == {"k": "v2"}
        assert daily.id not in got.roles() and fresh.id in got.roles()
        assert any(why == "unauthorized" for _, why in got.report.rejected)


# ---- second implementation: the JavaScript verifier agrees with Python ----

@pytest.mark.skipif(not __import__("shutil").which("node"), reason="node not installed")
def test_javascript_verifier_agrees_with_python(tmp_path, keys, capsys, monkeypatch):
    import subprocess
    from loom.cli import main
    a, b, c = keys["alice"], keys["bob"], keys["carol"]
    home = tmp_path / "home"; a.save(home)
    sa = Store(home / "store")
    d = create_document(sa, a, "interop ✓")
    append(sa, a, d, set_action("unicode", {"é": ["ü", 1, None, True]}))
    append(sa, a, d, grant_action(b.pubkey, "write"))
    append(sa, b, d, set_action("n", -7))
    append(sa, c, d, set_action("x", "intruder"))      # unauthorized: both must reject it
    append(sa, a, d, revoke_action(b.id))
    append(sa, b, d, set_action("n", 8))               # after the revoke: both must reject it
    append(sa, a, d, del_action("unicode"))
    monkeypatch.setenv("LOOM_HOME", str(home))
    site = tmp_path / "site"
    main(["publish", d, str(site)]); capsys.readouterr()

    def js():
        r = subprocess.run(["node", str(site / "loom" / "verify.js"), str(site / "loom"), d],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)

    py = Document.load(sa, d)
    got = js()
    assert got["state"] == py.state() == {"n": -7}
    assert got["provenance"] == py.provenance()
    assert got["roles"] == py.roles() == {a.id: "admin"}
    assert got["report"]["seen"] == py.report.seen == 8
    assert sorted(map(tuple, got["report"]["rejected"])) == sorted(py.report.rejected)
    assert len(py.report.rejected) == 2

    # tamper with a blob on the "host": both implementations reject exactly that op
    blob = sorted((site / "loom" / "blobs").iterdir())[0]
    blob.write_bytes(blob.read_bytes().replace(b'"v":1', b'"v":1 '))
    got = js()
    py2 = Document.load(Store(site / "loom"), d)
    assert sorted(map(tuple, got["report"]["rejected"])) == sorted(py2.report.rejected)
    assert any("hash" in why for _, why in py2.report.rejected)


# ---- open threads: nobody owns the thread, everybody owns their own words --

def test_open_thread_authority_is_own_keys_only(tmp_path, keys):
    a, b, c = keys["alice"], keys["bob"], keys["carol"]
    s = Store(tmp_path / "s")
    d = create_document(s, a, "square", open=True)
    h1 = append(s, b, d, set_action(f"{b.id}/1", {"text": "hello", "re": None}))   # no grant needed
    h2 = append(s, c, d, set_action(f"{c.id}/1", {"text": "hi bob", "re": h1}))
    forged = append(s, c, d, set_action(f"{b.id}/2", {"text": "bob says carol is great", "re": None}))
    bare = append(s, a, d, set_action("title", "mine now"))                           # not under a's id
    g = append(s, a, d, grant_action(b.pubkey, "admin"))                                # no admins exist
    r = append(s, a, d, revoke_action(b.id))
    own = append(s, a, d, set_action(a.id, {"text": "the bare id is also yours", "re": None}))
    doc = Document.load(s, d)
    assert doc.open and doc.roles() == {}
    assert {h1, h2, own} <= set(doc.valid)
    for h in (forged, bare, g, r):
        assert (h, "unauthorized") in doc.report.rejected
    assert doc.state()[f"{c.id}/1"]["re"] == h1
    # an author can edit and delete their own words, nobody else can
    append(s, b, d, set_action(f"{b.id}/1", {"text": "hello (edited)", "re": None}))
    bad = append(s, c, d, del_action(f"{b.id}/1"))
    doc = Document.load(s, d)
    assert doc.state()[f"{b.id}/1"]["text"] == "hello (edited)"
    assert (bad, "unauthorized") in doc.report.rejected


def test_say_and_thread_cli(tmp_path, keys, capsys, monkeypatch):
    from loom.cli import main
    a, b = keys["alice"], keys["bob"]
    home = tmp_path / "home"; a.save(home); b.save(home)
    monkeypatch.setenv("LOOM_HOME", str(home))
    main(["--key", "alice", "create", "chat", "--open"])
    d = capsys.readouterr().out.strip().splitlines()[0]
    main(["--key", "alice", "say", d, "anyone there?"])
    first = capsys.readouterr().out.strip()
    main(["--key", "bob", "say", d, "yes, and I never asked permission", "--re", first])
    capsys.readouterr()
    main(["thread", d])
    out = capsys.readouterr().out
    assert "open" in out.splitlines()[0]
    assert "anyone there?" in out and "never asked permission" in out and f"(re {first[7:19]})" in out
    main(["--key", "alice", "create", "owned"])
    owned = capsys.readouterr().out.strip().splitlines()[0]
    with pytest.raises(SystemExit, match="not an open thread"):
        main(["--key", "bob", "say", owned, "nope"])


@pytest.mark.skipif(not __import__("shutil").which("node"), reason="node not installed")
def test_javascript_verifier_agrees_on_open_threads(tmp_path, keys, capsys, monkeypatch):
    import subprocess
    from loom.cli import main
    a, b, c = keys["alice"], keys["bob"], keys["carol"]
    home = tmp_path / "home"; a.save(home)
    sa = Store(home / "store")
    d = create_document(sa, a, "square", open=True)
    h1 = append(sa, b, d, set_action(f"{b.id}/1", {"text": "hello", "re": None}))
    append(sa, c, d, set_action(f"{b.id}/2", {"text": "forged", "re": None}))
    append(sa, a, d, grant_action(b.pubkey, "admin"))
    append(sa, c, d, set_action(f"{c.id}/1", {"text": "hi", "re": h1}))
    monkeypatch.setenv("LOOM_HOME", str(home))
    site = tmp_path / "site"
    main(["publish", d, str(site)]); capsys.readouterr()
    r = subprocess.run(["node", str(site / "loom" / "verify.js"), str(site / "loom"), d], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    py = Document.load(sa, d)
    assert got["open"] is True and got["roles"] == {} == py.roles()
    assert got["state"] == py.state() and set(got["state"]) == {f"{b.id}/1", f"{c.id}/1"}
    assert sorted(map(tuple, got["report"]["rejected"])) == sorted(py.report.rejected) and len(py.report.rejected) == 2


# ---- hostile input never crashes a reader or a relay ---------------------

def test_hostile_blobs_are_rejected_not_crashes(tmp_path, keys):
    from loom.sync import accept_blob
    from urllib import request, error
    a = keys["alice"]
    s = Store(tmp_path / "s")
    d = create_document(s, a, "t")
    bad = [b'{"v":1.5}', b'[' * 5000 + b']' * 5000, b'[]', b'1', b'"x"', b'null',
           b'{"v":1,"type":"op","doc":null,"author":"","pubkey":"","seq":1,"lamport":1,"deps":[],"action":{"genesis":{"title":' + b'[' * 200 + b']' * 200 + b'}},"sig":""}']
    hs = []
    for raw in bad:
        h = s.put(raw); s.add_to_doc(d, h); hs.append(h)
    doc = Document.load(s, d)
    assert doc.report.valid == 1 and set(hs) == {h for h, _ in doc.report.rejected}
    for raw in bad:
        with pytest.raises(ValueError):
            accept_blob(Store(tmp_path / "r"), raw)
    # a signed op with a boolean lamport is rejected (JavaScript rejects it too)
    op = build_op(a, d, 2, 2, [d], set_action("k", 1))
    op["lamport"] = True
    op["sig"] = __import__("loom.identity", fromlist=["b64e"]).b64e(a.sign(__import__("loom.ops", fromlist=["signing_bytes"]).signing_bytes(op)))
    assert verify_op(op) == (False, "lamport must be a positive integer")

    # the relay survives bad requests and never hands out files outside its store
    server, url = serve_in_thread(tmp_path / "relay")
    try:
        def code(method, path, data=None, headers=None):
            req = request.Request(url + path, data=data, method=method, headers=headers or {})
            try:
                with request.urlopen(req, timeout=5) as r:
                    return r.status
            except error.HTTPError as e:
                return e.code
        assert code("GET", "/docs/..") == 404 and code("GET", "/blobs/%2e%2e%2fkeys") == 404
        assert code("POST", "/blobs", b"{}", {"Content-Length": "abc"}) == 400
        assert code("POST", "/blobs", b"{}", {"Content-Length": "-5"}) == 400
        assert code("POST", "/blobs", b"[" * 5000 + b"]" * 5000) == 400
        assert code("GET", "/") == 200
        # an oversized blob from a relay is refused by the client
        (tmp_path / "relay" / "blobs").mkdir(exist_ok=True)
        big = b"x" * 1_000_001
        (tmp_path / "relay" / "blobs" / ("0" * 64)).write_bytes(big)
        with pytest.raises(ValueError, match="oversized"):
            HttpRelay(url).get("sha256:" + "0" * 64)
    finally:
        server.shutdown()
