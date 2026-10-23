"""A document: a DAG of signed ops, a capability table, and an LWW-map state.

Verification is deterministic on the op set alone. Every peer holding the same
ops computes the same valid set, the same rejections, and the same state.
"""
import json
from dataclasses import dataclass, field

from .canon import canonical
from .ops import own_key, verify_op, op_hash, action_kind, ROLE_ADMIN, ROLE_WRITE, build_op, seal_action, unseal_action
from .store import Store, IntegrityError


@dataclass
class Report:
    seen: int = 0
    valid: int = 0
    sealed: int = 0      # valid ops whose content we could not read (no key)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    def reject(self, h: str, why: str) -> None:
        self.rejected.append((h, why))


class Document:
    def __init__(self, doc_id: str, ops: dict[str, dict], key: bytes | None = None):
        self.id = doc_id
        self.key = key                 # read key for a sealed document, if we hold it
        self.ops = ops                 # hash -> op, everything we were handed
        self.valid: dict[str, dict] = {}
        self.order: list[str] = []     # topological order of valid ops
        self.report = Report(seen=len(ops))
        self.owner: str | None = None
        self.open = False              # open thread: no capability table, own keys only
        self.sealed = False            # read capability: actions are encrypted
        self._ancestors: dict[str, frozenset] = {}
        self._authorized: dict[str, bool] = {}
        self._verify()

    # ---- loading -----------------------------------------------------

    @classmethod
    def load(cls, store: Store, doc_id: str, key: bytes | None = None) -> "Document":
        ops = {}
        for h in store.doc_ops(doc_id):
            try:
                ops[h] = json.loads(store.get(h))
            except (IntegrityError, OSError, ValueError, RecursionError):
                ops[h] = None  # recorded as seen, rejected below
        return cls(doc_id, ops, key)

    @property
    def locked(self) -> bool:
        """Sealed and we hold no key: envelopes verify, contents do not apply."""
        return self.sealed and self.key is None

    # ---- verification -------------------------------------------------

    def _verify(self) -> None:
        rep = self.report
        structural: dict[str, dict] = {}
        for h, op in self.ops.items():
            if op is None:
                rep.reject(h, "unreadable or hash mismatch")
                continue
            try:
                matches = op_hash(op) == h
            except ValueError:   # floats, nesting, non-string keys
                matches = False
            if not matches:
                rep.reject(h, "hash does not match content")
                continue
            ok, why = verify_op(op)
            if not ok:
                rep.reject(h, why)
                continue
            is_genesis = action_kind(op["action"]) == "genesis"
            if is_genesis and h != self.id:
                rep.reject(h, "foreign genesis")
                continue
            if not is_genesis and op["doc"] != self.id:
                rep.reject(h, "belongs to another document")
                continue
            structural[h] = op

        if self.id not in structural:
            rep.reject(self.id, "genesis missing")
            return
        self.owner = structural[self.id]["author"]
        genesis = structural[self.id]["action"]["genesis"]
        self.open = bool(genesis.get("open", False))
        self.sealed = bool(genesis.get("sealed", False))

        # Read capability: in a sealed document every action must be sealed, and
        # is replaced by its decrypted inner action when we hold the key.
        for h, op in list(structural.items()):
            if h == self.id:
                continue
            kind = action_kind(op["action"])
            if self.sealed and kind != "sealed":
                rep.reject(h, "unsealed action in a sealed document"); del structural[h]
            elif not self.sealed and kind == "sealed":
                rep.reject(h, "sealed action in an unsealed document"); del structural[h]
            elif kind == "sealed" and self.key is not None:
                try:
                    inner = unseal_action(self.key, op["doc"], op["author"], op["seq"], op["action"]["sealed"])
                except ValueError as e:
                    rep.reject(h, str(e)); del structural[h]
                    continue
                structural[h] = {**op, "action": inner}

        # Causal closure: keep ops whose deps are all present and whose lamport
        # exceeds every dep's. Sorting by (lamport, hash) is then a topo order.
        kept: dict[str, dict] = {}
        for h, op in sorted(structural.items(), key=lambda kv: (kv[1]["lamport"], kv[0])):
            if h == self.id:
                kept[h] = op
                continue
            missing = [d for d in op["deps"] if d not in kept]
            if missing:
                rep.reject(h, f"missing or invalid dependency {missing[0]}")
                continue
            if any(kept[d]["lamport"] >= op["lamport"] for d in op["deps"]):
                rep.reject(h, "lamport not greater than dependencies")
                continue
            kept[h] = op
        self._kept = kept
        order = sorted(kept, key=lambda h: (kept[h]["lamport"], h))

        # Authority, judged against each op's own causal past.
        for h in order:
            if self._authorized_at(h):
                self.valid[h] = kept[h]
                self.order.append(h)
            else:
                rep.reject(h, "unauthorized")
        rep.valid = len(self.valid)

    def _ancestors_of(self, h: str) -> frozenset:
        if h in self._ancestors:
            return self._ancestors[h]
        acc = set()
        for d in self._kept[h]["deps"]:
            acc.add(d)
            acc |= self._ancestors_of(d)
        fs = frozenset(acc)
        self._ancestors[h] = fs
        return fs

    def _roles_at(self, h: str) -> dict[str, str]:
        """Capability table built from the valid grants/revokes in h's causal past."""
        roles = {self.owner: ROLE_ADMIN}
        past = sorted(self._ancestors_of(h), key=lambda a: (self._kept[a]["lamport"], a))
        for a in past:
            op = self._kept[a]
            kind = action_kind(op["action"])
            if kind not in ("grant", "revoke") or not self._authorized_at(a):
                continue
            body = op["action"][kind]
            if kind == "grant":
                roles[body["to"]] = body["role"]
            else:
                roles.pop(body["id"], None)
        return roles

    def _authorized_at(self, h: str) -> bool:
        if h in self._authorized:
            return self._authorized[h]
        op = self._kept[h]
        kind = action_kind(op["action"])
        if kind == "genesis":
            ok = h == self.id
        elif kind == "sealed":
            ok = True  # no key: the envelope is valid, the content is unknown
            self.report.sealed += 1
        elif self.open:
            # Nobody owns the thread; everybody owns their own words.
            ok = kind in ("set", "del") and own_key(op["author"], op["action"][kind])
        else:
            role = self._roles_at(h).get(op["author"])
            if kind in ("set", "del"):
                ok = role in (ROLE_WRITE, ROLE_ADMIN)
            else:  # grant / revoke
                ok = role == ROLE_ADMIN
        self._authorized[h] = ok
        return ok

    # ---- derived views -----------------------------------------------

    def state(self) -> dict:
        """Last-writer-wins map over valid set/del ops."""
        winners: dict[str, tuple] = {}
        for h in self.order:
            op = self.valid[h]
            kind = action_kind(op["action"])
            if kind not in ("set", "del"):
                continue
            key = op["action"][kind]
            rank = (op["lamport"], op["author"], h)
            if key not in winners or rank > winners[key][0]:
                winners[key] = (rank, op)
        out = {}
        for key, (_, op) in sorted(winners.items()):
            if "set" in op["action"]:
                out[key] = op["action"]["value"]
        return out

    def provenance(self) -> dict[str, dict]:
        """For each present key: who wrote it and in which op."""
        winners: dict[str, tuple] = {}
        for h in self.order:
            op = self.valid[h]
            kind = action_kind(op["action"])
            if kind not in ("set", "del"):
                continue
            key = op["action"][kind]
            rank = (op["lamport"], op["author"], h)
            if key not in winners or rank > winners[key][0]:
                winners[key] = (rank, op, h)
        return {k: {"author": op["author"], "op": h, "lamport": op["lamport"]}
                for k, (_, op, h) in winners.items() if "set" in op["action"]}

    def roles(self) -> dict[str, str]:
        """Capability table as of the full valid history. Empty for an open thread."""
        if self.open:
            return {}
        roles = {self.owner: ROLE_ADMIN}
        for h in self.order:
            op = self.valid[h]
            kind = action_kind(op["action"])
            if kind == "grant":
                roles[op["action"]["grant"]["to"]] = op["action"]["grant"]["role"]
            elif kind == "revoke":
                roles.pop(op["action"]["revoke"]["id"], None)
        return roles

    def frontier(self) -> list[str]:
        """Valid ops that no valid op depends on."""
        depended = {d for h in self.order for d in self.valid[h]["deps"]}
        return sorted(h for h in self.order if h not in depended)

    def next_lamport(self) -> int:
        return 1 + max((self.valid[h]["lamport"] for h in self.order), default=0)

    def next_seq(self, author: str) -> int:
        return 1 + max((op["seq"] for op in self.valid.values() if op["author"] == author), default=0)

    def title(self) -> str:
        g = self.valid.get(self.id)
        if not g:
            return ""
        return g["action"]["genesis"].get("title", "") or self.state().get("_title", "")


# ---- authoring helpers ------------------------------------------------

def create_document(store: Store, identity, title: str, open: bool = False,
                    key: bytes | None = None) -> str:
    """A key makes the document sealed: the title then travels encrypted too."""
    from .ops import genesis_action, set_action
    op = build_op(identity, None, 1, 1, [], genesis_action("" if key else title, open, sealed=key is not None))
    h = store.put(canonical(op))
    store.add_to_doc(h, h)
    if key:
        append(store, identity, h, set_action("_title", title), key)
    return h


def append(store: Store, identity, doc_id: str, action: dict, key: bytes | None = None) -> str:
    """Build an op on the current frontier, sign it, store it. Returns its hash."""
    doc = Document.load(store, doc_id, key)
    if doc.owner is None:
        raise ValueError("document has no valid genesis")
    seq = doc.next_seq(identity.id)
    if doc.sealed:
        if key is None:
            raise ValueError("document is sealed; read key required to write")
        action = seal_action(key, doc_id, identity.id, seq, action)
    op = build_op(identity, doc_id, seq, doc.next_lamport(), doc.frontier(), action)
    h = store.put(canonical(op))
    store.add_to_doc(doc_id, h)
    return h
