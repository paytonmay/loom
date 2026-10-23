"""Build, sign, and verify a single operation."""
from .canon import canonical, hash_obj, is_hash, CanonError
from .identity import Identity, identity_id, verify, b64e, b64d

VERSION = 1
ROLE_WRITE = "write"
ROLE_ADMIN = "admin"
ROLES = (ROLE_WRITE, ROLE_ADMIN)
ACTIONS = ("genesis", "set", "del", "grant", "revoke")


def signing_bytes(op: dict) -> bytes:
    return canonical({k: v for k, v in op.items() if k != "sig"})


def op_hash(op: dict) -> str:
    return hash_obj(op)


def build_op(identity: Identity, doc: str | None, seq: int, lamport: int,
             deps: list[str], action: dict) -> dict:
    op = {
        "v": VERSION,
        "type": "op",
        "doc": doc,
        "author": identity.id,
        "pubkey": b64e(identity.pubkey),
        "seq": seq,
        "lamport": lamport,
        "deps": sorted(set(deps)),
        "action": action,
    }
    op["sig"] = b64e(identity.sign(signing_bytes(op)))
    return op


def action_kind(action: dict) -> str:
    for k in ACTIONS:
        if k in action:
            return k
    raise ValueError("unknown action")


def verify_op(op) -> tuple[bool, str]:
    """Structural and cryptographic checks on one op, in isolation."""
    if not isinstance(op, dict):
        return False, "not an object"
    required = {"v", "type", "doc", "author", "pubkey", "seq", "lamport", "deps", "action", "sig"}
    if set(op) != required:
        return False, f"fields must be exactly {sorted(required)}"
    if op["v"] != VERSION or op["type"] != "op":
        return False, "bad version or type"
    if not (type(op["seq"]) is int and op["seq"] >= 1):  # bool is an int in Python; not here
        return False, "seq must be a positive integer"
    if not (type(op["lamport"]) is int and op["lamport"] >= 1):
        return False, "lamport must be a positive integer"
    deps = op["deps"]
    if not isinstance(deps, list) or deps != sorted(set(deps)) or not all(is_hash(d) for d in deps):
        return False, "deps must be a sorted list of unique hashes"
    action = op["action"]
    kinds = [k for k in ACTIONS if isinstance(action, dict) and k in action]
    if len(kinds) != 1:
        return False, "action must have exactly one known kind"
    kind = kinds[0]
    allowed = {kind} | ({"value"} if kind == "set" else set())
    if set(action) != allowed:
        return False, f"action keys must be exactly {sorted(allowed)}"
    is_genesis = kind == "genesis"
    if is_genesis != (op["doc"] is None):
        return False, "genesis iff doc is null"
    if is_genesis and (deps or op["lamport"] != 1 or op["seq"] != 1):
        return False, "genesis must have no deps, lamport 1, seq 1"
    if not is_genesis and (not deps or not is_hash(op["doc"])):
        return False, "non-genesis op must have deps and a doc id"
    ok, why = _check_action(kind, action[kind])
    if not ok:
        return False, why
    try:
        pk = b64d(op["pubkey"])
        sig = b64d(op["sig"])
    except Exception:
        return False, "pubkey or sig is not base64"
    if identity_id(pk) != op["author"]:
        return False, "author does not match pubkey"
    try:
        data = signing_bytes(op)
    except CanonError as e:
        return False, str(e)
    if not verify(pk, data, sig):
        return False, "signature invalid"
    return True, "ok"


def _check_action(kind: str, body) -> tuple[bool, str]:
    if kind == "genesis":
        if not (isinstance(body, dict) and isinstance(body.get("title", ""), str)
                and isinstance(body.get("open", False), bool)):
            return False, "genesis body must be an object with optional string title and bool open"
    elif kind == "set":
        if not isinstance(body, str):
            return False, "set key must be a string"
    elif kind == "del":
        if not isinstance(body, str):
            return False, "del key must be a string"
    elif kind == "grant":
        if not (isinstance(body, dict) and set(body) == {"to", "pubkey", "role"}
                and body["role"] in ROLES and isinstance(body["to"], str)):
            return False, "grant needs to, pubkey, role"
        try:
            if identity_id(b64d(body["pubkey"])) != body["to"]:
                return False, "grant.to does not match grant.pubkey"
        except Exception:
            return False, "grant.pubkey is not base64"
    elif kind == "revoke":
        if not (isinstance(body, dict) and set(body) == {"id"} and isinstance(body["id"], str)):
            return False, "revoke needs id"
    return True, "ok"


def set_action(key: str, value) -> dict:
    return {"set": key, "value": value}


def del_action(key: str) -> dict:
    return {"del": key}


def grant_action(pubkey: bytes, role: str) -> dict:
    return {"grant": {"to": identity_id(pubkey), "pubkey": b64e(pubkey), "role": role}}


def revoke_action(who: str) -> dict:
    return {"revoke": {"id": who}}


def genesis_action(title: str, open: bool = False) -> dict:
    body = {"title": title}
    if open:
        body["open"] = True
    return {"genesis": body}


def own_key(author: str, key: str) -> bool:
    """In an open thread, an author may write only under their own id."""
    return key == author or key.startswith(author + "/")
