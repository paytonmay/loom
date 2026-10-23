"""Canonical encoding and hashing.

Every signed or hashed structure is JSON with sorted keys, no whitespace,
UTF-8, integers only. Hashes are rendered as "sha256:<hex>".
"""
import hashlib
import json

PREFIX = "sha256:"


class CanonError(ValueError):
    pass


MAX_DEPTH = 64


def _check(obj, path="$", depth=0):
    if depth > MAX_DEPTH:
        raise CanonError(f"nesting deeper than {MAX_DEPTH} at {path}")
    if isinstance(obj, float):
        raise CanonError(f"float not allowed in signed structure at {path}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonError(f"non-string key at {path}")
            _check(v, f"{path}.{k}", depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check(v, f"{path}[{i}]", depth + 1)


def canonical(obj) -> bytes:
    _check(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return PREFIX + hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    return sha256(canonical(obj))


def is_hash(s) -> bool:
    return (
        isinstance(s, str)
        and s.startswith(PREFIX)
        and len(s) == len(PREFIX) + 64
        and all(c in "0123456789abcdef" for c in s[len(PREFIX):])
    )


def hex_of(h: str) -> str:
    return h[len(PREFIX):]


def from_hex(x: str) -> str:
    return PREFIX + x
