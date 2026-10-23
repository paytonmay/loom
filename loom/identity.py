"""Identity is an ML-DSA-44 keypair. id = sha256 of the public key."""
import base64
import hashlib
import json
import os
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_44

ALG = "ML-DSA-44"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def identity_id(pubkey: bytes) -> str:
    return "id:" + hashlib.sha256(pubkey).hexdigest()


def verify(pubkey: bytes, data: bytes, sig: bytes) -> bool:
    try:
        return bool(ML_DSA_44.verify(pubkey, data, sig))
    except Exception:
        return False


class Identity:
    def __init__(self, name: str, pubkey: bytes, seckey: bytes | None = None):
        self.name = name
        self.pubkey = pubkey
        self.seckey = seckey

    @property
    def id(self) -> str:
        return identity_id(self.pubkey)

    @classmethod
    def generate(cls, name: str) -> "Identity":
        pk, sk = ML_DSA_44.keygen()
        return cls(name, pk, sk)

    def sign(self, data: bytes) -> bytes:
        if self.seckey is None:
            raise ValueError("no secret key")
        return ML_DSA_44.sign(self.seckey, data)

    # ---- persistence -------------------------------------------------

    @staticmethod
    def _path(home: Path, name: str) -> Path:
        return Path(home) / "keys" / f"{name}.json"

    def save(self, home: Path) -> Path:
        p = self._path(home, self.name)
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {"name": self.name, "alg": ALG, "pubkey": b64e(self.pubkey)}
        if self.seckey is not None:
            rec["seckey"] = b64e(self.seckey)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f, indent=2)
        return p

    @classmethod
    def load(cls, home: Path, name: str) -> "Identity":
        p = cls._path(home, name)
        with open(p) as f:
            rec = json.load(f)
        if rec.get("alg") != ALG:
            raise ValueError(f"unsupported key algorithm {rec.get('alg')}")
        sk = b64d(rec["seckey"]) if "seckey" in rec else None
        return cls(rec["name"], b64d(rec["pubkey"]), sk)
