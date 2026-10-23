"""Content-addressed blob store on disk, plus a per-document index of op hashes."""
from pathlib import Path

from .canon import sha256, hex_of, from_hex, is_hash


class IntegrityError(Exception):
    pass


class Store:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.blobs = self.root / "blobs"
        self.docs = self.root / "docs"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.docs.mkdir(parents=True, exist_ok=True)

    # ---- blobs -------------------------------------------------------

    def put(self, data: bytes) -> str:
        h = sha256(data)
        p = self.blobs / hex_of(h)
        if not p.exists():
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(p)
        return h

    def get(self, h: str) -> bytes:
        if not is_hash(h):
            raise IntegrityError(f"malformed hash {h!r}")
        data = (self.blobs / hex_of(h)).read_bytes()
        if sha256(data) != h:
            raise IntegrityError(f"blob {h} does not match its hash")
        return data

    def get_raw(self, h: str) -> bytes:
        """Bytes as stored, unverified. For relays: the reader checks the hash."""
        return (self.blobs / hex_of(h)).read_bytes()

    def has(self, h: str) -> bool:
        return is_hash(h) and (self.blobs / hex_of(h)).exists()

    # ---- document index ---------------------------------------------

    def _index(self, doc_id: str) -> Path:
        return self.docs / hex_of(doc_id)

    def add_to_doc(self, doc_id: str, h: str) -> None:
        p = self._index(doc_id)
        existing = self.doc_ops(doc_id)
        if h not in existing:
            with open(p, "a") as f:
                f.write(h + "\n")

    def doc_ops(self, doc_id: str) -> set[str]:
        p = self._index(doc_id)
        if not p.exists():
            return set()
        return {line.strip() for line in p.read_text().splitlines() if line.strip()}

    def doc_ids(self) -> list[str]:
        return sorted(from_hex(p.name) for p in self.docs.iterdir())

    def resolve_doc(self, prefix: str) -> str:
        """Accept a full hash or a unique hex prefix."""
        if is_hash(prefix):
            return prefix
        x = prefix[len("sha256:"):] if prefix.startswith("sha256:") else prefix
        matches = [d for d in self.doc_ids() if hex_of(d).startswith(x)]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise KeyError(f"no document matches {prefix!r}")
        raise KeyError(f"ambiguous document prefix {prefix!r}")
