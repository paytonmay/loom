# Loom

Live example: https://paytonmay.github.io/loom/ (verify it with `./loom.sh verify` on that URL).

A document that needs no server. Content-addressed, signed with post-quantum
keys (ML-DSA-44), writable only by capability, merged conflict-free between
peers. See `DESIGN.md` for the full design.

```
python3 -m venv .venv && . .venv/bin/activate
pip install dilithium-py cryptography pytest
pytest -q
./demo.sh
```

Everyday use:

```
./loom.sh keygen default
./loom.sh create "my notes"            # prints the document id
./loom.sh set <doc> title '"hello"'    # values are JSON, or plain text
./loom.sh show <doc>                   # state, provenance, roles, verification report
./loom.sh grant <doc> <hex pubkey>     # from the other person's `loom id --export`
./loom.sh serve ./relay                # an HTTP relay; a shared folder works too
./loom.sh push <doc> http://host:7700
./loom.sh pull <doc> http://host:7700
```

Publishing on a site you already have, with no server code:

```
./loom.sh publish <doc> ./site --page notes.html   # site/loom/ (the ops) + site/notes.html
# deploy ./site however you already do (git push, rsync, S3 sync)
./loom.sh verify https://example.com/notes.html    # anyone: fetch the ops, verify, report
./loom.sh pull <doc> https://example.com/loom      # or pull into your own store
```

The page links back to the signed ops with `<link rel="loom">` and carries a
JavaScript verifier, so a browser checks every signature itself and shows a
banner. A static host is a read-only relay: pushes to it fail with a
message, so push to the folder and republish instead.

The JavaScript verifier is a second, independent implementation; the test
suite runs it under Node (if installed) and requires it to agree with Python.

Before you rely on it, set a recovery key so a lost laptop is not lost authorship:

```
LOOM_HOME=/Volumes/usb/loom ./loom.sh keygen default     # generate it somewhere you keep offline
./loom.sh recovery <that key's hex pubkey from `id --export`>
```

New documents grant it admin. To recover: pull the document on any machine,
then with the offline key `grant` a fresh key `--admin` and `revoke` the old id.

An open thread has no owner. Anyone may post, only as themselves:

```
./loom.sh create "town square" --open
./loom.sh say <doc> "hello"                  # posts under your own id; no grant needed
./loom.sh say <doc> "reply" --re <op hash>
./loom.sh thread <doc>
```

`LOOM_HOME` picks the key and store directory (default `~/.loom`). Two peers
on one machine use two homes.

Layout: `loom/` is the code, `tests/` the tests, `DESIGN.md` the design,
`docs/` the published site that GitHub Pages serves (the live example above).

License: MIT. The bundled `loom/static/mldsa.js` is from the noble libraries, also MIT.
