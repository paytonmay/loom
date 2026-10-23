# Loom: Technical Design

Status: experiment; phases 0 to 6, the adoption track, and open threads are built. Started 2026-10-23. Author: Payton May, with Claude.

---

## 1. Thesis

Loom is a prototype of a document that needs no server. Its content is
addressed by hash, signed with post-quantum keys, writable only by holders of
an explicit capability, and merged conflict-free between peers.

The experiment tests one claim: that those four properties, combined in a
single small system, make the secure version of a shared document the
*easiest* version to build. The web won because sloppy was easy. A successor
wins only if correct is easier.

The quantum threat to the web is being patched in place and will not by itself
produce a new web. The web's deeper flaws are structural:

1. A URL names a place, not content. Content at a place can change or vanish.
2. Data lives on servers, not with the people it belongs to.
3. Code runs with ambient authority: anything the user can touch, the code can.

Loom attacks those three directly, and uses post-quantum signatures so that the
provenance it establishes stays verifiable for decades, past the point where
today's elliptic-curve signatures can be forged.

The prototype is a command-line tool and library in Python, chosen for speed
of iteration. Nothing in the design depends on Python. A second implementation
in Go is the planned test of whether the protocol is specified tightly enough
to interoperate.

---

## 2. Goals and non-goals

### Goals

- A document is a set of signed operations. Anyone holding the set can verify
  every byte of it with no network access and no trusted third party.
- Two peers that have never talked to a server can each edit offline and
  merge to the same state.
- Write access is a capability: an unforgeable, delegatable, revocable grant
  from someone who holds it. There are no accounts and no logins.
- All signatures are post-quantum (ML-DSA, FIPS 204). All hashes are SHA-256.
- A relay that stores and forwards operations learns nothing it can forge and
  cannot alter anything without detection. Hosting becomes caching.
- The whole thing fits in a few hundred lines a person can read in an evening.

### Non-goals, for this phase

- Performance. Pure-Python ML-DSA is slow. We measure, we do not optimize.
- Rich text or a text CRDT. The document is a map of keys to values. A
  sequence CRDT is a well-understood addition once the authority model works.
- Network discovery, NAT traversal, gossip. Peers find each other out of band.
- Encryption at rest on the peer's own disk.
- A user interface. The agent-facing interface is sketched in section 9 and
  deferred.

---

## 3. Background: the four structural ideas

### Content addressing

A thing is named by the hash of its bytes. The name cannot lie about the
content, the content can be fetched from anyone who has it, and two copies are
provably the same copy. Prior art: Git, IPFS, Hypercore, Unison (for code).

### Local-first data with CRDTs

Each peer holds a full copy and edits it locally. A Conflict-free Replicated
Data Type guarantees that peers which have seen the same set of operations,
in any order, reach the same state. The server, if one exists, is a relay.
Prior art: Ink and Switch's local-first essay, Automerge, Yjs.

### Capability security

Authority is a reference you hold, not an identity you claim. Code and people
can act only on what they have been handed. Most web vulnerability classes,
from cross-site request forgery to prompt injection, are failures of ambient
authority. Prior art: the E language, Capability Myths Demolished, Spritely
Goblins, UCAN, the WebAssembly Component Model.

### Post-quantum signatures

Shor's algorithm breaks RSA and elliptic-curve signatures. ML-DSA (formerly
CRYSTALS-Dilithium) is the NIST-standardized lattice-based replacement.
Signatures are roughly 2.4 KB instead of 64 bytes. For a system whose entire
security rests on signatures that must stay valid for decades, that cost is
the price of being right.

### The AI-as-reader shift

Increasingly the reader of a web resource is an agent acting for a person.
Agents do not need pages; they need verifiable data, a schema, and explicit
capabilities. Loom's documents are already that shape. Section 9 sketches the
interface.

---

## 4. Architecture

```
  +-----------------------------------------------------------+
  |  CLI / library API           loom.cli                     |
  +-----------------------------------------------------------+
  |  Document                    loom.doc                     |
  |    operation DAG, causal order, capability table,         |
  |    LWW-map state, verification report                     |
  +-----------------------------------------------------------+
  |  Operations                  loom.ops                     |
  |    build, sign, verify a single op                        |
  +------------------------+----------------------------------+
  |  Identity   loom.identity   |  Sync          loom.sync    |
  |    ML-DSA-44 keypair,       |    push / pull op sets via  |
  |    id = sha256(pubkey)      |    directory or HTTP relay  |
  +------------------------+----------------------------------+
  |  Store                       loom.store                   |
  |    content-addressed blobs on disk: blobs/<sha256>        |
  +-----------------------------------------------------------+
  |  Canon                       loom.canon                   |
  |    canonical JSON, SHA-256, id formatting                 |
  +-----------------------------------------------------------+
```

### How a change flows

```
  Alice                         Relay (dumb)                  Bob
  -----                         ------------                  ---
  edit: set title="Loom"
  build op, deps = frontier
  sign with ML-DSA sk
  store blob by hash
          --- push: blobs ----->  store by hash
                                  verify hash + signature
                                  (cannot forge, cannot alter)
                                         ----- pull: blobs ----->  store by hash
                                                                   verify hash + sig
                                                                   check Alice's capability
                                                                   merge into DAG
                                                                   recompute LWW state
```

The relay is optional. Alice and Bob can exchange the same blobs over a USB
stick, a shared folder, or email. The relay is a cache with a network
interface, nothing more.

---

## 5. Data model

### Canonical encoding

Every signed or hashed structure is a JSON object encoded canonically:

- keys sorted lexicographically by Unicode code point
- no whitespace
- UTF-8, with non-ASCII emitted as-is (not escaped)
- numbers are integers only; floats are forbidden in signed structures
- no duplicate keys

`hash(x) = sha256(canonical_json(x))`, rendered as `sha256:<64 hex>`.

### Blob

A blob is any byte string stored under its hash. The store is a directory,
`blobs/<hex>`. Writing is idempotent. Reading verifies the hash.

### Operation

An operation is the unit of change. Every op is signed by its author and
content-addressed by the hash of its signed form.

```json
{
  "v": 1,
  "type": "op",
  "doc": "sha256:...",          // id of the genesis op; null in genesis itself
  "author": "id:...",           // sha256 of the author's public key
  "pubkey": "<base64 ML-DSA-44 public key>",
  "seq": 7,                     // per-author counter, starts at 1
  "lamport": 42,                // 1 + max(lamport of deps), 1 for genesis
  "deps": ["sha256:...", ...],  // the author's current frontier, sorted
  "action": { ... },            // see below
  "sig": "<base64 ML-DSA-44 signature over canonical_json(op without sig)>"
}
```

`deps` makes the op set a directed acyclic graph. It gives causal order
without trusting any clock, and it is what makes capability checks
well-defined: "did Alice hold write access when she wrote this" becomes "is
a valid grant to Alice an ancestor of this op, with no valid revoke in
between."

### Actions

```json
{"genesis": {"title": "..."}}                       // first op; author becomes owner
{"set": "<key>", "value": <json>}                   // write a key
{"del": "<key>"}                                    // delete a key
{"grant": {"to": "id:...", "pubkey": "...", "role": "write" | "admin"}}
{"revoke": {"id": "id:..."}}
```

### Document

A document is identified by the hash of its genesis op. Its state is the
Last-Writer-Wins map computed over the valid ops in the DAG:

- for each key, the winning op is the valid `set` or `del` with the greatest
  `(lamport, author, hash)` tuple
- a winning `del` means the key is absent

The `(lamport, author, hash)` total order means every peer holding the same
op set computes the same state, regardless of arrival order. That is the
CRDT property.

### Verification report

`show` prints the state and a report: how many ops were seen, how many were
rejected and why (bad hash, bad signature, author does not match key, missing
dependency, unauthorized), so that a reader can see exactly what the system
trusted and what it threw away.

---

## 6. Identity and signatures

An identity is an ML-DSA-44 keypair. There is no name, no email, no account.

- `id = "id:" + hex(sha256(pubkey))`
- Ops carry the full public key so that any op is self-verifying.
- A key file may hold only the public half. The CLI refuses to sign with
  such a key and says so.
- **Recovery.** Losing the only key would mean losing authorship, with no
  server to appeal to. The capability model already answers this: a second
  admin key, generated in a home you keep offline, whose public half is
  registered on the daily machine as the key named `recovery`. `create`
  grants it admin automatically. After a lost laptop: pull the document
  anywhere, grant a fresh daily key admin with the recovery key, revoke the
  old one. The revocation is causal, so the thief's later writes are
  rejected by every peer. No new protocol; it is just a grant you make
  before you need it.
- Private keys live in `$LOOM_HOME/keys/<name>.json`. Default
  `LOOM_HOME` is `~/.loom`. Two peers on one machine use two homes.

ML-DSA-44 is the smallest parameter set (NIST security level 2, roughly
equivalent to AES-128 against a quantum adversary). Public key 1312 bytes,
secret key 2560 bytes, signature 2420 bytes. Level 3 and 5 are a one-line
change if needed.

Signing covers the canonical JSON of the op with `sig` removed. Verification
recomputes it. The op's hash covers the op *with* the signature, so two
signatures of the same content produce two distinct ops; this is deliberate.
ML-DSA signatures are randomized, so this case only arises if an author signs
the same content twice, which the `seq` counter prevents.

---

## 7. Capabilities

### Rules

1. The author of the genesis op is the **owner**: the first admin, and the
   author of record. The owner has no other privilege and can be revoked
   like anyone else. (An earlier draft made the owner immune; that made
   recovery from a lost owner key impossible, so it was dropped.)
2. An **admin** may `grant` `write` or `admin` to any identity and may
   `revoke` any identity. Admin is full trust: grant it only to keys you
   control, such as a recovery key, or to people you would hand the
   document to outright.
3. A **writer** may `set` and `del`.
4. An op by author A is **authorized** if, in the set of A's op's ancestors,
   processed in topological order, the capability table ends with A holding
   the role the action requires.
5. A `grant` or `revoke` is itself an op and is subject to rule 4: it counts
   only if its author held `admin` at that point in the causal past.

### Why ancestors, not time

Clocks can be forged; causal history cannot. Judging authority by what the
author had provably seen when they signed makes the check deterministic on
every peer, with no coordinator and no trusted timestamp.

### Known consequence

Revocation is causal, not instantaneous. If Alice is revoked and
concurrently writes an op that does not yet have the revoke as an ancestor,
that op is valid. Every peer agrees it is valid. This is the correct
behavior for a system without a coordinator; it is listed in section 12 as a
property people should understand before relying on it.

Two admins may revoke each other concurrently. Both revokes are valid, since
each was authorized in its own causal past, and the document is left with
no admin: readable, mergeable, frozen. Peers converge on that state. The
owner has no tie-break, on purpose; a tie-break would be an immunity by
another name.

### Open threads: provenance without ownership

A genesis may carry `"open": true`. The document then has no capability
table at all. Grants and revokes are unauthorized, the genesis author has no
privilege beyond having started the thread, and rules 1 through 5 are
replaced by one rule:

6. In an open thread, an op by author A may `set` or `del` only a key equal
   to A's id or beginning with A's id followed by `/`.

Nobody owns the thread; everybody owns their own words. Nobody can silence
you and nobody can speak as you. The thing an open thread gives up is
moderation at the container: with no owner there is no revocation, so
filtering moves to the reader, who chooses whose identities to show. That is
where email, Usenet and nostr all landed, and it is the honest price of
"free". An owned document and an open thread share everything else: the op
envelope, identities, relays, the page, the verifier.

A message is a `set` of key `<author id>/<seq>` to `{"text": ..., "re":
<op hash or null>}`; `loom say` and `loom thread` are thin helpers over
that. An author may edit or delete their own messages (last writer wins
among their own ops) and nobody else can.

### Read capability: sealed documents

A genesis may carry `"sealed": true`. Every later action in that document
must then be a `sealed` action:

```
{"sealed": {"nonce": <12 bytes, base64>, "ct": <ChaCha20-Poly1305, base64>}}
```

The ciphertext is the canonical encoding of an ordinary inner action
(`set`, `del`, `grant` or `revoke`) encrypted under the document's 32-byte
read key, with the op's `doc`, `author` and `seq` as associated data so a
ciphertext cannot be lifted into another op. Everything else in the op,
including `deps`, `lamport` and the signature, stays in the clear. The
signature covers the ciphertext.

Consequences:

- A relay, a static host, and the browser verifier check every hash and
  signature without the key. They see who wrote, when in causal order, and
  how much. They cannot see what. Hosting a private document on a public
  host costs nothing extra.
- A reader without the key gets a verified skeleton: the report counts the
  sealed ops as valid and unreadable, state is empty, and the title is empty
  too, because a sealed document's title travels as a sealed `_title` key.
- A reader with the key decrypts each action and then applies the normal
  rules, including capabilities: grants and revokes are sealed like
  everything else, so even the capability table is private.
- A wrong key, a tampered ciphertext, or a ciphertext moved to another op
  fails authentication and is reported as rejected, never applied.
- An unsealed action in a sealed document is rejected, so a careless writer
  cannot leak; a sealed action in an unsealed document is rejected, so the
  two kinds never mix.

The read key is shared out of band: `loom readkey <doc>` prints it, `loom
readkey <doc> <hex>` imports it. Wrapping it under a recipient's ML-KEM
public key is a later convenience, not a change to the format. Taking read
access away is not possible, since whoever has the key has the ciphertexts:
the honest move is a new document with a new key, which is what every
encrypted-group design ends up doing.

A published page for a sealed document holds no plaintext: `publish` loads
the document without the key on purpose.

---

## 8. Sync without hosting

A relay exposes four operations:

```
list(doc)        -> set of op hashes it holds for the document
get(hash)        -> the blob
put(blob)        -> store if sha256 matches and signature verifies
```

Peers sync by set difference: fetch the relay's list, pull what is missing,
push what the relay lacks. Because ops are content-addressed and
self-verifying, nothing a relay does can corrupt a document. The worst it can
do is withhold, which is detectable by comparing with any other peer.

Two relay implementations, same interface:

- **Directory relay**: a folder. Any shared folder works.
- **HTTP relay**: `loom serve`, a stdlib HTTP server with the four endpoints.
- **Static relay**: the directory relay's folder, served read-only by any
  file host. Not a third implementation; the same layout, no code.

The relay does not understand documents. It understands hashes and
signatures. That is the whole point: when the hosting layer cannot be
trusted with anything, it does not need to be trusted at all.

### Static relay: any file host, no code

The two relays share one on-disk layout, and the HTTP relay serves it
verbatim:

```
<relay>/
  blobs/<hex>      one op, the exact bytes that hash to sha256:<hex>
  docs/<hex>       the ops of document sha256:<hex>, one hash per line
```

`GET docs/<hex>` and `GET blobs/<hex>` on `loom serve` return those files
unchanged. The only thing `loom serve` adds is `POST blobs`. So a folder
that was pushed to and then copied to any static host (GitHub Pages, S3,
a web server's document root, a shared drive with an HTTP front) is a
read-only relay. Peers pull from it with the same client. A push to it
fails with a clear message; the owner pushes to the folder and republishes
it with whatever already publishes the site.

This is the adoption path. Nothing new runs anywhere. "Adopting Loom" for
an existing site means copying a folder to where the site already lives.
Blobs are immutable and may be cached forever; only the per-document index
changes, and a stale index can only withhold, never corrupt.

Operational notes: a missing index is a 404, which the client reads as an
empty set, so an unpublished document is simply "nothing yet". File names
are bare hex with no extension; every static host tested serves those.
Clients verify every blob's hash on receipt, so a host's content type and
caching headers do not matter.

### The page is a view; the link is the document

`loom publish <doc> <site>` pushes to `<site>/loom/` and writes an HTML page
beside it. The page carries one line that matters:

```
<link rel="loom" href="loom/docs/<hex>">
```

The href is the document's index file in the relay, so one link names both
the relay and the document. Humans read a normal page. A peer or an agent
follows the link, pulls the ops, and verifies every field's author and
history itself. The page says in its footer that it is a rendering and not
the source; a tampered or stale page cannot pass itself off as the
document, because the document is whatever the signed ops say.

`loom verify <url>` is the other half: given a page URL, a local `.html`,
a relay URL plus a document id, or a folder plus an id, it pulls into a
scratch store and prints the same report `show` prints. It touches nothing
in `LOOM_HOME`, so anyone can point it at a stranger's page. This is the
one-command demonstration of the thesis to someone who has never heard of
Loom: the host is a dumb file server, and the reader trusts it with nothing.

The page also embeds a `<script type="application/loom+json">` block with
the state, provenance, roles and report, as a convenience for a reader that
has not yet pulled the ops. It is unverified until they do, and the page
says so.

### Verification in the reader's browser

`publish` copies two files beside the ops: `loom/verify.js`, a JavaScript
implementation of the verifier, and `loom/mldsa.js`, ML-DSA-44 and SHA-256
bundled from the MIT-licensed noble libraries. The page loads the verifier
as a module. It follows the back-link, fetches the index and every blob,
checks each hash and signature, rebuilds the causal order and capability
table, derives the state, and compares it to what the page shows. A banner
at the top then says one of three things: verified, page does not match the
signed document, or could not verify here (with the command to run instead).

The host serves the verifier, so a hostile host could serve a lying one.
That is the same limit every web page has, and the design does not pretend
otherwise: the browser banner is a convenience for honest hosts and a strong
check against accidental corruption; `loom verify` from a tool you installed
is the check against a hostile host. Content addressing makes the next step
cheap when wanted: a reader can pin the verifier's hash.

The JavaScript verifier is also the **second implementation** the plan
called for (phase 6 named Go; JavaScript turned out to be the one adoption
needs). It shares no code with the Python one. A test runs both over the
same documents, including unauthorized, revoked and tampered ops, and
requires identical state, provenance, roles and rejection lists. One
divergence is known and documented in the file: integers beyond 2^53.

---

## 9. Agent interface (future)

A Loom document is already what an agent wants: verifiable data with
provenance per field. The sketch:

- A reserved key `_schema` holds a JSON Schema for the document's other keys.
- A reserved key `_intents` holds a list of actions the document's owner is
  willing to let an agent take, each naming the capability role it needs.
- An agent reading the document gets, for each field, the author identity and
  the op hash. Provenance is not a feature bolted on; it falls out of the data
  model.

No page, no scraping, no guessing. The document says what it is, who vouches
for each part, and what may be done with it.

---

## 10. Threat model

### Defended

| Threat | Defense |
|---|---|
| Relay alters content | Content addressing; hash mismatch is detected |
| Relay forges an op | ML-DSA signature; relay has no key |
| Unauthorized peer writes | Capability check against causal history |
| Replay of an old op | Ops are idempotent by hash; replay is a no-op |
| Quantum adversary forging signatures | ML-DSA is lattice-based; Shor does not apply |
| Harvest-now-decrypt-later on signatures | Signatures are PQ from day one |
| Peers disagree on state | CRDT total order guarantees convergence |
| Relay or host reads a private document | Sealed actions: ChaCha20-Poly1305 under a read key the host never sees |
| Ciphertext tampered or moved between ops | AEAD tag plus doc/author/seq as associated data |
| Relay or blob crafted to crash a reader | Nesting cap, float and type checks, size cap of 1 MB per blob; every malformed blob is a rejection in the report, never an exception |
| Page content injects script | Every value is HTML-escaped; the verifier writes text only; the embedded JSON escapes `</` |

### Not defended, by design, in this phase

- **Metadata of sealed documents.** Authors, causal structure, timing by
  lamport, op sizes and the capability-op count are visible to anyone with
  the ops. Only contents are hidden.
- **Taking read access back.** A key, once shared, is shared. Start a new
  document to exclude someone.

- **A public `loom serve` accepts storage from anyone.** It stores any
  correctly signed op, so a stranger can fill its disk with documents of
  their own. Run it on localhost or behind something that limits who may
  POST; the static-host path has no such exposure because nothing accepts
  writes.

| Threat | Status |
|---|---|
| Relay withholds ops | Detectable by cross-checking, not prevented |
| Compromised private key | Revocation is causal; see section 12 |
| Traffic analysis of who syncs with whom | Out of scope |
| Reading ops in transit or on relay | Phase 4 (read capabilities) |
| Denial of service on a relay | Out of scope |
| Side channels in the pure-Python ML-DSA | Known; the library is not constant-time. Not for production keys. |

---

## 11. Implementation plan

### Language and libraries

- Python 3.12, stdlib wherever possible.
- `dilithium-py` 1.5.1: pure-Python ML-DSA per FIPS 204. Chosen because it
  installs with no compiler. It is slow (tens of milliseconds per signature)
  and not side-channel hardened. Acceptable for an experiment.
- `cryptography` 43: ChaCha20-Poly1305 for sealed documents.
- `pytest` for tests.

### Repo layout

```
elegant/
  DESIGN.md            this document
  README.md            how to run the demo
  loom/
    canon.py           canonical JSON, sha256, id helpers
    identity.py        keygen, load, sign, verify
    store.py           content-addressed blob store
    ops.py             build and verify a single op
    doc.py             DAG, causal order, capabilities, LWW state, report
    sync.py            directory relay and HTTP relay, push/pull
    page.py            HTML rendering and the <link rel="loom"> back-link
    static/verify.js   the verifier in JavaScript: browser banner and node CLI
    static/mldsa.js    ML-DSA-44 + SHA-256, bundled from noble (MIT)
    cli.py             command-line interface
  tests/
    test_loom.py
  docs/                the published site (GitHub Pages serves this folder):
                       index.html, loom/blobs, loom/docs, loom/verify.js
  demo.sh              two peers and a relay on one machine
```

### Phases

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | Canon + store | `put` then `get` round-trips; tampered blob is rejected |
| 1 | Identity | keygen, sign, verify; id derives from pubkey |
| 2 | Ops + document | create, set, del, show; LWW converges from shuffled op order |
| 3 | Capabilities | unauthorized op rejected; grant enables; revoke disables causally |
| 4 | Sync | two peers converge through a directory relay and an HTTP relay |
| 5 | Read capability | encrypted actions; relay sees only metadata. Done |
| 6 | Second implementation | reads and verifies documents written by the Python one. Done in JavaScript (the browser verifier); Go remains optional |
| 7 | Agent interface | `_schema` and `_intents`; an agent reads and acts with provenance |

Phases 0 through 4 are the target for the first session.

### Adoption track (runs beside the phases)

The protocol must pay off for one site with no other Loom user in the world,
or it loses to the incumbent. Section 8 holds the design; the steps:

| Step | Deliverable | Status |
|---|---|---|
| 1 | Any static host is a read-only relay | done |
| 2 | `loom publish`: page with `<link rel="loom">` back-link | done |
| 3 | `loom verify <url>`: one command, no setup, no trust in the host | done |
| 3b | Recovery key; owner immunity dropped | done |
| 3c | Verification in the reader's browser; second implementation | done |
| 4 | Dogfood: the project's status document live at https://paytonmay.github.io/loom/ | done |
| 5 | Open-thread mode: ownerless messaging with provenance | done |
| 6 | Cross-site capability grants (the network effect, last) | later |

Key-loss recovery is addressed in section 6 (an offline admin key, granted
at creation); browser-side verification in section 8. The first adopter is
this project: its status document is a Loom document on GitHub Pages, the
site repo is `paytonmay/loom`, and `loom verify` against the live URL
returns every op valid. GitHub Pages serves bare-hex file names and the
module script without configuration; a `.nojekyll` file is included so
Jekyll never touches the folder.

---

## 12. Open questions and known weaknesses

- **Causal revocation.** A revoked key can still produce valid ops until the
  revoke reaches it causally. Mitigations: an "epoch" mechanism where the
  owner re-keys the document, or a policy that peers refuse ops older than
  the latest revoke they have seen. Both trade availability for safety.
- **Key loss.** Addressed for documents by the recovery key (section 6),
  which is an ordinary admin grant made in advance. The identity itself is
  still unrecoverable: a lost key's *past* signatures stay valid, but no one
  can sign as it again. Social or threshold recovery of the key would go
  further and belongs to a later phase.
- **Signature size.** At 2.4 KB per op, a document with a thousand edits
  carries 2.4 MB of signatures. Batching edits into one op, or signing
  Merkle roots of batches, cuts this by orders of magnitude.
- **No sequence CRDT.** A map is enough to prove the authority model. Text
  needs RGA or Fugue; both compose with the same op envelope.
- **Side channels.** The pure-Python ML-DSA is not constant-time. A Go or
  liboqs backend fixes this; the protocol does not change.
- **Who pays for relays.** The technical design makes relays cheap and
  untrusted. It says nothing about why anyone would run one. This is the
  question every decentralized system has failed on, and it is not a
  question code can answer.

---

## 13. References

- FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA), NIST, 2024
- FIPS 203, ML-KEM, NIST, 2024
- Kleppmann, Wiggins, van Hardenberg, McGranaghan. "Local-first software." Ink and Switch, 2019
- Shapiro, Preguiça, Baquero, Zawirski. "Conflict-free Replicated Data Types." 2011
- Miller, Yee, Shapiro. "Capability Myths Demolished." 2003
- Miller. "Robust Composition." PhD thesis, 2006 (the E language)
- UCAN: User Controlled Authorization Networks, specification
- IPFS, Hypercore, and Unison documentation on content addressing
- Lamport. "Time, Clocks, and the Ordering of Events in a Distributed System." 1978
- dilithium-py, GiacomoPope, pure-Python ML-DSA
