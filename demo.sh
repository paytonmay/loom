#!/bin/sh
# Two peers and a relay on one machine. Everything stays under ./demo-run.
set -e
cd "$(dirname "$0")"
LOOM="./loom.sh"
rm -rf demo-run && mkdir -p demo-run/relay
A="demo-run/alice"; B="demo-run/bob"

say() { printf '\n\033[1m# %s\033[0m\n' "$*"; }

say "alice and bob each create a post-quantum identity"
LOOM_HOME=$A $LOOM keygen default
LOOM_HOME=$B $LOOM keygen default
BOB_PK=$(LOOM_HOME=$B $LOOM id --export | python3 -c 'import sys,json; print(json.load(sys.stdin)["pubkey"])')
BOB_ID=$(LOOM_HOME=$B $LOOM id)

say "alice creates a document and writes to it"
DOC=$(LOOM_HOME=$A $LOOM create "Loom experiment log")
LOOM_HOME=$A $LOOM set $DOC status '"drafting"' >/dev/null
LOOM_HOME=$A $LOOM set $DOC phase 0 >/dev/null

say "start an HTTP relay (it stores hashes and checks signatures; it understands nothing else)"
$LOOM serve demo-run/relay --port 7700 & RELAY=$!
sleep 1
trap 'kill $RELAY 2>/dev/null' EXIT

say "alice pushes; bob pulls a document he has never seen"
LOOM_HOME=$A $LOOM push $DOC http://127.0.0.1:7700
LOOM_HOME=$B $LOOM pull $DOC http://127.0.0.1:7700

say "bob tries to write without a capability"
LOOM_HOME=$B $LOOM set $DOC status '"hijacked"' >/dev/null
LOOM_HOME=$B $LOOM push $DOC http://127.0.0.1:7700
LOOM_HOME=$A $LOOM pull $DOC http://127.0.0.1:7700
LOOM_HOME=$A $LOOM show $DOC

say "alice grants bob write access; bob writes; both converge"
LOOM_HOME=$A $LOOM grant $DOC $BOB_PK
LOOM_HOME=$A $LOOM push $DOC http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$B $LOOM pull $DOC http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$B $LOOM set $DOC phase 1 >/dev/null
LOOM_HOME=$B $LOOM set $DOC note '"written by bob, offline, merged later"' >/dev/null
LOOM_HOME=$B $LOOM push $DOC http://127.0.0.1:7700
LOOM_HOME=$A $LOOM pull $DOC http://127.0.0.1:7700
LOOM_HOME=$A $LOOM show $DOC

say "the causal log, as alice sees it"
LOOM_HOME=$A $LOOM log $DOC

say "alice publishes: static files plus an HTML page that links back to the signed ops"
LOOM_HOME=$A $LOOM publish $DOC demo-run/site --page index.html
python3 -m http.server 7701 -d demo-run/site >/dev/null 2>&1 & SITE=$!
sleep 1
trap 'kill $RELAY $SITE 2>/dev/null' EXIT

say "anyone verifies the page from its URL; the dumb file server is a read-only relay"
$LOOM verify http://127.0.0.1:7701/index.html

say "dave pulls through the same host, then tries to push to it"
rm -rf demo-run/dave
LOOM_HOME=demo-run/dave $LOOM pull $DOC http://127.0.0.1:7701/loom
LOOM_HOME=demo-run/dave $LOOM keygen default >/dev/null
LOOM_HOME=demo-run/dave $LOOM set $DOC note '"dave was here"' >/dev/null
LOOM_HOME=demo-run/dave $LOOM push $DOC http://127.0.0.1:7701/loom || echo "(a static host cannot accept pushes; the owner publishes the folder instead)"

say "an open thread: nobody owns it, everybody owns their own words"
SQ=$(LOOM_HOME=$A $LOOM create "town square" --open 2>/dev/null)
LOOM_HOME=$A $LOOM push $SQ http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$B $LOOM pull $SQ http://127.0.0.1:7700 >/dev/null
LOOM_HOME=demo-run/dave $LOOM pull $SQ http://127.0.0.1:7700 >/dev/null
FIRST=$(LOOM_HOME=$A $LOOM say $SQ "anyone there?")
LOOM_HOME=$A $LOOM push $SQ http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$B $LOOM pull $SQ http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$B $LOOM say $SQ "yes, and nobody granted me anything" --re $FIRST >/dev/null
LOOM_HOME=$B $LOOM push $SQ http://127.0.0.1:7700 >/dev/null
say "dave tries to post as bob"
LOOM_HOME=demo-run/dave $LOOM set $SQ "$BOB_ID/9" '{"text":"bob says dave is great","re":null}' >/dev/null
LOOM_HOME=demo-run/dave $LOOM push $SQ http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$A $LOOM pull $SQ http://127.0.0.1:7700 >/dev/null
LOOM_HOME=$A $LOOM thread $SQ
LOOM_HOME=$A $LOOM show $SQ | tail -2

say "a relay operator tampers with a stored op"
F=$(ls demo-run/relay/blobs | head -1)
printf '{"tampered":true}' > demo-run/relay/blobs/$F
rm -rf demo-run/carol
LOOM_HOME=demo-run/carol $LOOM pull $DOC http://127.0.0.1:7700 || echo "(pull refused the tampered blob, as it should)"
