// Loom verifier, in the reader's browser or under Node.
//
// This is the second implementation of the protocol, independent of the
// Python one. It fetches a document's signed ops from a relay, checks every
// hash and signature, rebuilds the causal order and the capability table,
// and derives the state. In a page it then says whether the page matches.
//
// Known gaps against the Python implementation: integers beyond 2^53 lose
// precision in JavaScript, so an op carrying one fails its hash check here
// and is rejected rather than accepted.
import { ml_dsa44, sha256 } from './mldsa.js';

const PREFIX = 'sha256:';
const VERSION = 1;
const ACTIONS = ['genesis', 'set', 'del', 'grant', 'revoke'];
const ROLES = ['write', 'admin'];
const te = new TextEncoder();
const td = new TextDecoder();

// ---- canon ---------------------------------------------------------------

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const hashBytes = (bytes) => PREFIX + hex(sha256(bytes));
export const isHash = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
const hexOf = (h) => h.slice(PREFIX.length);

// Python sorts keys by code point; JS sort() by UTF-16 unit. Compare by code point.
function cmpCodePoints(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0));
  const y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

// Mirrors canon.py: sorted keys, no whitespace, integers only, UTF-8.
export function canonical(obj, path = '$') {
  if (obj === null || typeof obj === 'boolean' || typeof obj === 'string') return JSON.stringify(obj);
  if (typeof obj === 'number') {
    if (!Number.isInteger(obj)) throw new Error(`float not allowed in signed structure at ${path}`);
    return String(obj);
  }
  if (Array.isArray(obj)) return '[' + obj.map((v, i) => canonical(v, `${path}[${i}]`)).join(',') + ']';
  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort(cmpCodePoints);
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(obj[k], `${path}.${k}`)).join(',') + '}';
  }
  throw new Error(`unsupported value at ${path}`);
}
export const hashObj = (obj) => hashBytes(te.encode(canonical(obj)));

// ---- identity ------------------------------------------------------------

const B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
function b64d(s) {
  if (typeof s !== 'string' || !B64.test(s)) throw new Error('bad base64');
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const identityId = (pk) => 'id:' + hex(sha256(pk));
function verifySig(pk, data, sig) {
  try { return ml_dsa44.verify(sig, data, pk); } catch { return false; }
}

// ---- ops -----------------------------------------------------------------

export function actionKind(action) {
  for (const k of ACTIONS) if (action && typeof action === 'object' && k in action) return k;
  throw new Error('unknown action');
}
const isInt = (x) => Number.isInteger(x);
const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
const signingBytes = (op) => { const { sig, ...rest } = op; return te.encode(canonical(rest)); };

function checkAction(kind, body) {
  if (kind === 'genesis') {
    if (!(body && typeof body === 'object' && !Array.isArray(body) && (body.title === undefined || typeof body.title === 'string')
          && (body.open === undefined || typeof body.open === 'boolean')))
      return [false, 'genesis body must be an object with optional string title and bool open'];
  } else if (kind === 'set' || kind === 'del') {
    if (typeof body !== 'string') return [false, `${kind} key must be a string`];
  } else if (kind === 'grant') {
    if (!(body && typeof body === 'object' && sameSet(Object.keys(body), ['to', 'pubkey', 'role'])
          && ROLES.includes(body.role) && typeof body.to === 'string')) return [false, 'grant needs to, pubkey, role'];
    let pk; try { pk = b64d(body.pubkey); } catch { return [false, 'grant.pubkey is not base64']; }
    if (identityId(pk) !== body.to) return [false, 'grant.to does not match grant.pubkey'];
  } else if (kind === 'revoke') {
    if (!(body && typeof body === 'object' && sameSet(Object.keys(body), ['id']) && typeof body.id === 'string'))
      return [false, 'revoke needs id'];
  }
  return [true, 'ok'];
}

// Structural and cryptographic checks on one op, in isolation. Mirrors ops.verify_op.
export function verifyOp(op) {
  if (!op || typeof op !== 'object' || Array.isArray(op)) return [false, 'not an object'];
  const required = ['v', 'type', 'doc', 'author', 'pubkey', 'seq', 'lamport', 'deps', 'action', 'sig'];
  if (!sameSet(Object.keys(op), required)) return [false, `fields must be exactly ${JSON.stringify([...required].sort())}`];
  if (op.v !== VERSION || op.type !== 'op') return [false, 'bad version or type'];
  if (!(isInt(op.seq) && op.seq >= 1)) return [false, 'seq must be a positive integer'];
  if (!(isInt(op.lamport) && op.lamport >= 1)) return [false, 'lamport must be a positive integer'];
  const deps = op.deps;
  const sortedUnique = Array.isArray(deps) && JSON.stringify(deps) === JSON.stringify([...new Set(deps)].sort());
  if (!sortedUnique || !deps.every(isHash)) return [false, 'deps must be a sorted list of unique hashes'];
  const action = op.action;
  const kinds = ACTIONS.filter((k) => action && typeof action === 'object' && k in action);
  if (kinds.length !== 1) return [false, 'action must have exactly one known kind'];
  const kind = kinds[0];
  const allowed = kind === 'set' ? [kind, 'value'] : [kind];
  if (!sameSet(Object.keys(action), allowed)) return [false, `action keys must be exactly ${JSON.stringify(allowed.sort())}`];
  const isGenesis = kind === 'genesis';
  if (isGenesis !== (op.doc === null)) return [false, 'genesis iff doc is null'];
  if (isGenesis && (deps.length || op.lamport !== 1 || op.seq !== 1)) return [false, 'genesis must have no deps, lamport 1, seq 1'];
  if (!isGenesis && (!deps.length || !isHash(op.doc))) return [false, 'non-genesis op must have deps and a doc id'];
  const [ok, why] = checkAction(kind, action[kind]);
  if (!ok) return [false, why];
  let pk, sig;
  try { pk = b64d(op.pubkey); sig = b64d(op.sig); } catch { return [false, 'pubkey or sig is not base64']; }
  if (identityId(pk) !== op.author) return [false, 'author does not match pubkey'];
  let data;
  try { data = signingBytes(op); } catch (e) { return [false, String(e.message)]; }
  if (!verifySig(pk, data, sig)) return [false, 'signature invalid'];
  return [true, 'ok'];
}

// ---- document ------------------------------------------------------------

const byLamportThenHash = (ops) => (a, b) => (ops.get(a).lamport - ops.get(b).lamport) || (a < b ? -1 : a > b ? 1 : 0);

export class Document {
  constructor(id, ops) {           // ops: Map<hash, op|null>
    this.id = id;
    this.ops = ops;
    this.valid = new Map();
    this.order = [];
    this.report = { seen: ops.size, valid: 0, rejected: [] };
    this.owner = null;
    this.open = false;              // open thread: no capability table, own keys only
    this._ancestors = new Map();
    this._authorized = new Map();
    this._verify();
  }
  _reject(h, why) { this.report.rejected.push([h, why]); }

  _verify() {
    const structural = new Map();
    for (const [h, op] of this.ops) {
      if (op === null) { this._reject(h, 'unreadable or hash mismatch'); continue; }
      let hh; try { hh = hashObj(op); } catch { hh = null; }
      if (hh !== h) { this._reject(h, 'hash does not match content'); continue; }
      const [ok, why] = verifyOp(op);
      if (!ok) { this._reject(h, why); continue; }
      const isGenesis = actionKind(op.action) === 'genesis';
      if (isGenesis && h !== this.id) { this._reject(h, 'foreign genesis'); continue; }
      if (!isGenesis && op.doc !== this.id) { this._reject(h, 'belongs to another document'); continue; }
      structural.set(h, op);
    }
    if (!structural.has(this.id)) { this._reject(this.id, 'genesis missing'); return; }
    this.owner = structural.get(this.id).author;
    this.open = structural.get(this.id).action.genesis.open === true;

    const kept = new Map();
    for (const h of [...structural.keys()].sort(byLamportThenHash(structural))) {
      const op = structural.get(h);
      if (h === this.id) { kept.set(h, op); continue; }
      const missing = op.deps.filter((d) => !kept.has(d));
      if (missing.length) { this._reject(h, `missing or invalid dependency ${missing[0]}`); continue; }
      if (op.deps.some((d) => kept.get(d).lamport >= op.lamport)) { this._reject(h, 'lamport not greater than dependencies'); continue; }
      kept.set(h, op);
    }
    this._kept = kept;
    for (const h of [...kept.keys()].sort(byLamportThenHash(kept))) {
      if (this._authorizedAt(h)) { this.valid.set(h, kept.get(h)); this.order.push(h); }
      else this._reject(h, 'unauthorized');
    }
    this.report.valid = this.valid.size;
  }

  _ancestorsOf(h) {
    if (this._ancestors.has(h)) return this._ancestors.get(h);
    const acc = new Set();
    for (const d of this._kept.get(h).deps) { acc.add(d); for (const a of this._ancestorsOf(d)) acc.add(a); }
    this._ancestors.set(h, acc);
    return acc;
  }

  _rolesAt(h) {
    const roles = new Map([[this.owner, 'admin']]);
    const past = [...this._ancestorsOf(h)].sort(byLamportThenHash(this._kept));
    for (const a of past) {
      const op = this._kept.get(a);
      const kind = actionKind(op.action);
      if ((kind !== 'grant' && kind !== 'revoke') || !this._authorizedAt(a)) continue;
      const body = op.action[kind];
      if (kind === 'grant') roles.set(body.to, body.role); else roles.delete(body.id);
    }
    return roles;
  }

  _authorizedAt(h) {
    if (this._authorized.has(h)) return this._authorized.get(h);
    const op = this._kept.get(h);
    const kind = actionKind(op.action);
    let ok;
    if (kind === 'genesis') ok = h === this.id;
    else if (this.open) {
      // Nobody owns the thread; everybody owns their own words.
      const key = op.action[kind];
      ok = (kind === 'set' || kind === 'del') && (key === op.author || key.startsWith(op.author + '/'));
    } else {
      const role = this._rolesAt(h).get(op.author);
      ok = (kind === 'set' || kind === 'del') ? (role === 'write' || role === 'admin') : role === 'admin';
    }
    this._authorized.set(h, ok);
    return ok;
  }

  _winners() {
    const winners = new Map();
    for (const h of this.order) {
      const op = this.valid.get(h);
      const kind = actionKind(op.action);
      if (kind !== 'set' && kind !== 'del') continue;
      const key = op.action[kind];
      const rank = [op.lamport, op.author, h];
      const cur = winners.get(key);
      const greater = !cur || rank[0] > cur.rank[0] || (rank[0] === cur.rank[0] && (rank[1] > cur.rank[1] || (rank[1] === cur.rank[1] && rank[2] > cur.rank[2])));
      if (greater) winners.set(key, { rank, op, h });
    }
    return winners;
  }
  state() {
    const out = {};
    for (const key of [...this._winners().keys()].sort(cmpCodePoints)) {
      const w = this._winners().get(key);
      if ('set' in w.op.action) out[key] = w.op.action.value;
    }
    return out;
  }
  provenance() {
    const out = {};
    for (const [key, w] of this._winners()) if ('set' in w.op.action) out[key] = { author: w.op.author, op: w.h, lamport: w.op.lamport };
    return out;
  }
  roles() {
    if (this.open) return {};
    const roles = { [this.owner]: 'admin' };
    for (const h of this.order) {
      const op = this.valid.get(h);
      const kind = actionKind(op.action);
      if (kind === 'grant') roles[op.action.grant.to] = op.action.grant.role;
      else if (kind === 'revoke') delete roles[op.action.revoke.id];
    }
    return roles;
  }
  frontier() {
    const depended = new Set();
    for (const h of this.order) for (const d of this.valid.get(h).deps) depended.add(d);
    return this.order.filter((h) => !depended.has(h)).sort();
  }
  title() { const g = this.valid.get(this.id); return g ? (g.action.genesis.title || '') : ''; }
  summary() {
    return { id: this.id, title: this.title(), open: this.open, state: this.state(), provenance: this.provenance(),
             roles: this.roles(), report: this.report };
  }
}

// ---- loading from a relay ------------------------------------------------

// fetchBytes(relativePath) -> Uint8Array, or throws; null for "not found".
export async function loadDocument(docId, fetchBytes) {
  const index = await fetchBytes(`docs/${hexOf(docId)}`);
  const hashes = index === null ? [] : td.decode(index).split('\n').map((s) => s.trim()).filter(isHash);
  const ops = new Map();
  await Promise.all(hashes.map(async (h) => {
    let op = null;
    try {
      const bytes = await fetchBytes(`blobs/${hexOf(h)}`);
      if (bytes !== null && hashBytes(bytes) === h) op = JSON.parse(td.decode(bytes));
    } catch { op = null; }
    ops.set(h, op);
  }));
  return new Document(docId, ops);
}

export function parseLoomHref(href) {
  const i = href.lastIndexOf('/docs/');
  const rest = i < 0 ? '' : href.slice(i + 6);
  if (i < 0 || !isHash(PREFIX + rest)) throw new Error(`not a loom back-link: ${href}`);
  return { base: href.slice(0, i), docId: PREFIX + rest };
}

// ---- in a page -----------------------------------------------------------

const same = (a, b) => canonical(a) === canonical(b);

export async function verifyPage(doc = globalThis.document) {
  const link = doc.querySelector('link[rel~="loom"]');
  if (!link) return;
  const banner = doc.getElementById('loom-verify') || doc.body.insertBefore(doc.createElement('div'), doc.body.firstChild);
  banner.id = 'loom-verify';
  const show = (cls, text) => { banner.className = 'loom-' + cls; banner.textContent = text; };
  show('pending', 'Verifying the signed document in your browser…');
  try {
    const { base, docId } = parseLoomHref(new URL(link.getAttribute('href'), doc.baseURI).href);
    const fetchBytes = async (rel) => {
      const r = await fetch(`${base}/${rel}`, { cache: 'no-store' });
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`${r.status} fetching ${rel}`);
      return new Uint8Array(await r.arrayBuffer());
    };
    const d = await loadDocument(docId, fetchBytes);
    const r = d.report;
    const counts = `${r.seen} ops fetched, ${r.valid} valid, ${r.rejected.length} rejected`;
    if (d.owner === null) return show('bad', `Not a verifiable document: genesis missing. ${counts}.`);
    const embedded = doc.getElementById('loom');
    const page = embedded ? JSON.parse(embedded.textContent) : null;
    if (page && (!same(page.state, d.state()) || !same(page.provenance, d.provenance())))
      return show('bad', `This page does NOT match the signed document. ${counts}. Verified state: ${JSON.stringify(d.state())}`);
    show('ok', `Verified in your browser: every field below is signed by its author (ML-DSA-44). ${counts}.`);
  } catch (e) {
    show('unknown', `Could not verify here (${e.message}). Run: loom verify <this page's URL>`);
  }
}

// ---- under node: node verify.js <relay dir> <doc id> ---------------------

const isNode = typeof process !== 'undefined' && process.versions?.node;
if (isNode && process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const [dir, docId] = process.argv.slice(2);
  if (!dir || !isHash(docId)) { console.error('usage: node verify.js <relay dir> <sha256:doc id>'); process.exit(2); }
  const fetchBytes = async (rel) => {
    try { return new Uint8Array(await fs.readFile(path.join(dir, rel))); }
    catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  };
  const d = await loadDocument(docId, fetchBytes);
  console.log(JSON.stringify(d.summary(), null, 2));
  process.exit(d.owner === null ? 1 : 0);
} else if (typeof globalThis.document !== 'undefined') {
  if (globalThis.document.readyState === 'loading') globalThis.document.addEventListener('DOMContentLoaded', () => verifyPage());
  else verifyPage();
}
