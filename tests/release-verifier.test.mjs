import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Fastify from 'fastify';
import { registerPortal } from '../apps/api/src/static.mjs';
import { releaseIntegrity } from '../apps/portal/release-integrity.mjs';
import { buildWebClosure } from '../security/web-release-closure.mjs';
import {
  canonicalJson,
  publicKeyId,
  signEd25519,
  leafHash,
  merkleRoot,
  inclusionProof,
  checkpointBody,
  releaseStatement,
  validateTrustPolicy,
  RELEASE_EVIDENCE_SCHEMA,
} from '../packages/core/release-authenticity.mjs';
import { verifyPublishedRelease, EVIDENCE_PATH } from '../tools/release-verifier/verify-published-release.mjs';

const COMMIT = 'b'.repeat(40),
  ORIGIN = 'https://portal.example.test';
const keypair = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  return { privateKey, entry: { keyId: publicKeyId(spki), publicKey: spki } };
};
const release = keypair(),
  log = keypair(),
  w1 = keypair(),
  w2 = keypair();
const trust = validateTrustPolicy({
  schemaVersion: 1,
  project: 'Galinsky-2028/Galinsky-2028',
  note: 'verifier test',
  releaseKeys: [release.entry],
  logOrigin: 'log.example/g28',
  logKey: log.entry,
  witnessKeys: [w1.entry, w2.entry],
  witnessQuorum: 2,
  minimumSequence: 1,
});

async function published(t) {
  const root = await mkdtemp(join(tmpdir(), 'g28-verifier-'));
  const html =
    '<!doctype html><html><head><meta charset="UTF-8"><title>portal</title>  <script type="module" crossorigin src="/assets/index-a.js"></script>\n  <link rel="stylesheet" crossorigin href="/assets/index-c.css">\n</head><body></body></html>';
  const bundle = {
    'assets/index-a.js': { type: 'chunk', fileName: 'assets/index-a.js', code: 'import("./lazy-d.js")' },
    'assets/lazy-d.js': { type: 'chunk', fileName: 'assets/lazy-d.js', code: 'export const lazy=1' },
    'assets/index-c.css': { type: 'asset', fileName: 'assets/index-c.css', source: 'body{}' },
    'index.html': { type: 'asset', fileName: 'index.html', source: html },
  };
  releaseIntegrity().generateBundle.handler({}, bundle);
  await mkdir(join(root, 'dist/portal/assets'), { recursive: true });
  for (const [name, f] of Object.entries(bundle))
    await writeFile(join(root, 'dist/portal', name), f.type === 'chunk' ? f.code : f.source);
  const closure = buildWebClosure(root, COMMIT, ['dist/portal']);
  const statement = releaseStatement({
    closure,
    sequence: 2,
    issuedAt: '2026-11-15T12:00:00.000Z',
    transport: { origin: ORIGIN, tls13Only: true, fallbackRefused: true, observedAt: '2026-11-15T12:00:00.000Z' },
  });
  const leaves = [leafHash(Buffer.from('earlier')), leafHash(Buffer.from(canonicalJson(statement))), leafHash(Buffer.from('later'))];
  const body = checkpointBody({ origin: 'log.example/g28', treeSize: 3, rootHash: merkleRoot(leaves) });
  const evidence = {
    schema: RELEASE_EVIDENCE_SCHEMA,
    statement,
    closure,
    releaseSignature: { keyId: release.entry.keyId, signature: signEd25519(release.privateKey, canonicalJson(statement)) },
    inclusion: { index: 1, proof: inclusionProof(leaves, 1).map((b) => b.toString('base64')) },
    checkpoint: {
      body,
      signatures: [log, w1, w2].map((k) => ({ keyId: k.entry.keyId, signature: signEd25519(k.privateKey, body) })),
    },
  };
  await writeFile(join(root, 'dist/release-evidence.json'), JSON.stringify(evidence));
  const app = Fastify();
  registerPortal(app, ORIGIN, join(root, 'dist/portal'));
  const tamper = new Map();
  const fetchImpl = async (url, init) => {
    const u = new URL(url);
    assert.equal(u.origin, ORIGIN);
    const r = await app.inject({ url: u.pathname, headers: init.headers });
    const payload = tamper.has(u.pathname) ? tamper.get(u.pathname) : r.rawPayload;
    return new Response(payload, { status: r.statusCode });
  };
  t.after(async () => {
    await app.close();
    await rm(root, { recursive: true, force: true });
  });
  return { root, evidence, fetchImpl, tamper, app };
}
const NOW = Date.parse('2026-11-16T00:00:00Z');

test('an honest published release verifies from the downloaded bytes alone', async (t) => {
  const { fetchImpl, app } = await published(t);
  const served = await app.inject({ url: EVIDENCE_PATH });
  assert.equal(served.statusCode, 200);
  const result = await verifyPublishedRelease({ origin: ORIGIN, trust, fetchImpl, now: NOW });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.files, 4);
  assert.equal(result.witnesses.length, 2);
});

test('a served chunk, page or evidence that differs from the witnessed release is rejected', async (t) => {
  const { fetchImpl, tamper, evidence } = await published(t);
  const check = async () => verifyPublishedRelease({ origin: ORIGIN, trust, fetchImpl, now: NOW });
  tamper.set('/assets/lazy-d.js', 'export const lazy=2');
  assert.match((await check()).missing.join(' '), /installed bytes differ/);
  tamper.clear();
  tamper.set('/', '<!doctype html><html><head><meta charset="UTF-8"></head></html>');
  assert.equal((await check()).ok, false);
  tamper.clear();
  // A server that re-signs with its own key is not trusted.
  const rogue = keypair();
  tamper.set(
    EVIDENCE_PATH,
    JSON.stringify({ ...evidence, releaseSignature: { keyId: rogue.entry.keyId, signature: signEd25519(rogue.privateKey, canonicalJson(evidence.statement)) } }),
  );
  assert.match((await check()).missing.join(' '), /not signed by a pinned release key/);
  // Dropping a witness cosignature fails the quorum.
  tamper.set(EVIDENCE_PATH, JSON.stringify({ ...evidence, checkpoint: { ...evidence.checkpoint, signatures: evidence.checkpoint.signatures.slice(0, 2) } }));
  assert.match((await check()).missing.join(' '), /witness cosignatures/);
  tamper.set(EVIDENCE_PATH, JSON.stringify({ ...evidence, closure: { ...evidence.closure, files: [{ path: 'dist/portal/../../etc/passwd' }] } }));
  assert.match((await check()).missing.join(' '), /unsafe path/);
  tamper.clear();
  assert.equal((await verifyPublishedRelease({ origin: 'http://portal.example.test', trust, fetchImpl, now: NOW })).ok, false);
  assert.match(
    (await verifyPublishedRelease({ origin: ORIGIN, trust: { ...trust, minimumSequence: 3 }, fetchImpl, now: NOW })).missing.join(' '),
    /anti-rollback/,
  );
});

test('the portal answers 404 when no evidence is published', async () => {
  const app = Fastify();
  registerPortal(app, ORIGIN, join(tmpdir(), 'g28-no-such-portal'), join(tmpdir(), 'g28-no-such-evidence.json'));
  const r = await app.inject({ url: EVIDENCE_PATH });
  assert.equal(r.statusCode, 404);
  await app.close();
});
