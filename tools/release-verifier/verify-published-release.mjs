#!/usr/bin/env node
// Outside verifier for protected-reporting releases.
//
// Run it from your OWN reviewed checkout of this repository, with your OWN copy of the
// trust policy. It does not trust the server: it downloads the portal exactly as a browser
// would, hashes every published byte, and accepts the release only if:
//   - the downloaded files reproduce the closure digest in a release statement signed by a
//     pinned release key (with the anti-rollback floor);
//   - that statement is included in the pinned transparency log at a checkpoint cosigned by
//     a quorum of pinned independent witnesses;
//   - the signed TLS 1.3 observation names this origin and is fresh; and
//   - the page's own integrity table (import map + SRI) matches the downloaded bytes, so the
//     browser would refuse anything else.
// The server only supplies untrusted bytes and the evidence document; every check is local.
//
//   node tools/release-verifier/verify-published-release.mjs https://portal.example \
//     --trust path/to/your/release-trust.json [--user preview --password-env PREVIEW_PASSWORD]
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyReleaseEvidence, validateTrustPolicy, canonicalJson } from '../../packages/core/release-authenticity.mjs';

export const EVIDENCE_PATH = '/.well-known/g28-release.json';
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const sri = (b) => 'sha384-' + createHash('sha384').update(b).digest('base64');

export async function verifyPublishedRelease({ origin, trust, headers = {}, fetchImpl = fetch, now = Date.now() }) {
  const base = new URL(origin);
  if (base.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(base.hostname))
    return { ok: false, missing: ['the portal origin must use HTTPS'] };
  const get = async (path) => {
    const r = await fetchImpl(new URL(path, base), { headers, redirect: 'error' });
    if (!r.ok) throw Error(`${path} returned HTTP ${r.status}`);
    return Buffer.from(await r.arrayBuffer());
  };
  try {
    validateTrustPolicy(trust);
    const evidence = JSON.parse((await get(EVIDENCE_PATH)).toString('utf8'));
    const manifest = evidence.closure;
    if (!manifest || !Array.isArray(manifest.files) || canonicalJson(manifest.buildRoots) !== '["dist/portal"]')
      return { ok: false, missing: ['the evidence does not list the published portal files'] };
    // Re-download every listed file and rebuild the closure from what was actually served.
    const files = [];
    for (const f of manifest.files) {
      if (typeof f.path !== 'string' || !/^dist\/portal\/[A-Za-z0-9._/-]+$/.test(f.path) || f.path.includes('..'))
        return { ok: false, missing: ['the evidence lists an unsafe path'] };
      const rel = f.path.slice('dist/portal'.length);
      const bytes = await get(rel === '/index.html' ? '/' : rel);
      files.push({ path: f.path, size: bytes.length, sha256: sha256(bytes), bytes });
    }
    files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    const common = {
      schemaVersion: 1,
      standardVersion: '1.0.0',
      project: 'Galinsky-2028/Galinsky-2028',
      sourceCommit: evidence.statement?.sourceCommit,
      buildRoots: ['dist/portal'],
      fileCount: files.length,
      files: files.map(({ path, size, sha256: h }) => ({ path, size, sha256: h })),
    };
    const observed = { ...common, closureDigest: 'sha256:' + sha256(canonicalJson(common)) };
    const result = verifyReleaseEvidence({ evidence, trust, installedClosure: observed, publicOrigin: base.origin, now });
    if (!result.ok) return result;
    // The served document must bind every script and stylesheet it loads to these bytes.
    const html = files.find((f) => f.path === 'dist/portal/index.html')?.bytes.toString('utf8');
    if (!html) return { ok: false, missing: ['the release has no index.html'] };
    const map = html.match(/<script type="importmap">([\s\S]*?)<\/script>/);
    const integrity = map ? JSON.parse(map[1]).integrity || {} : {};
    const byUrl = new Map(files.map((f) => [f.path.slice('dist/portal'.length), f.bytes]));
    const js = [...byUrl.keys()].filter((u) => u.endsWith('.js'));
    for (const u of js)
      if (integrity[u] !== sri(byUrl.get(u))) return { ok: false, missing: [`${u} is not bound by the page's integrity table`] };
    for (const [, attr, u, hash] of html.matchAll(/\s(src|href)="(\/assets\/[^"]+)" integrity="([^"]+)"/g))
      if (!byUrl.has(u) || sri(byUrl.get(u)) !== hash) return { ok: false, missing: [`${attr} ${u} has a mismatched integrity value`] };
    return { ...result, files: files.length, origin: base.origin };
  } catch (error) {
    return { ok: false, missing: [String(error.message)] };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2),
    flag = (n) => {
      const i = args.indexOf(n);
      return i >= 0 ? args[i + 1] : undefined;
    };
  const origin = args[0],
    trustPath = flag('--trust');
  if (!origin || !trustPath) {
    console.error('Use: verify-published-release.mjs <https origin> --trust <your release-trust.json> [--user u --password-env VAR]');
    process.exit(2);
  }
  const headers = {};
  if (flag('--user'))
    headers.authorization = 'Basic ' + Buffer.from(flag('--user') + ':' + (process.env[flag('--password-env') || ''] || '')).toString('base64');
  const result = await verifyPublishedRelease({ origin, trust: JSON.parse(readFileSync(trustPath, 'utf8')), headers });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
}
