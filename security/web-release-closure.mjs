// Deterministic SHA-256 inventory for EVERY shipped web/portal file.
// An unsigned CI artifact, never an authenticated release or E2EESA certificate.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  existsSync, lstatSync, readFileSync, readdirSync, mkdirSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT = 'Galinsky-2028/Galinsky-2028';
export const WEB_BUILD_ROOTS = ['dist/portal', 'dist/web'];
const check = (condition, message) => {
  if (!condition) throw Error('Web release closure: ' + message);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
function canon(value) {
  if (Array.isArray(value)) return '[' + value.map(canon).join(',') + ']';
  if (value && typeof value === 'object')
    return '{' + Object.keys(value).sort()
      .map((key) => JSON.stringify(key) + ':' + canon(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function checkFilePath(path) {
  check(typeof path === 'string' && /^[\x20-\x7e]+$/.test(path) &&
    !path.startsWith('/') && !path.includes('\\') &&
    path.split('/').every((part) => part && part !== '.' && part !== '..'),
    'unsafe build artifact path');
}
export function discoverBuildFiles(baseRoot, roots = WEB_BUILD_ROOTS) {
  check(Array.isArray(roots) && roots.length > 0 &&
    roots.length === new Set(roots).size, 'build root list must be explicit');
  const results = [];
  function scan(root, relativePath) {
    const here = resolve(baseRoot, relativePath);
    check(here.startsWith(resolve(baseRoot) + sep),
      'build artifact escapes checkout');
    const stat = lstatSync(here);
    check(!stat.isSymbolicLink(), 'symbolic build artifact cannot be trusted: ' + relativePath);
    if (stat.isDirectory()) {
      for (const name of readdirSync(here).sort()) {
        const child = relativePath + '/' + name;
        checkFilePath(child);
        scan(root, child);
      }
    } else {
      check(stat.isFile(), 'non-file build artifact: ' + relativePath);
      const bytes = readFileSync(here);
      results.push({
        path: relativePath,
        size: bytes.length,
        sha256: sha256(bytes),
      });
    }
  }
  for (const name of roots) {
    checkFilePath(name);
    const location = resolve(baseRoot, name);
    check(existsSync(location) && lstatSync(location).isDirectory() &&
      !lstatSync(location).isSymbolicLink(), 'missing build output: ' + name);
    scan(name, name);
    check(results.some((x) => x.path.startsWith(name + '/')),
      'empty build output: ' + name);
  }
  return results.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
export function buildWebClosure(baseRoot, sourceCommit, roots = WEB_BUILD_ROOTS) {
  check(/^[a-f0-9]{40}$/.test(sourceCommit), 'immutable source commit required');
  const files = discoverBuildFiles(baseRoot, roots);
  check(files.length > 0, 'no compiled artifacts');
  const common = {
    schemaVersion: 1,
    standardVersion: '1.0.0',
    project: PROJECT,
    sourceCommit,
    buildRoots: [...roots],
    fileCount: files.length,
    files,
  };
  return { ...common, closureDigest: 'sha256:' + sha256(canon(common)) };
}
export function verifyWebClosure(baseRoot, manifest) {
  check(manifest && manifest.schemaVersion === 1 &&
    manifest.standardVersion === '1.0.0' && manifest.project === PROJECT &&
    /^[a-f0-9]{40}$/.test(manifest.sourceCommit), 'invalid manifest identity');
  const expected = buildWebClosure(baseRoot, manifest.sourceCommit, manifest.buildRoots);
  check(canon(manifest) === canon(expected),
    'compiled artifact was changed, added, removed or reordered');
  return { fileCount: expected.fileCount, digest: expected.closureDigest };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    check(process.argv.length === 3, 'provide an output JSON path');
    const cwd = process.cwd();
    const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd, encoding: 'utf8',
    }).trim();
    if (process.env.GITHUB_SHA)
      check(process.env.GITHUB_SHA === commit, 'GitHub checkout SHA differs from assessed build');
    const manifest = buildWebClosure(cwd, commit);
    const output = resolve(process.argv[2]);
    check(output.startsWith(cwd + sep) &&
      !WEB_BUILD_ROOTS.some((name) => output.startsWith(resolve(cwd, name) + sep)),
      'manifest must be outside the compiled artifact roots');
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, JSON.stringify(manifest, null, 2) + '\n', {
      flag: 'w', mode: 0o600,
    });
    const report = verifyWebClosure(cwd, JSON.parse(readFileSync(output, 'utf8')));
    console.log('Unsigned, source-bound web closure manifest created:', JSON.stringify(report));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
