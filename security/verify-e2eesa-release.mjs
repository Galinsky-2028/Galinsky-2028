// Verifies the exact published E2EESA source, not product certification.
// An externally provided, authenticated standard checkout is mandatory in CI.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const allowed = new Set(['allowed', 'recommended']);
const check = (condition, message) => {
  if (!condition) throw new Error('E2EESA 1.0 binding: ' + message);
};
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function verifyManifest(standardRoot, manifest, expectedDigest) {
  check(manifest?.schema_version === '0.1' && manifest.release_version === '1.0.0',
    'wrong published standard version');
  check(manifest.external_certification === 'not-claimed' &&
    manifest.external_review_status === 'pending',
    'independent review must be represented accurately');
  const files = manifest.files;
  check(Array.isArray(files) && files.length === manifest.file_count && files.length > 0,
    'invalid source manifest cardinality');
  let previous = '';
  const normalized = [];
  for (const file of files) {
    const path = file?.path;
    check(typeof path === 'string' && /^[\x20-\x7e]+$/.test(path) &&
      !isAbsolute(path) && !path.includes('\\') &&
      path.split('/').every((part) => part !== '' && part !== '.' && part !== '..') &&
      path > previous,
      'duplicate, unsorted or unsafe source manifest path');
    previous = path;
    check(Number.isSafeInteger(file.size) && file.size >= 0 &&
      /^[a-f0-9]{40}$/.test(file.git_blob_sha), 'invalid blob metadata: ' + path);
    const location = resolve(standardRoot, path);
    check(location.startsWith(resolve(standardRoot) + sep), 'source path escapes checkout');
    check(existsSync(location) && lstatSync(location).isFile(),
      'source file missing or not a regular file: ' + path);
    const bytes = readFileSync(location);
    check(bytes.length === file.size, 'source size changed: ' + path);
    const sha = createHash('sha1')
      .update(Buffer.from('blob ' + bytes.length + '\0'))
      .update(bytes).digest('hex');
    check(sha === file.git_blob_sha, 'source bytes changed: ' + path);
    normalized.push({ git_blob_sha: sha, path, size: bytes.length });
  }
  const digest = 'sha256:' + sha256(JSON.stringify(normalized));
  check(digest === manifest.tree_digest && digest === expectedDigest,
    'source manifest digest mismatch');
  return { files: normalized.length, treeDigest: digest };
}

export function verifyProfiles(catalog, lock) {
  check(catalog?.standard_version === lock.standardVersion &&
    Array.isArray(catalog.profiles), 'wrong or malformed E2EESA catalog');
  check(Array.isArray(lock.profileRefs) && lock.profileRefs.length >= 6 &&
    lock.profileRefs.length === new Set(lock.profileRefs).size,
    'duplicate or empty selected profiles');
  const matched = [];
  for (const ref of lock.profileRefs) {
    check(typeof ref === 'string' && /^[a-z0-9-]+@\d+\.\d+\.\d+$/.test(ref),
      'profile reference must be exact id@version');
    const [id, version] = ref.split('@');
    const profiles = catalog.profiles.filter((p) =>
      p.profile_id === id && p.profile_version === version);
    check(profiles.length === 1 && allowed.has(profiles[0].status),
      'required profile is not currently approved: ' + ref);
    matched.push(ref);
  }
  check(matched.includes(lock.mlsProfile) &&
    lock.mlsProfile === 'group-mls-rfc9420@0.1.0',
    'MLS profile must remain explicitly pinned');
  return matched;
}

export function verifyProjectBindings(projectRoot, lock) {
  const status = readJson(join(projectRoot, 'security/e2eesa-status.json'));
  const inventory = readJson(join(projectRoot, 'security/e2eesa-inventory.json'));
  const flow = readJson(join(projectRoot, 'security/source-flow-contract.json'));
  for (const source of [status.standard, inventory.standardBasis, flow.standard]) {
    check(source?.repository ===
      'neophilism/End-To-End-Everywhere-Security-Architecture-Standard' &&
      source.canonicalRepository === lock.standardRepository &&
      source.commit === lock.standardCommit &&
      source.basis === 'production' &&
      source.version === lock.standardVersion &&
      source.releaseTreeDigest === lock.standardTreeDigest,
      'status, inventory and flow source locks disagree');
  }
  check(status.canonicalRepository === 'Galinsky-2028/Galinsky-2028' &&
    inventory.canonicalRepository === status.canonicalRepository &&
    flow.canonicalRepository === status.canonicalRepository,
    'project identity mismatches current GitHub repository');
  check(status.standard.releaseManifest === lock.standardManifest &&
    status.standard.releaseLock === 'security/e2eesa-release-lock.json',
    'published source evidence missing from status');
  check(inventory.coverageComplete === false && inventory.reviewed === false &&
    inventory.standardBasis.conformanceArtifactProduced === false &&
    flow.productionE2eeClaim === false && flow.certificationClaim === false &&
    flow.runtimeCoverageVerified === false &&
    status.implementation.complete === false &&
    status.testing.complete === false && status.independentReview.complete === false,
    'product compliance is falsely asserted without source/build/runtime proof');
  check(lock.scope === 'source-profile-compatibility-only' &&
    lock.productConformanceClaim === false &&
    lock.independentlyAuthenticatedReview === 'pending' &&
    lock.protectedRuntime.startsWith('disabled-'),
    'invalid claims or premature protected-runtime activation');
  const module = readFileSync(join(projectRoot, 'packages/core/protected-mls.mjs'), 'utf8');
  check(module.includes("export const MLS_PROFILE = '" + lock.mlsProfile + "';") &&
    module.includes("export const MLS_SUITE = '" + lock.mlsSuite + "';") &&
    module.includes('ts-mls@' + lock.mlsPackageVersion),
    'actual client source differs from reviewed protocol bindings');
  const pkg = readJson(join(projectRoot, 'package.json'));
  const packageLock = readJson(join(projectRoot, 'package-lock.json'));
  check(pkg.dependencies?.[lock.mlsPackage] === lock.mlsPackageVersion &&
    packageLock.packages?.['node_modules/' + lock.mlsPackage]?.version ===
      lock.mlsPackageVersion &&
    typeof packageLock.packages['node_modules/' + lock.mlsPackage].integrity === 'string',
    'installed MLS package is not pinned to the reviewed library');
  const config = readFileSync(join(projectRoot, 'apps/api/src/config.mjs'), 'utf8');
  check(config.includes("assert(!protectedContent,'protected_unavailable'"),
    'protected intake fail-closed activation guard was removed');
  return { project: status.canonicalRepository, runtime: 'protected-intake-blocked' };
}

export function verifyRelease({ projectRoot, standardRoot, observedCommit }) {
  const lock = readJson(join(projectRoot, 'security/e2eesa-release-lock.json'));
  check(lock.schemaVersion === 1 &&
    lock.standardRepository ===
      'Galinsky-Labs/End-To-End-Everywhere-Security-Architecture-Standard' &&
    /^[a-f0-9]{40}$/.test(lock.standardCommit) &&
    lock.standardCommit === observedCommit &&
    lock.standardVersion === '1.0.0' &&
    /^sha256:[a-f0-9]{64}$/.test(lock.standardTreeDigest) &&
    lock.standardManifest === 'release/1.0.0-manifest.json',
    'exact published source ref is not locked');
  check(readFileSync(join(standardRoot, 'VERSION'), 'utf8').trim() === lock.standardVersion,
    'checked out upstream VERSION is incorrect');
  const manifest = readJson(join(standardRoot, lock.standardManifest));
  const source = verifyManifest(standardRoot, manifest, lock.standardTreeDigest);
  const profiles = verifyProfiles(readJson(join(standardRoot, 'profiles/catalog.json')), lock);
  const product = verifyProjectBindings(projectRoot, lock);
  return { ...source, profiles: profiles.length, ...product };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    check(process.argv.length === 3, 'supply an exact checked-out standard directory');
    const standardRoot = resolve(process.argv[2]);
    check(existsSync(join(standardRoot, '.git')), 'upstream checkout required');
    const observedCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: standardRoot, encoding: 'utf8',
    }).trim();
    const result = verifyRelease({ projectRoot: root, standardRoot, observedCommit });
    console.log('Verified E2EESA 1.0 source/profile compatibility only:', JSON.stringify(result));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
