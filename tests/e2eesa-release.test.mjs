import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  verifyManifest,
  verifyProfiles,
  verifyProjectBindings,
} from '../security/verify-e2eesa-release.mjs';
import { loadConfig } from '../apps/api/src/config.mjs';

const lock = JSON.parse(readFileSync('security/e2eesa-release-lock.json', 'utf8'));
const sha = (content) => createHash('sha256').update(content).digest('hex');
const manifest = (root, values) => {
  const files = Object.entries(values).sort(([a], [b]) => a.localeCompare(b)).map(([path, content]) => {
    const location = join(root, path);
    mkdirSync(join(location, '..'), { recursive: true });
    const bytes = Buffer.from(content);
    writeFileSync(location, bytes);
    return {
      path,
      size: bytes.length,
      git_blob_sha: createHash('sha1')
        .update(Buffer.from('blob ' + bytes.length + '\0'))
        .update(bytes).digest('hex'),
    };
  });
  const treeDigest = 'sha256:' + sha(JSON.stringify(
    files.map(({ git_blob_sha, path, size }) => ({ git_blob_sha, path, size })),
  ));
  return {
    schema_version: '0.1',
    release_version: '1.0.0',
    external_certification: 'not-claimed',
    external_review_status: 'pending',
    file_count: files.length,
    files,
    tree_digest: treeDigest,
  };
};

test('a release must be complete, ordered and cryptographically bound to exact file bytes', () => {
  const root = mkdtempSync(join(tmpdir(), 'g28-e2eesa-'));
  try {
    const source = manifest(root, {
      'profiles/catalog.json': '{"profile":[]}',
      'release/notes.md': 'stable standard, not a product certificate',
    });
    assert.deepEqual(verifyManifest(root, source, source.tree_digest), {
      files: 2,
      treeDigest: source.tree_digest,
    });
    assert.throws(() => verifyManifest(root, source, 'sha256:' + '0'.repeat(64)), /digest mismatch/);
    writeFileSync(join(root, 'profiles/catalog.json'), '{"profile":[1]}');
    assert.throws(() => verifyManifest(root, source, source.tree_digest), /source size changed|source bytes changed/);
    writeFileSync(join(root, 'profiles/catalog.json'), '{"profile":[]}');
    assert.throws(() => verifyManifest(root, {
      ...source, files: [...source.files].reverse(),
    }, source.tree_digest), /unsafe source manifest path/);
    assert.throws(() => verifyManifest(root, {
      ...source, files: [{ ...source.files[0], path: '../outside' }, source.files[1]],
    }, source.tree_digest), /unsafe source manifest path/);
    assert.throws(() => verifyManifest(root, {
      ...source, files: source.files.slice(0, 1),
    }, source.tree_digest), /cardinality/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('every chosen cryptographic and client profile must remain explicitly allowed', () => {
  const catalog = {
    standard_version: '1.0.0',
    profiles: lock.profileRefs.map((ref, i) => {
      const [profile_id, profile_version] = ref.split('@');
      return { profile_id, profile_version, status: i % 2 ? 'allowed' : 'recommended' };
    }),
  };
  assert.deepEqual(verifyProfiles(catalog, lock), lock.profileRefs);
  assert.throws(() => verifyProfiles({ ...catalog, standard_version: '0.9.0' }, lock), /catalog/);
  assert.throws(() => verifyProfiles({ ...catalog,
    profiles: catalog.profiles.slice(1),
  }, lock), /not currently approved/);
  assert.throws(() => verifyProfiles({ ...catalog,
    profiles: catalog.profiles.map((p, i) => i === 2 ? { ...p, status: 'research' } : p),
  }, lock), /not currently approved/);
  assert.throws(() => verifyProfiles(catalog, {
    ...lock, profileRefs: [...lock.profileRefs, lock.profileRefs[0]],
  }), /duplicate/);
});

test('project metadata ties 1.0 source to current implementation without claiming approval', () => {
  assert.equal(verifyProjectBindings(process.cwd(), lock).runtime, 'protected-intake-blocked');
  assert.throws(() => verifyProjectBindings(process.cwd(), {
    ...lock, standardCommit: '0'.repeat(40),
  }), /source locks disagree/);
  assert.throws(() => verifyProjectBindings(process.cwd(), {
    ...lock, mlsSuite: 'unregistered-magic-crypto',
  }), /actual client source differs/);
  assert.throws(() => verifyProjectBindings(process.cwd(), {
    ...lock, productConformanceClaim: true,
  }), /invalid claims/);
  assert.throws(
    () => loadConfig({ PROTECTED_CONTENT_ENABLED: 'true', PROTECTED_SETUP_ENABLED: 'true' }),
    (error) => error.code === 'protected_unavailable' && error.status === 503,
  );
});
