import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdirSync, mkdtempSync, rmSync, writeFileSync, unlinkSync, symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildWebClosure, verifyWebClosure, discoverBuildFiles,
} from '../security/web-release-closure.mjs';

function withBuild(fn) {
  const root = mkdtempSync(join(tmpdir(), 'g28-web-closure-'));
  for (const path of ['dist/web/assets', 'dist/portal/assets'])
    mkdirSync(join(root, path), { recursive: true });
  writeFileSync(join(root, 'dist/web/index.html'), '<script src="assets/main.js"></script>');
  writeFileSync(join(root, 'dist/web/assets/main.js'), 'console.log("public");');
  writeFileSync(join(root, 'dist/portal/index.html'), '<script src="assets/portal.js"></script>');
  writeFileSync(join(root, 'dist/portal/assets/portal.js'), 'console.log("portal");');
  try { fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
const SHA = 'f'.repeat(40);

test('the complete web and portal closure is content-addressed, source-bound and deterministic', () => {
  withBuild((root) => {
    const original = buildWebClosure(root, SHA);
    assert.equal(original.fileCount, 4);
    assert(/^sha256:[a-f0-9]{64}$/.test(original.closureDigest));
    assert.deepEqual(original, buildWebClosure(root, SHA));
    assert.equal(verifyWebClosure(root, original).fileCount, 4);
    assert.notEqual(buildWebClosure(root, 'a'.repeat(40)).closureDigest, original.closureDigest);
  });
});

test('every byte and entry is bound, including same-length source edits and new files', () => {
  withBuild((root) => {
    const initial = buildWebClosure(root, SHA);
    writeFileSync(join(root, 'dist/portal/assets/portal.js'), 'console.log("stolen");');
    assert.throws(() => verifyWebClosure(root, initial), /changed, added, removed/);
    writeFileSync(join(root, 'dist/portal/assets/portal.js'), 'console.log("portal");');
    writeFileSync(join(root, 'dist/web/assets/extra.js'), 'alert("unlisted");');
    assert.throws(() => verifyWebClosure(root, initial), /changed, added, removed/);
    unlinkSync(join(root, 'dist/web/assets/extra.js'));
    const clone = structuredClone(initial);
    clone.files[0].sha256 = '0'.repeat(64);
    assert.throws(() => verifyWebClosure(root, clone), /changed, added, removed/);
    clone.files[0].sha256 = initial.files[0].sha256;
    clone.sourceCommit = 'a'.repeat(40);
    assert.throws(() => verifyWebClosure(root, clone), /changed, added, removed/);
  });
});

test('symlinks, empty builds, malformed roots and unbound commits fail closed', () => {
  withBuild((root) => {
    const rootDir = join(root, 'dist/web');
    symlinkSync(join(root, 'dist/portal/assets/portal.js'),
      join(rootDir, 'assets/linked.js'));
    assert.throws(() => discoverBuildFiles(root), /symbolic build artifact/);
    unlinkSync(join(rootDir, 'assets/linked.js'));
    assert.throws(() => buildWebClosure(root, 'deadbeef'), /source commit/);
    assert.throws(() => discoverBuildFiles(root, ['dist/web', '../private']),
      /unsafe build artifact path/);
    assert.throws(() => discoverBuildFiles(root, ['dist/empty']),
      /missing build output/);
  });
});
