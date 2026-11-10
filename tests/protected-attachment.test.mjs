import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  encryptProtectedAttachment,
  decryptProtectedAttachment,
  attachmentNonce,
  attachmentManifestDigest,
} from '../packages/core/protected-attachment.mjs';
test('attachment profile uses fresh keys, exact counter nonces, private manifest binding and authenticated fixed chunks including empty files', async () => {
  const bytes = new Uint8Array(randomBytes(150000)),
    parent = randomUUID(),
    first = await encryptProtectedAttachment({ bytes, name: 'private-source.txt' }, parent),
    second = await encryptProtectedAttachment({ bytes, name: 'private-source.txt' }, parent);
  assert.notEqual(
    first.manifest.attachment_master_key_hex,
    second.manifest.attachment_master_key_hex,
  );
  assert.equal(first.chunks.length, 3);
  assert.equal(
    Buffer.from(attachmentNonce('01020304', 258)).toString('hex'),
    '010203040000000000000102',
  );
  assert(!JSON.stringify(first.chunks).includes('private-source.txt'));
  assert(!JSON.stringify(first.chunks).includes(first.manifest.attachment_master_key_hex));
  const opened = await decryptProtectedAttachment(first.manifest, first.chunks, parent);
  assert.deepEqual(opened.bytes, bytes);
  assert.equal(opened.name, 'private-source.txt');
  await assert.rejects(
    decryptProtectedAttachment(
      first.manifest,
      [first.chunks[1], first.chunks[0], first.chunks[2]],
      parent,
    ),
  );
  await assert.rejects(
    decryptProtectedAttachment(
      first.manifest,
      [second.chunks[0], ...first.chunks.slice(1)],
      parent,
    ),
  );
  await assert.rejects(decryptProtectedAttachment(first.manifest, first.chunks.slice(1), parent));
  await assert.rejects(
    decryptProtectedAttachment(
      { ...first.manifest, filename: 'substituted.txt' },
      first.chunks,
      parent,
    ),
  );
  await assert.rejects(decryptProtectedAttachment(first.manifest, first.chunks, randomUUID()));
  const badHash = { ...first.manifest, whole_plaintext_hash_hex: 'f'.repeat(64) };
  badHash.manifest_context_digest_hex = await attachmentManifestDigest(badHash);
  await assert.rejects(decryptProtectedAttachment(badHash, first.chunks, parent));
  const empty = await encryptProtectedAttachment(
    { bytes: new Uint8Array(), name: 'empty' },
    parent,
  );
  assert.equal(empty.chunks.length, 1);
  assert.equal(
    (await decryptProtectedAttachment(empty.manifest, empty.chunks, parent)).bytes.length,
    0,
  );
  await assert.rejects(
    encryptProtectedAttachment({ bytes: new Uint8Array(150001), name: 'oversize' }, parent),
  );
});
test('private manifest digest matches the pinned upstream E2EESA reference fixture', async () => {
  const { readFile } = await import('node:fs/promises'),
    m = JSON.parse(
      await readFile(new URL('fixtures/e2eesa-attachment-manifest.json', import.meta.url), 'utf8'),
    );
  assert.equal(await attachmentManifestDigest(m), m.manifest_context_digest_hex);
});
