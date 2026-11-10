// Service-readable routing metadata and opaque authenticated MLS wire data.
// This parser never accepts a plaintext report or private manifest field.
import { decodeMlsMessage } from 'ts-mls';
import { canonical } from './protected-crypto.mjs';
import { MLS_PROFILE, MLS_SUITE, mlsBytes, mlsBase64 } from './protected-mls.mjs';
import { protectedId } from './protected-records.mjs';
import { assert, exactKeys } from './validation.mjs';
const utf8 = new TextEncoder(),
  decoder = new TextDecoder('utf-8', { fatal: true });
const same = (a, b) => canonical(a) === canonical(b);
export function protectedMlsContext(input) {
  const b = exactKeys(input, [
    'profile',
    'recordId',
    'sequence',
    'kind',
    'sender',
    'recipients',
    'generation',
    'epoch',
    'identityHeads',
  ]);
  assert(b.profile === MLS_PROFILE, 'protected_profile', 'Use the reviewed ratcheted client.');
  protectedId(b.recordId);
  protectedId(b.sender);
  assert(
    ['incident', 'help', 'correction', 'profile', 'operational_note'].includes(b.kind) &&
      Number.isSafeInteger(b.sequence) &&
      b.sequence >= 1 &&
      b.sequence <= 100 &&
      b.epoch === b.sequence + 1 &&
      Number.isSafeInteger(b.generation) &&
      b.generation >= 1,
    'invalid_protected_context',
    'Invalid record context.',
  );
  assert(
    Array.isArray(b.recipients) &&
      b.recipients.length >= 2 &&
      b.recipients.length <= 12 &&
      same(b.recipients, [...new Set(b.recipients)].sort()) &&
      b.recipients.includes(b.sender),
    'invalid_recipients',
    'Choose the exact sorted current recipient devices.',
  );
  b.recipients.forEach(protectedId);
  assert(
    Array.isArray(b.identityHeads) && b.identityHeads.length >= 1 && b.identityHeads.length <= 12,
    'identity_heads',
    'Bind the signed current identity states.',
  );
  for (const head of b.identityHeads) {
    exactKeys(head, ['id', 'sequence', 'hash']);
    protectedId(head.id);
    assert(
      Number.isSafeInteger(head.sequence) && head.sequence >= 1 && /^[a-f0-9]{64}$/.test(head.hash),
      'identity_heads',
      'Invalid identity state binding.',
    );
  }
  assert(
    same(
      b.identityHeads.map((h) => h.id),
      [...new Set(b.identityHeads.map((h) => h.id))].sort(),
    ),
    'identity_heads',
    'Sort distinct identity state references.',
  );
  return b;
}
function wire(value, type) {
  const bytes = mlsBytes(value, 80000),
    p = decodeMlsMessage(bytes, 0);
  assert(
    p && p[1] === bytes.length && p[0].version === 'mls10' && p[0].wireformat === type,
    'invalid_mls_wire',
    'Invalid or unsupported MLS wire message.',
  );
  return p[0];
}
export function protectedMlsBundle(input, context) {
  const b = exactKeys(input, ['format', 'members', 'setup', 'commit', 'message', 'chunks']);
  assert(
    b.format === 'g28-mls-record-v1' &&
      Array.isArray(b.members) &&
      b.members.length === context.recipients.length,
    'invalid_mls_bundle',
    'Invalid protected bundle.',
  );
  for (const m of b.members) {
    exactKeys(m, ['device', 'signatureKey']);
    protectedId(m.device);
    assert(
      mlsBytes(m.signatureKey, 64).length === 32,
      'invalid_mls_member',
      'Invalid MLS signing identity.',
    );
  }
  assert(
    same(
      b.members.map((m) => m.device),
      context.recipients,
    ),
    'invalid_mls_member',
    'MLS members differ from the declared recipients.',
  );
  const commit = wire(b.commit, 'mls_public_message').publicMessage,
    pm = wire(b.message, 'mls_private_message').privateMessage,
    aad = canonical(context);
  assert(
    commit.content.contentType === 'commit' &&
      commit.content.commit.path &&
      commit.content.commit.proposals.length === 0 &&
      commit.content.sender.senderType === 'member' &&
      Number(commit.content.epoch) === context.epoch - 1 &&
      decoder.decode(commit.content.groupId) === context.recordId &&
      decoder.decode(commit.content.authenticatedData) === aad,
    'invalid_mls_commit',
    'A fresh authenticated epoch update is required.',
  );
  assert(
    pm.contentType === 'application' &&
      Number(pm.epoch) === context.epoch &&
      decoder.decode(pm.groupId) === context.recordId &&
      decoder.decode(pm.authenticatedData) === aad,
    'invalid_mls_message',
    'The encrypted message context does not match.',
  );
  assert(
    Array.isArray(b.chunks) && b.chunks.length <= 3,
    'invalid_mls_attachment',
    'Use the bounded authenticated attachment format.',
  );
  for (const chunk of b.chunks)
    assert(
      mlsBytes(chunk, 90000).length >= 16,
      'invalid_mls_attachment',
      'Invalid encrypted attachment chunk.',
    );
  const path = commit.content.commit.path,
    member = b.members.find((m) => m.device === context.sender);
  assert(
    path.leafNode.credential.credentialType === 'basic' &&
      decoder.decode(path.leafNode.credential.identity) === context.sender &&
      mlsBase64(path.leafNode.signaturePublicKey) === member.signatureKey,
    'invalid_mls_commit',
    'An epoch update cannot change the certified sender identity.',
  );
  let refs = null;
  if (context.sequence === 1) {
    const s = exactKeys(b.setup, [
      'claimId',
      'creatorPackage',
      'membershipCommit',
      'welcome',
      'packages',
    ]);
    protectedId(s.claimId);
    assert(
      s.claimId === context.recordId &&
        Array.isArray(s.packages) &&
        s.packages.length === context.recipients.length - 1,
      'invalid_mls_setup',
      'Bind the original one-time package claim.',
    );
    wire(s.creatorPackage, 'mls_key_package');
    const creation = wire(s.membershipCommit, 'mls_public_message').publicMessage,
      welcome = wire(s.welcome, 'mls_welcome').welcome;
    assert(
      creation.content.contentType === 'commit' &&
        creation.content.commit.path &&
        creation.content.sender.senderType === 'member' &&
        creation.content.sender.leafIndex === 0 &&
        Number(creation.content.epoch) === 0 &&
        decoder.decode(creation.content.groupId) === context.recordId &&
        welcome.cipherSuite === MLS_SUITE,
      'invalid_mls_setup',
      'Invalid initial membership transition.',
    );
    for (const p of s.packages) {
      exactKeys(p, ['device', 'id', 'hash']);
      protectedId(p.device);
      protectedId(p.id);
      assert(
        /^[a-f0-9]{64}$/.test(p.hash),
        'invalid_mls_setup',
        'Invalid one-time package reference.',
      );
    }
    assert(
      same(
        s.packages.map((p) => p.device),
        context.recipients.filter((d) => d !== context.sender),
      ),
      'invalid_mls_setup',
      'Bind every original recipient package once.',
    );
    const adds = creation.content.commit.proposals;
    assert(
      adds.length === s.packages.length &&
        adds.every(
          (p) => p.proposalOrRefType === 'proposal' && p.proposal.proposalType === 'add',
        ) &&
        same(
          adds.map((p) => decoder.decode(p.proposal.add.keyPackage.leafNode.credential.identity)),
          s.packages.map((p) => p.device),
        ),
      'invalid_mls_setup',
      'Initial membership must contain only the exact authorized additions.',
    );
    refs = welcome.secrets.map((s) => mlsBase64(s.newMember));
  } else assert(b.setup === null, 'invalid_mls_setup', 'Replies cannot enroll new recipients.');
  return { bundle: b, senderLeaf: commit.content.sender.leafIndex, welcomeRefs: refs };
}
export function encodeProtectedMlsBundle(bundle) {
  return 'G28-MLS-1:' + mlsBase64(utf8.encode(canonical(bundle)));
}
export function protectedMlsEnvelope(input) {
  const b = exactKeys(input, ['context', 'ciphertext', 'signature']),
    context = protectedMlsContext(b.context);
  assert(
    typeof b.ciphertext === 'string' &&
      b.ciphertext.startsWith('G28-MLS-1:') &&
      b.ciphertext.length <= 400000 &&
      typeof b.signature === 'string' &&
      b.signature.length <= 4000 &&
      b.signature.startsWith('-----BEGIN PGP SIGNATURE-----'),
    'invalid_protected_envelope',
    'Use the bounded authenticated MLS format.',
  );
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(mlsBytes(b.ciphertext.slice(10), 400000)));
  } catch {
    assert(false, 'invalid_protected_envelope', 'Invalid encrypted bundle.');
  }
  return {
    envelope: { context, ciphertext: b.ciphertext, signature: b.signature },
    ...protectedMlsBundle(parsed, context),
  };
}
