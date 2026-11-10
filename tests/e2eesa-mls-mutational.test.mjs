import test from 'node:test';
import assert from 'node:assert/strict';
import { protectedMlsContext } from '../packages/core/protected-mls-envelope.mjs';
import { mlsBytes } from '../packages/core/protected-mls.mjs';

const id = (n) => '00000000-0000-4000-8000-' + n.toString(16).padStart(12, '0');
const a = id(1), b = id(2);
const valid = () => ({
  profile: 'group-mls-rfc9420@0.1.0',
  recordId: id(3),
  sequence: 1,
  kind: 'help',
  sender: a,
  recipients: [a, b],
  generation: 1,
  epoch: 2,
  identityHeads: [{ id: id(4), sequence: 1, hash: 'a'.repeat(64) }],
});

test('1024 deterministic adversarial MLS envelope metadata mutations fail closed', () => {
  assert.deepEqual(protectedMlsContext(valid()), valid());
  let seed = 20261110;
  const next = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed;
  };
  const variants = [
    (x) => { x.profile = 'unregistered-mls'; },
    (x) => { x.sequence = 101 + next() % 2000; },
    (x) => { x.epoch += 1; },
    (x) => { x.recipients.reverse(); },
    (x) => { x.recipients = [...x.recipients, a]; },
    (x) => { x.sender = id(9); },
    (x) => { x.generation = -1; },
    (x) => { x.identityHeads[0].hash = 'z'.repeat(64); },
    (x) => { x.identityHeads.push(x.identityHeads[0]); },
    (x) => { x.identityHeads[0].sequence = 0; },
    (x) => { x.kind = 'unverified-dump'; },
    (x) => { x.recordId = '../report'; },
    (x) => { x.plaintext = 'NOT AUTHORIZED'; },
    (x) => { x.identityHeads[0].approvedBy = 'service'; },
  ];
  for (let i = 0; i < 1024; i++) {
    const x = valid();
    variants[next() % variants.length](x);
    assert.throws(
      () => protectedMlsContext(x),
      undefined,
      'malformed context accepted at case ' + i,
    );
  }
});

test('1024 malformed base64 MLS encodings cannot be accepted as wire data', () => {
  let seed = 0x28a0;
  for (let i = 0; i < 1024; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    const suffix = (seed & 0xffff).toString(16);
    const invalid = [
      'AA' + suffix + '=*', // forbidden trailing character
      '!' + suffix,
      'AA== ' + suffix,
      'A'.repeat(4 + (seed % 20)) + '_',
    ][i % 4];
    assert.throws(() => mlsBytes(invalid), undefined, 'bad base64 accepted: ' + i);
  }
});
