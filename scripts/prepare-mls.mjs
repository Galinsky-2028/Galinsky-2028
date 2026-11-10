// E2EESA strengthens RFC9420: even add-only commits require a fresh UpdatePath.
// Pin and review the exact upstream source. Never patch an unknown library.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const pins = {
  'ts-mls': [
    '1.6.4',
    'sha512-BFb9qJ3V1+HIuifC+MtnlROEj3oc6NEzA7Ig1/LAmANDRhNay7UCnwkzijzHH9cav5wf1BoJw8KQ2mXiEhPy1Q==',
  ],
  '@noble/hashes': [
    '2.4.0',
    'sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==',
  ],
  '@hpke/core': [
    '1.9.0',
    'sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==',
  ],
  '@hpke/common': [
    '1.13.0',
    'sha512-PqaJR89RWJQmt/WOGuBLrcrtXtEMbWu91XIbxDjKDTDgKvqvhlxOzQ9BAf9a0Q+yqqbTtQ0pK6KUyVi2WMehbA==',
  ],
};
const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
for (const [name, [version, integrity]] of Object.entries(pins)) {
  const installed = JSON.parse(
    readFileSync(new URL('../node_modules/' + name + '/package.json', import.meta.url), 'utf8'),
  );
  const recorded = lock.packages['node_modules/' + name];
  if (
    installed.version !== version ||
    recorded?.version !== version ||
    recorded.integrity !== integrity
  )
    throw Error('Unreviewed protected-protocol dependency.');
}
const path = new URL('../node_modules/ts-mls/dist/src/createCommit.js', import.meta.url),
  original = readFileSync(path, 'utf8');
const hash = (s) => createHash('sha256').update(s).digest('hex');
const before = '2813d68a1457a55470bbb1f2d223e12aa61c69e18a177f920c51cbdccc4bb004';
const from = 'const [tree, updatePath, pathSecrets, newPrivateKey] = res.needsUpdatePath',
  to =
    'const [tree, updatePath, pathSecrets, newPrivateKey] = true /* G28: mandatory fresh UpdatePath */';
if (original.includes(to)) {
  if (hash(original.replace(to, from)) !== before) throw Error('Unexpected patched MLS source.');
} else {
  if (hash(original) !== before || original.split(from).length !== 2)
    throw Error('Unexpected upstream MLS source.');
  writeFileSync(path, original.replace(from, to));
}
