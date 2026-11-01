import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runVerification, verificationPreflight, verificationSteps } from '../scripts/verify.mjs';

const local = { TEST_DATABASE_URL: 'postgresql://127.0.0.1:5432/g28test' };
const expectedSteps = [
  ['run', 'check'],
  ['run', 'lint'],
  ['run', 'format:check'],
  ['run', 'secrets:check'],
  ['run', 'typecheck'],
  ['run', 'test'],
  ['run', 'test:api'],
  ['run', 'build'],
  ['run', 'perf:budget'],
  ['run', 'test:browser'],
  ['run', 'test:review-browser'],
  ['run', 'test:public-browser'],
  ['run', 'test:coordination-browser'],
  ['audit', '--omit=dev', '--audit-level=high'],
];

const invalid = [
  undefined,
  null,
  42,
  {},
  'invalid',
  'postgresql://db.example.test/neondb',
  'https://localhost/db',
  'postgresql://localhost.example.test/test',
  'postgresql://localhost./test',
  'postgresql://127.1/test',
  'postgresql://127.0.0.1/test?host=remote.example.test',
  'postgresql://localhost/test?host=localhost&host=remote.example.test',
  'postgresql://localhost/test?%68ost=remote.example.test',
  'postgresql://localhost/test?port=9999',
  'postgresql://localhost/test?sslkey=/not-read-by-this-test',
  'postgresql://localhost/test?sslrootcert=/not-read-by-this-test',
  'postgresql://localhost/test?options=anything',
  'postgresql://localhost/test?',
  'postgresql://localhost/test#ignored',
  'postgresql://localhost/test#',
  'postgresql://localhost',
  'postgresql://localhost/',
  'postgresql://localhost/test/other',
  'postgresql://localhost/%00',
  'postgresql://localhost:0/test',
  'postgresql://localhost:65536/test',
  'postgresql://%ZZ@localhost/test',
  ' postgresql://localhost/test',
  'postgresql://local\nhost/test',
  'postgresql://localhost/test\t',
];

test('full verification rejects unsafe or ambiguous database targets before any gate runs', () => {
  for (const url of invalid) {
    const env = { TEST_DATABASE_URL: url };
    assert.throws(() => verificationPreflight(env));
    let calls = 0;
    const errors = [];
    assert.equal(
      runVerification({
        env,
        run: () => {
          calls++;
          return { status: 0 };
        },
        logError: (message) => errors.push(message),
      }),
      1,
    );
    assert.equal(calls, 0);
    assert.equal(errors.length, 1);
  }
});

test('both PostgreSQL schemes accept explicit loopback database names', () => {
  for (const url of [
    'postgresql://127.0.0.1/test',
    'postgres://localhost:5432/g28_test',
    'postgresql://localhost:15432/test-123',
    'postgresql://127.0.0.1:65535/test',
  ])
    assert.doesNotThrow(() => verificationPreflight({ TEST_DATABASE_URL: url }));
});

test('preflight errors do not disclose URL credentials or client-file paths', () => {
  const url = new URL('postgresql://remote.example.test/test');
  url.username = 'fixture-user';
  url.password = 'fixture-credential-canary';
  url.searchParams.set('sslkey', '/fixture-private-file');
  const errors = [];
  assert.equal(
    runVerification({ env: { TEST_DATABASE_URL: url.href }, logError: (e) => errors.push(e) }),
    1,
  );
  assert.equal(errors.length, 1);
  for (const value of [url.href, url.username, url.password, '/fixture-private-file'])
    assert(!errors[0].includes(value));
});

test('full verification includes every required gate and the production dependency audit', () => {
  assert.deepEqual(verificationSteps, expectedSteps);
  assert(Object.isFrozen(verificationSteps));
  assert(verificationSteps.every(Object.isFrozen));
  const calls = [];
  const env = { ...local, CI: 'true' };
  assert.equal(
    runVerification({
      env,
      run: (command, args, options) => {
        calls.push(args);
        assert.equal(command, process.platform === 'win32' ? 'npm.cmd' : 'npm');
        assert.deepEqual(options.env, env);
        assert.notEqual(options.env, env);
        assert.equal(options.cwd, fileURLToPath(new URL('../', import.meta.url)));
        assert.equal(options.stdio, 'inherit');
        return { status: 0, signal: null };
      },
      logError: assert.fail,
    }),
    0,
  );
  assert.deepEqual(calls, expectedSteps);
});

for (let failedIndex = 0; failedIndex < expectedSteps.length; failedIndex++) {
  test(`a failure in ${expectedSteps[failedIndex].join(' ')} prevents every later gate`, () => {
    const calls = [];
    const errors = [];
    assert.equal(
      runVerification({
        env: local,
        run: (_command, args) => {
          calls.push(args);
          return { status: calls.length - 1 === failedIndex ? 23 : 0 };
        },
        logError: (error) => errors.push(error),
      }),
      23,
    );
    assert.deepEqual(calls, expectedSteps.slice(0, failedIndex + 1));
    assert.equal(errors.length, 1);
  });
}

test('subprocess errors and invalid statuses fail closed without leaking values', () => {
  const canary = 'fixture-child-error-canary';
  for (const result of [
    { error: new Error(canary), status: 0 },
    { status: null, signal: 'SIGTERM' },
    { status: 0, signal: 'SIGTERM' },
    { status: null },
    { status: -1 },
    { status: 256 },
    { status: '0' },
    undefined,
  ]) {
    let calls = 0;
    const errors = [];
    assert.equal(
      runVerification({
        env: local,
        run: () => {
          calls++;
          return result;
        },
        logError: (message) => errors.push(message),
      }),
      1,
    );
    assert.equal(calls, 1);
    assert.equal(errors.length, 1);
    assert(!errors[0].includes(canary));
  }
  const errors = [];
  assert.equal(
    runVerification({
      env: local,
      run: () => {
        throw new Error(canary);
      },
      logError: (message) => errors.push(message),
    }),
    1,
  );
  assert.equal(errors.length, 1);
  assert(!errors[0].includes(canary));
});

test('the real verification entrypoint refuses unsafe input before spawning npm', () => {
  const result = spawnSync(process.execPath, ['scripts/verify.mjs'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    env: { TEST_DATABASE_URL: invalid[10], PATH: '' },
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must not contain query options or fragments/);
  assert(!result.stderr.includes('remote.example.test'));
  assert.equal(result.stdout, '');
});

test('the real verification entrypoint refuses a missing database without skipping tests', () => {
  const result = spawnSync(process.execPath, ['scripts/verify.mjs'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    env: { PATH: '' },
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Full verification cannot skip PostgreSQL tests/);
  assert.equal(result.stdout, '');
});

test('the real verification entrypoint reports unavailable npm as failure, not success', () => {
  const result = spawnSync(process.execPath, ['scripts/verify.mjs'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    env: { ...local, PATH: '' },
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Verification gate run check failed/);
  assert.equal(result.stdout, '');
});

test('full verification refuses reduced or malformed browser coverage before any subprocess', () => {
  for (const engines of [
    'chromium',
    'chromium,firefox',
    'chromium,chromium,webkit',
    'chromium,firefox,webkit,chromium',
    'chromium,firefox,webkit,',
    'chromium,firefox,fixture-engine-canary',
    ' ',
    null,
    42,
  ]) {
    let calls = 0;
    const errors = [];
    assert.equal(
      runVerification({
        env: { ...local, G28_BROWSER_ENGINES: engines },
        run: () => {
          calls++;
          return { status: 0 };
        },
        logError: (message) => errors.push(message),
      }),
      1,
    );
    assert.equal(calls, 0);
    assert.equal(errors.length, 1);
    assert.match(errors[0], /requires Chromium, Firefox and WebKit/);
    assert(!errors[0].includes('fixture-engine-canary'));
  }
});

test('default and complete three-engine selections retain every verification gate', () => {
  for (const engines of ['', 'chromium,firefox,webkit', ' webkit, chromium, firefox ']) {
    let calls = 0;
    const env = { ...local, G28_BROWSER_ENGINES: engines };
    assert.equal(
      runVerification({
        env,
        run: (_command, _args, options) => {
          calls++;
          assert.equal(options.env.G28_BROWSER_ENGINES, engines);
          return { status: 0 };
        },
        logError: assert.fail,
      }),
      0,
    );
    assert.equal(calls, verificationSteps.length);
  }
});

test('real full-verification CLI refuses single-engine coverage before launching npm', () => {
  const result = spawnSync(process.execPath, ['scripts/verify.mjs'], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    env: { ...local, G28_BROWSER_ENGINES: 'chromium', PATH: '' },
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires Chromium, Firefox and WebKit/);
  assert.equal(result.stdout, '');
});
