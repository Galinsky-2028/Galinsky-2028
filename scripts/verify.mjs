import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));

// Keep every gate explicit. A successful subset is not full verification.
export const verificationSteps = Object.freeze(
  [
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
  ].map((args) => Object.freeze(args)),
);

export function verificationPreflight(env) {
  const value = env?.TEST_DATABASE_URL;
  if (!value)
    throw new Error(
      'TEST_DATABASE_URL must identify an isolated loopback test database. Full verification cannot skip PostgreSQL tests.',
    );
  if (typeof value !== 'string' || /[\u0000-\u0020\u007f]/u.test(value))
    throw new Error('TEST_DATABASE_URL must be a valid PostgreSQL URL without raw whitespace.');
  let url;
  try {
    url = new URL(value);
    // Validate percent escapes without ever printing the supplied credential.
    decodeURIComponent(url.username);
    decodeURIComponent(url.password);
  } catch {
    throw new Error('TEST_DATABASE_URL must be a valid PostgreSQL URL.');
  }
  if (
    !['postgres:', 'postgresql:'].includes(url.protocol) ||
    !['127.0.0.1', 'localhost'].includes(url.hostname)
  )
    throw new Error(
      'Full verification accepts only an isolated loopback PostgreSQL database. Never use a live database.',
    );
  // pg connection-string options can override the authority host or read TLS
  // files. Refuse all options instead of guessing which a future driver honors.
  if (value.includes('?') || value.includes('#'))
    throw new Error('TEST_DATABASE_URL must not contain query options or fragments.');
  // An empty database lets the driver fall back to PGDATABASE or the user name.
  // Deliberately accept only simple, explicit disposable-database identifiers.
  if (!/^\/[A-Za-z0-9_-]+$/.test(url.pathname))
    throw new Error('TEST_DATABASE_URL must name an explicit disposable test database.');
  if (url.port) {
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw new Error('TEST_DATABASE_URL must use a valid PostgreSQL port.');
  }
  // Focused browser runs are useful for debugging, but cannot establish full
  // verification. The reviewer runner honors this environment override.
  const requestedEngines = env.G28_BROWSER_ENGINES;
  if (requestedEngines !== undefined && requestedEngines !== '') {
    const required = ['chromium', 'firefox', 'webkit'];
    const selected =
      typeof requestedEngines === 'string'
        ? requestedEngines.split(',').map((engine) => engine.trim())
        : [];
    if (
      selected.length !== required.length ||
      new Set(selected).size !== required.length ||
      !required.every((engine) => selected.includes(engine))
    )
      throw new Error(
        'Full verification requires Chromium, Firefox and WebKit. Unset G28_BROWSER_ENGINES or select all three engines; use focused browser commands for debugging.',
      );
  }
}

export function runVerification({
  env = process.env,
  run = spawnSync,
  logError = console.error,
} = {}) {
  // Snapshot the environment so the checked URL is the one passed to children.
  const childEnv = { ...env };
  try {
    verificationPreflight(childEnv);
  } catch (error) {
    logError(error.message);
    return 1;
  }
  for (const args of verificationSteps) {
    let result;
    try {
      result = run(process.platform === 'win32' ? 'npm.cmd' : 'npm', [...args], {
        cwd: repositoryRoot,
        env: childEnv,
        stdio: 'inherit',
      });
    } catch {
      // Spawn errors can contain environment values; report only the fixed gate.
      logError(`Verification gate ${args.join(' ')} could not start. No later gates ran.`);
      return 1;
    }
    if (!result || result.error || result.signal || result.status !== 0) {
      logError(`Verification gate ${args.join(' ')} failed. No later gates ran.`);
      return Number.isInteger(result?.status) && result.status > 0 && result.status <= 255
        ? result.status
        : 1;
    }
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runVerification();
}
