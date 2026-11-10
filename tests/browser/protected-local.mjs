// Real IndexedDB/Web Locks/Argon2 vault against an isolated real HTTP/SQL API.
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile, readdir, rm } from 'node:fs/promises';
import { createServer } from 'vite';
import { chromium } from 'playwright';
import { createApp } from '../../apps/api/src/app.mjs';
import { PostgresStore, databasePool } from '../../apps/api/src/postgres-store.mjs';
import { randomToken, tokenHash } from '../../packages/core/auth.mjs';
const base = process.env.TEST_DATABASE_URL;
if (!base) {
  console.log('Protected local browser journey requires isolated TEST_DATABASE_URL.');
  process.exit(0);
}
assert(['localhost', '127.0.0.1'].includes(new URL(base).hostname));
const name = 'g28_local_browser_' + randomBytes(5).toString('hex'),
  admin = databasePool(base),
  url = new URL(base);
url.pathname = '/' + name;
await admin.query('CREATE DATABASE ' + name);
const pool = databasePool(url.href),
  store = new PostgresStore(pool),
  origin = 'http://localhost:4471',
  apiOrigin = 'http://127.0.0.1:4470',
  config = {
    protectedMls: true,
    protectedSetup: true,
    protectedContent: false,
    staffIdentity: true,
    adminLoginReady: true,
    adminOwnerEmailKey: tokenHash(randomUUID()),
    portalOrigin: origin,
    publicOrigin: 'http://localhost:4469',
  },
  app = createApp({ store, config });
let vite, browser;
try {
  for (const f of (await readdir('db/migrations')).filter((f) => f.endsWith('.sql')).sort())
    await pool.query(await readFile('db/migrations/' + f, 'utf8'));
  await app.listen({ host: '127.0.0.1', port: 4470 });
  vite = await createServer({
    configFile: false,
    root: process.cwd(),
    cacheDir: '/tmp/' + name + '-vite',
    optimizeDeps: {
      noDiscovery: true,
      include: [
        'react',
        '@simplewebauthn/browser',
        'react-dom/client',
        'react/jsx-dev-runtime',
        '@noble/hashes/argon2.js',
        'openpgp',
        'ts-mls',
        'ts-mls/clientConfig.js',
        'ts-mls/clientState.js',
        'ts-mls/messageProtection.js',
        'ts-mls/keyPackage.js',
        'ts-mls/leafNode.js',
      ],
    },
    server: {
      host: 'localhost',
      port: 4471,
      strictPort: true,
      hmr: false,
      proxy: { '/api': { target: apiOrigin } },
    },
    appType: 'custom',
  });
  vite.middlewares.use((req, res, next) => {
    if (req.url === '/local-test') {
      res.setHeader('Content-Type', 'text/html');
      res.end('<!doctype html><title>Isolated protected client test</title>');
    } else next();
  });
  await vite.listen();
  browser = await chromium.launch({
    headless: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, args: ['--no-sandbox'] }
      : {}),
  });
  const actors = [];
  for (let i = 0; i < 2; i++) {
    const account = randomUUID(),
      token = randomToken(),
      csrf = randomToken();
    await pool.query(
      "INSERT INTO g28.accounts(id,email_key,delivery_envelope,verified_at,terms_version) VALUES($1,$2,'passkey-only',now(),'synthetic')",
      [account, tokenHash(account)],
    );
    await pool.query(
      'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
      [tokenHash(token), account, csrf, new Date(Date.now() + 86400000)],
    );
    const context = await browser.newContext();
    await context.addCookies([
      { name: 'g28-local', value: token, url: origin, httpOnly: true, sameSite: 'Lax' },
    ]);
    const page = await context.newPage(),
      requests = [];
    page.on('request', (r) => {
      if (r.url().includes('/api/')) requests.push(r.postData() || '');
    });
    await page.goto(origin + '/local-test');
    await page.evaluate(
      async ({ account, csrf }) => {
        const { createProtectedClient } = await import('/apps/portal/src/protected-client.mjs');
        window.fixtureCsrf = csrf;
        window.makeClient = () =>
          createProtectedClient({
            account,
            api: async (path, body) => {
              const result = await fetch(path, {
                method: body ? 'POST' : 'GET',
                headers: body ? { 'Content-Type': 'application/json', 'x-csrf-token': csrf } : {},
                body: body ? JSON.stringify(body) : undefined,
              });
              const data = await result.json();
              if (!result.ok) throw Error(data.message || data.error || 'API rejected');
              if (window.tamperClaim && path.endsWith('/claims')) {
                window.tamperClaim = false;
                const { newMlsSigningKeys, newMlsKeyPackage } =
                  await import('/packages/core/protected-mls.mjs');
                const keys = await newMlsSigningKeys(),
                  target = data.packages[0].device,
                  pair = await newMlsKeyPackage(target, keys);
                data.members.find((m) => m.device === target).signatureKey = keys.publicKey;
                data.packages[0].wire = pair.wire;
              }
              if (window.rollbackIdentity && path.includes('/identities/')) {
                window.rollbackIdentity = false;
                const { identityStateHash } = await import('/packages/core/protected-identity.mjs');
                data.identity = data.history.initialState;
                data.history.events = [];
                data.stateHash = await identityStateHash(data.identity);
              }
              if (window.loseMessageAck && path.endsWith('/records') && body) {
                window.loseMessageAck = false;
                throw Error('Synthetic message acknowledgement lost');
              }
              if (window.loseAck && path.endsWith('/identity') && body) {
                window.loseAck = false;
                throw Error('Synthetic lost acknowledgement');
              }
              return data;
            },
          });
        window.client = window.makeClient();
      },
      { account, csrf },
    );
    actors.push({ account, context, page, requests, hash: tokenHash(token) });
  }
  const [a, b] = actors,
    password = 'SYNTHETIC_LOCAL_UNLOCK_CANARY_6109';
  await a.page.evaluate(() => {
    window.loseAck = true;
  });
  assert.match(
    await a.page.evaluate(async (password) => {
      try {
        await window.client.enroll(password, 'Synthetic local browser', true);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, password),
    /lost acknowledgement/,
  );
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM g28.protected_identity_events')).rows[0].n,
    1,
  );
  const first = await a.page.evaluate(async (password) => window.client.unlock(password), password);
  assert(first.hasRoot);
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM g28.protected_identity_events')).rows[0].n,
    1,
    'retry must acknowledge without duplicating identity events',
  );
  const second = await b.page.evaluate(
    async (password) => window.client.enroll(password, 'Other synthetic local browser', true),
    password,
  );
  const contact = await a.page.evaluate(
    async (p) => window.client.peer(p.identityId, p.rootFingerprint),
    second,
  );
  assert.equal(contact.verification.status, 'unverified');
  assert.match(
    await a.page.evaluate(async ({ accountId }) => {
      try {
        await window.client.verify(accountId, {
          method: 'numeric',
          comparison: 'wrong',
          independent: true,
          confirmed: true,
        });
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, contact),
    /independent trusted channel/,
  );
  const verified = await a.page.evaluate(
    async (c) =>
      window.client.verify(c.accountId, {
        method: 'numeric',
        comparison: c.safety.numeric,
        independent: true,
        confirmed: true,
      }),
    contact,
  );
  assert.equal(verified.status, 'verified');
  const peer = await b.page.evaluate(
    async (p) => window.client.peer(p.identityId, p.rootFingerprint),
    first,
  );
  assert.equal(
    contact.safety.numeric,
    peer.safety.numeric,
    'both independently controlled endpoints derive identical comparison values',
  );
  await a.page.evaluate(async () => window.client.publishPackages(2));
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM g28.protected_key_packages')).rows[0].n,
    2,
  );
  config.adminOwnerEmailKey = tokenHash(b.account);
  await store.withStaffSecurity(b.account, (s) => {
    s.credentials = [{ id: 'synthetic-browser-passkey' }];
    s.sessions = {
      [b.hash]: { credentialId: 'synthetic-browser-passkey', expires: Date.now() + 900000 },
    };
  });
  await b.page.evaluate(
    async (c) =>
      window.client.verify(c.accountId, {
        method: 'numeric',
        comparison: c.safety.numeric,
        independent: true,
        confirmed: true,
      }),
    peer,
  );
  await b.page.evaluate(async (second) => {
    const result = await fetch('/api/protected/v2/devices/' + second.deviceId + '/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.fixtureCsrf },
      body: JSON.stringify({
        fingerprint: second.deviceFingerprint,
        identityHash: (await (await fetch('/api/protected/v2/identity')).json()).stateHash,
        scope: 'incident',
        confirm: 'verified recipient identity independently',
      }),
    });
    if (!result.ok) throw Error(await result.text());
  }, second);
  await b.page.evaluate(async () => window.client.publishPackages(2));
  config.protectedContent = true;
  await a.page.evaluate(() => {
    window.loseMessageAck = true;
  });
  const failure = await a.page.evaluate(async (second) => {
    try {
      await window.client.send({
        kind: 'incident',
        devices: [second.deviceId],
        fingerprints: { [second.deviceId]: second.deviceFingerprint },
        text: 'BROWSER_MLS_PRIVATE_NARRATIVE_7210',
        attachment: {
          name: 'quarantined.html',
          bytes: new TextEncoder().encode('<script>PRIVATE_FILE_CANARY_7210</script>'),
        },
      });
      return 'unexpected';
    } catch (e) {
      return e.message;
    }
  }, second);
  assert.match(failure, /acknowledgement lost/);
  const record = (await pool.query('SELECT id,document FROM g28.protected_records')).rows[0];
  assert(record);
  assert(!JSON.stringify(record).includes('BROWSER_MLS_PRIVATE_NARRATIVE_7210'));
  assert(!JSON.stringify(record).includes('PRIVATE_FILE_CANARY_7210'));
  assert(!JSON.stringify(record).includes('quarantined.html'));
  assert.equal(
    (await a.page.evaluate(async (id) => window.client.retry(id), record.id)).version,
    1,
  );
  const opened = await b.page.evaluate(async (id) => window.client.synchronize(id), record.id);
  assert.equal(opened.messages[0].payload.text, 'BROWSER_MLS_PRIVATE_NARRATIVE_7210');
  const downloaded = await b.page.evaluate(async (id) => {
    const result = await window.client.attachment(id, 1);
    return { text: new TextDecoder().decode(result.bytes), name: result.name };
  }, record.id);
  assert.equal(downloaded.text, '<script>PRIVATE_FILE_CANARY_7210</script>');
  await b.page.evaluate(
    async (id) => window.client.reply({ id, text: 'BROWSER_MLS_PRIVATE_REPLY_7210' }),
    record.id,
  );
  const reply = await a.page.evaluate(async (id) => window.client.synchronize(id), record.id);
  assert.equal(reply.messages[1].payload.text, 'BROWSER_MLS_PRIVATE_REPLY_7210');
  await a.page.evaluate(() => window.client.lock());
  await a.page.evaluate(async (password) => window.client.unlock(password), password);
  assert.equal(
    (await a.page.evaluate(async (id) => window.client.synchronize(id), record.id)).messages.length,
    2,
    'encrypted checkpoint survives browser lock',
  );
  const racing = await Promise.allSettled([
    a.page.evaluate(
      async (id) => window.client.reply({ id, text: 'CONCURRENT_DRAFT_A_7210' }),
      record.id,
    ),
    b.page.evaluate(
      async (id) => window.client.reply({ id, text: 'CONCURRENT_DRAFT_B_7210' }),
      record.id,
    ),
  ]);
  assert.equal(
    racing.filter((r) => r.status === 'fulfilled').length,
    1,
    'exactly one simultaneous reply wins its epoch',
  );
  const winning = racing[0].status === 'fulfilled' ? a : b,
    losing = winning === a ? b : a;
  const reconciled = await losing.page.evaluate(
    async (id) => window.client.synchronize(id),
    record.id,
  );
  assert.equal(reconciled.messages.length, 3);
  assert(
    reconciled.draft?.text.startsWith('CONCURRENT_DRAFT_'),
    'losing draft survives without sending an automatic retry',
  );
  await losing.page.evaluate(async ({ id, text }) => window.client.reply({ id, text }), {
    id: record.id,
    text: reconciled.draft.text,
  });
  assert.equal(
    (await winning.page.evaluate(async (id) => window.client.synchronize(id), record.id)).messages
      .length,
    4,
  );
  await a.page.evaluate(() => {
    window.tamperClaim = true;
  });
  assert.match(
    await a.page.evaluate(async (second) => {
      try {
        await window.client.send({
          kind: 'incident',
          devices: [second.deviceId],
          fingerprints: { [second.deviceId]: second.deviceFingerprint },
          text: 'MUST_NOT_ENCRYPT_TO_SUBSTITUTED_RECIPIENT',
        });
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, second),
    /verified root-signed device keys/,
  );
  assert.equal(
    (await pool.query('SELECT count(*)::int AS n FROM g28.protected_records')).rows[0].n,
    1,
    'a host-substituted recipient package must not receive ciphertext',
  );
  await a.page.evaluate(() => {
    window.rollbackIdentity = true;
  });
  assert.match(
    await a.page.evaluate(async (second) => {
      try {
        await window.client.peer(second.identityId, second.rootFingerprint);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, second),
    /rolled back/,
  );
  const invalidated = await a.page.evaluate(
    async (second) => window.client.peer(second.identityId, second.rootFingerprint),
    second,
  );
  assert.equal(
    invalidated.verification.status,
    'invalidated',
    'an old matching root must not revive a failed monotonic pin',
  );
  await a.page.evaluate(
    async (c) =>
      window.client.verify(c.accountId, {
        method: 'numeric',
        comparison: c.safety.numeric,
        independent: true,
        confirmed: true,
      }),
    invalidated,
  );
  await b.page.evaluate(async () => window.client.publishPackages(2));
  await a.page.evaluate(() => {
    window.loseMessageAck = true;
  });
  await a.page.evaluate(async (second) => {
    try {
      await window.client.send({
        kind: 'incident',
        devices: [second.deviceId],
        fingerprints: { [second.deviceId]: second.deviceFingerprint },
        text: 'EXPIRING_UNCERTAIN_DRAFT_7210',
      });
    } catch (e) {
      if (!e.message.includes('acknowledgement lost')) throw e;
    }
  }, second);
  const expiredRecord = (
    await pool.query('SELECT id FROM g28.protected_records WHERE id<>$1', [record.id])
  ).rows[0];
  assert(
    expiredRecord,
    'the expired outbox scenario deliberately includes an accepted message with a lost response',
  );
  await a.page.evaluate(async () => {
    const realNow = Date.now;
    try {
      Date.now = () => realNow() + 25 * 3600000;
      await window.client.expirePending();
    } finally {
      Date.now = realNow;
    }
  });
  assert.match(
    await a.page.evaluate(async (id) => {
      try {
        await window.client.synchronize(id);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, expiredRecord.id),
    /encryption state expired/,
  );
  const disk = await a.page.evaluate(async () => {
    const local = await import('/apps/portal/src/protected-local.mjs');
    return JSON.stringify(await local.protectedLocalList(window.client.publicState().deviceId));
  });
  assert.equal(disk, '[]');
  const ciphertext = await a.page.evaluate(async (account) => {
    const local = await import('/apps/portal/src/protected-local.mjs');
    return JSON.stringify(await local.protectedLocalList(account));
  }, a.account);
  for (const forbidden of [
    password,
    'PRIVATE KEY',
    'rootSecret',
    'deviceSecret',
    'pendingTransition',
    'contacts',
    'signaturePrivateKey',
    'BROWSER_MLS_PRIVATE_NARRATIVE_7210',
    'PRIVATE_FILE_CANARY_7210',
  ])
    assert(
      !ciphertext.includes(forbidden),
      'IndexedDB must not contain private vault payload fields: ' + forbidden,
    );
  for (const actor of actors)
    for (const body of actor.requests) {
      assert(!body.includes(password));
      assert(!body.includes('PRIVATE KEY'));
      assert(!body.includes('privateKey'));
    }
  await a.page.evaluate(() => window.client.lock());
  assert.match(
    await a.page.evaluate(() => {
      try {
        return window.client.publicState();
      } catch (e) {
        return e.message;
      }
    }),
    /Unlock/,
  );
  assert.match(
    await a.page.evaluate(async () => {
      try {
        await window.client.unlock('wrong synthetic passphrase');
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }),
    /operation|authenticate|decrypt/i,
  );
  assert.deepEqual(
    await a.page.evaluate(async (password) => window.client.unlock(password), password),
    first,
  );
  const linkedContext = await browser.newContext();
  await linkedContext.addCookies(await a.context.cookies());
  const linkedPage = await linkedContext.newPage();
  await linkedPage.goto(origin + '/local-test');
  const csrf = await a.page.evaluate(() => window.fixtureCsrf);
  await linkedPage.evaluate(
    async ({ account, csrf }) => {
      const { createProtectedClient } = await import('/apps/portal/src/protected-client.mjs');
      window.client = createProtectedClient({
        account,
        api: async (path, body) => {
          const response = await fetch(path, {
            method: body ? 'POST' : 'GET',
            headers: body ? { 'Content-Type': 'application/json', 'x-csrf-token': csrf } : {},
            body: body ? JSON.stringify(body) : undefined,
          });
          const value = await response.json();
          if (!response.ok) throw Error(value.message || value.error);
          return value;
        },
      });
    },
    { account: a.account, csrf },
  );
  const linking = await linkedPage.evaluate(
    async ({ password, first }) =>
      window.client.prepareLinked(
        password,
        first.identityId,
        first.rootFingerprint,
        'Linked synthetic browser',
        true,
      ),
    { password, first },
  );
  assert.match(
    await linkedPage.evaluate(async (password) => {
      try {
        await window.client.unlock(password);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, password),
    /not authorized/,
  );
  assert.match(
    await a.page.evaluate(async (request) => {
      try {
        await window.client.authorizeLinked(request, 'f'.repeat(64));
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, linking.request),
    /fingerprint/,
  );
  assert.match(
    await a.page.evaluate(async (linking) => {
      try {
        await window.client.authorizeLinked(
          { ...linking.request, privateKey: 'MUST_NOT_SEND_PRIVATE_FIELD_7210' },
          linking.deviceFingerprint,
        );
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, linking),
    /unexpected fields/,
  );
  await a.page.evaluate(
    async (linking) => window.client.authorizeLinked(linking.request, linking.deviceFingerprint),
    linking,
  );
  await a.page.evaluate(
    async (linking) => window.client.authorizeLinked(linking.request, linking.deviceFingerprint),
    linking,
  );
  const linked = await linkedPage.evaluate(
    async (password) => window.client.unlock(password),
    password,
  );
  assert.equal(linked.hasRoot, false);
  assert.equal(linked.identityId, first.identityId);
  assert.equal(linked.sequence, 2);
  assert.match(
    await linkedPage.evaluate(async (id) => {
      try {
        await window.client.synchronize(id);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, record.id),
    /original authority/,
  );
  assert.equal(
    (
      await pool.query(
        'SELECT count(*)::int AS n FROM g28.protected_identity_events WHERE identity_id=$1',
        [first.identityId],
      )
    ).rows[0].n,
    2,
    'lost root-approval acknowledgement retries without another signed event',
  );
  const linkedRotation = await linkedPage.evaluate(
    async (password) =>
      window.client.rotateDevice(
        password,
        'Rotated linked browser',
        true,
        'rotate device and permanently lose old local history',
      ),
    password + ' linked rotation',
  );
  assert.equal(linkedRotation.completed, false);
  const thirdContext = await browser.newContext();
  await thirdContext.addCookies(await a.context.cookies());
  const thirdPage = await thirdContext.newPage();
  await thirdPage.goto(origin + '/local-test');
  await thirdPage.evaluate(
    async ({ account, csrf }) => {
      const { createProtectedClient } = await import('/apps/portal/src/protected-client.mjs');
      window.client = createProtectedClient({
        account,
        api: async (path, body) => {
          const r = await fetch(path, {
            method: body ? 'POST' : 'GET',
            headers: body ? { 'Content-Type': 'application/json', 'x-csrf-token': csrf } : {},
            body: body ? JSON.stringify(body) : undefined,
          });
          const v = await r.json();
          if (!r.ok) throw Error(v.message || v.error);
          return v;
        },
      });
    },
    { account: a.account, csrf },
  );
  const third = await thirdPage.evaluate(
    async ({ password, first }) =>
      window.client.prepareLinked(
        password,
        first.identityId,
        first.rootFingerprint,
        'Third synthetic device',
        true,
      ),
    { password, first },
  );
  await a.page.evaluate(
    async (r) => window.client.authorizeLinked(r.request, r.deviceFingerprint),
    third,
  );
  assert.match(
    await a.page.evaluate(async (r) => {
      try {
        await window.client.authorizeLinked(r.request, r.deviceFingerprint);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, linkedRotation),
    /unauthorized|stale/,
  );
  const refreshedRotation = await linkedPage.evaluate(
    async (password) => window.client.refreshPendingDevice(password),
    password + ' linked rotation',
  );
  assert.notEqual(refreshedRotation.request.event.id, linkedRotation.request.event.id);
  assert.equal(refreshedRotation.deviceFingerprint, linkedRotation.deviceFingerprint);

  await a.page.evaluate(
    async (r) => window.client.authorizeLinked(r.request, r.deviceFingerprint),
    refreshedRotation,
  );
  const revokedLinked = await linkedPage.evaluate(
    async (password) => window.client.unlock(password),
    password + ' linked rotation',
  );
  assert.equal(revokedLinked.hasRoot, false);
  assert.equal(revokedLinked.devices.find((d) => d.id === linked.deviceId).generation, 2);
  await a.page.evaluate(() => {
    window.loseAck = true;
  });
  assert.match(
    await a.page.evaluate(async (linked) => {
      try {
        await window.client.revokeDevice(
          linked.deviceId,
          linked.deviceFingerprint,
          'revoke this exact device',
        );
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, revokedLinked),
    /lost acknowledgement/,
  );
  assert.equal((await a.page.evaluate(() => window.client.publicState())).pendingAuthority, true);
  assert.equal((await a.page.evaluate(async () => window.client.retryAuthority())).sequence, 5);
  assert.match(
    await linkedPage.evaluate(async () => {
      try {
        await window.client.publishPackages(1);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }),
    /retired|quarantined/,
  );
  await thirdPage.evaluate(async () =>
    window.client.discardPendingDevice('delete pending local keys even if already authorized'),
  );
  assert.match(
    await thirdPage.evaluate(async (password) => {
      try {
        await window.client.unlock(password);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, password),
    /No protected device/,
  );
  await thirdContext.close();
  await a.page.evaluate(
    async (third) =>
      window.client.revokeDevice(
        third.request.event.subject.id,
        third.deviceFingerprint,
        'revoke this exact device',
      ),
    third,
  );
  assert.match(
    await a.page.evaluate(async (first) => {
      try {
        await window.client.revokeDevice(
          first.deviceId,
          first.deviceFingerprint,
          'revoke this exact device',
        );
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, first),
    /unauthorized|stale/,
  );
  await linkedContext.close();
  const tab = await a.context.newPage();
  await tab.goto(origin + '/local-test');
  await tab.evaluate(async (account) => {
    const { createProtectedClient } = await import('/apps/portal/src/protected-client.mjs');
    window.other = createProtectedClient({
      account,
      api: () => {
        throw Error('not used');
      },
    });
    window.other.lock();
  }, a.account);
  await a.page.waitForFunction(() => {
    try {
      window.client.publicState();
      return false;
    } catch {
      return true;
    }
  });
  await a.page.evaluate(
    async ({ accountId, csrf }) => {
      window.client.close();
      const { mountProtected } = await import('/tests/browser/protected-ui-fixture.tsx');
      window.unmountProtected = mountProtected({
        accountId,
        csrf,
        role: 'volunteer',
        enabled: true,
        intakeEnabled: true,
      });
    },
    { accountId: a.account, csrf },
  );
  await a.page.getByRole('heading', { name: 'Protected messages.', exact: true }).waitFor();
  await a.page.getByLabel('Local unlock phrase (16 characters minimum)').fill(password);
  await a.page.getByRole('button', { name: 'Unlock this browser’s device', exact: true }).click();
  await a.page.getByText(/Device unlocked locally/).waitFor();
  await a.page.getByRole('button', { name: new RegExp(record.id + ' ·') }).click();
  await a.page.getByText('BROWSER_MLS_PRIVATE_NARRATIVE_7210', { exact: true }).waitFor();
  await a.page.getByText('BROWSER_MLS_PRIVATE_REPLY_7210', { exact: true }).waitFor();
  const exportDownload = a.page.waitForEvent('download');
  await a.page
    .getByRole('button', { name: 'Export this exact original-recipient ciphertext', exact: true })
    .click();
  const exported = await exportDownload,
    exportBytes = await readFile(await exported.path(), 'utf8');
  assert(!exportBytes.includes('BROWSER_MLS_PRIVATE_NARRATIVE_7210'));
  assert(!exportBytes.includes('PRIVATE KEY'));
  assert(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM g28.protected_lifecycle_events WHERE record_id=$1 AND action='mls_ciphertext_export'",
        [record.id],
      )
    ).rows[0].n >= 1,
  );
  await a.page.setViewportSize({ width: 360, height: 800 });
  assert(await a.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  assert.equal(await a.page.locator('iframe').count(), 0);
  await a.page.getByRole('button', { name: 'Lock device', exact: true }).click();
  assert.equal(
    await a.page.getByText('BROWSER_MLS_PRIVATE_NARRATIVE_7210', { exact: true }).count(),
    0,
    'locking clears rendered plaintext',
  );
  await a.page.evaluate(() => window.unmountProtected());
  const rotatedPhrase = password + ' rotated',
    rotated = await b.page.evaluate(
      async (password) =>
        window.client.rotateDevice(
          password,
          'Rotated synthetic root device',
          true,
          'rotate device and permanently lose old local history',
        ),
      rotatedPhrase,
    );
  assert.equal(rotated.completed, true);
  assert.equal(rotated.own.rootFingerprint, second.rootFingerprint);
  assert.equal(rotated.own.deviceId, second.deviceId);
  assert.notEqual(rotated.own.deviceFingerprint, second.deviceFingerprint);
  assert.equal(rotated.own.devices.find((d) => d.id === second.deviceId).generation, 2);
  const rotationLocal = await b.page.evaluate(async (account) => {
    const { protectedLocalList } = await import('/apps/portal/src/protected-local.mjs');
    return (await protectedLocalList(account)).map((r) => r.key);
  }, b.account);
  assert(
    rotationLocal.every((key) => !key.startsWith('thread:')),
    'rotation atomically deletes old local epoch/history vaults',
  );
  await b.page.evaluate(() => window.client.lock());
  await b.page.evaluate(async (password) => window.client.unlock(password), rotatedPhrase);
  const rotatedRow = (
    await pool.query('SELECT state,scope FROM g28.protected_devices WHERE id=$1', [second.deviceId])
  ).rows[0];
  assert.equal(rotatedRow.state, 'enrolled');
  assert.equal(rotatedRow.scope, null, 'key rotation never inherits staff recipient approval');
  assert.match(
    await b.page.evaluate(async (id) => {
      try {
        await window.client.synchronize(id);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, record.id),
    /original authority/,
  );
  await a.page.evaluate(async (password) => {
    window.client = window.makeClient();
    return window.client.unlock(password);
  }, password);
  const unchangedRoot = await a.page.evaluate(
    async (second) => window.client.peer(second.identityId, second.rootFingerprint),
    second,
  );
  assert.equal(
    unchangedRoot.verification.status,
    'verified',
    'ordinary root-authorized device rotation preserves root verification',
  );
  assert.match(
    await a.page.evaluate(async (id) => {
      try {
        await window.client.synchronize(id);
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, record.id),
    /original recipient device changed/,
  );
  const replacementPhrase = password + ' replacement';
  await b.page.evaluate(() => {
    window.loseAck = true;
  });
  assert.match(
    await b.page.evaluate(async (password) => {
      try {
        await window.client.replaceRoot(
          password,
          'Replacement synthetic root',
          true,
          'replace root and permanently lose old local history',
        );
        return 'unexpected';
      } catch (e) {
        return e.message;
      }
    }, replacementPhrase),
    /lost acknowledgement/,
  );
  const replacement = await b.page.evaluate(
    async (password) => window.client.unlock(password),
    replacementPhrase,
  );
  assert.notEqual(replacement.identityId, second.identityId);
  assert.notEqual(replacement.rootFingerprint, second.rootFingerprint);
  const changedRoot = await a.page.evaluate(
    async (replacement) => window.client.peer(replacement.identityId, replacement.rootFingerprint),
    replacement,
  );
  assert.equal(
    changedRoot.verification.status,
    'invalidated',
    'root replacement cannot inherit verified contact trust',
  );
  assert.equal(
    (
      await pool.query('SELECT current FROM g28.protected_identities WHERE id=$1', [
        second.identityId,
      ])
    ).rows[0].current,
    false,
  );
  const afterReplacement = await b.page.evaluate(async (account) => {
    const { protectedLocalList } = await import('/apps/portal/src/protected-local.mjs');
    return (await protectedLocalList(account)).map((r) => r.key);
  }, b.account);
  assert(
    afterReplacement.every((key) => !key.startsWith('thread:')),
    'explicit rotation/replacement deletes only the owner’s old local thread vaults',
  );
  // A second account in the same browser gets a distinct encrypted storage key.
  const isolated = await a.page.evaluate(async (account) => {
    const { protectedLocalGet, deviceEntry } = await import('/apps/portal/src/protected-local.mjs');
    return await protectedLocalGet(deviceEntry(account));
  }, b.account);
  assert.equal(isolated, null);
  // Exercise the actual portal Shell/Settings, not a mocked logout helper.
  await a.page.setViewportSize({ width: 1280, height: 900 });
  await a.page.evaluate(async () => {
    window.client.close();
    history.replaceState({}, '', '/protected');
    const div = document.createElement('div');
    div.id = 'root';
    document.body.append(div);
    await import('/apps/portal/src/main.tsx');
  });
  await a.page.getByLabel('Local unlock phrase (16 characters minimum)').fill(password);
  await a.page.getByRole('button', { name: 'Unlock this browser’s device', exact: true }).click();
  await a.page.getByText(/Device unlocked locally/).waitFor();
  const beforeLogout = await a.page.evaluate(async (account) => {
    const { protectedLocalGet, deviceEntry } = await import('/apps/portal/src/protected-local.mjs');
    return protectedLocalGet(deviceEntry(account));
  }, a.account);
  await a.page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await a.page.getByRole('heading', { name: 'Start here.', exact: true }).waitFor();
  assert.deepEqual(
    await a.page.evaluate(async (account) => {
      const { protectedLocalGet, deviceEntry } =
        await import('/apps/portal/src/protected-local.mjs');
      return protectedLocalGet(deviceEntry(account));
    }, a.account),
    beforeLogout,
    'normal sign-out must lock without deleting or rewriting encrypted protected keys',
  );
  const returnToken = randomToken(),
    returnCsrf = randomToken();
  await pool.query(
    'INSERT INTO g28.sessions(token_hash,account_id,csrf_token,expires_at) VALUES($1,$2,$3,$4)',
    [tokenHash(returnToken), a.account, returnCsrf, new Date(Date.now() + 86400000)],
  );
  await a.context.addCookies([
    { name: 'g28-local', value: returnToken, url: origin, httpOnly: true, sameSite: 'Lax' },
  ]);
  await a.page.goto(origin + '/local-test');
  await a.page.evaluate(async () => {
    history.replaceState({}, '', '/settings');
    const div = document.createElement('div');
    div.id = 'root';
    document.body.append(div);
    await import('/apps/portal/src/main.tsx');
  });
  await a.page.getByRole('heading', { name: 'Account settings.', exact: true }).waitFor();
  await a.page.getByRole('button', { name: 'Sign out everywhere', exact: true }).click();
  await a.page.getByRole('heading', { name: 'Start here.', exact: true }).waitFor();
  assert.deepEqual(
    await a.page.evaluate(async (account) => {
      const { protectedLocalGet, deviceEntry } =
        await import('/apps/portal/src/protected-local.mjs');
      return protectedLocalGet(deviceEntry(account));
    }, a.account),
    beforeLogout,
    'global session revocation must preserve encrypted local keys too',
  );
  await b.page.evaluate(async () => {
    window.client.close();
    history.replaceState({}, '', '/settings');
    const div = document.createElement('div');
    div.id = 'root';
    document.body.append(div);
    await import('/apps/portal/src/main.tsx');
  });
  await b.page.getByRole('heading', { name: 'Account settings.', exact: true }).waitFor();
  await b.page.getByLabel('Type “close my account” to confirm').fill('close my account');
  await b.page.getByRole('button', { name: 'Close my account', exact: true }).click();
  await b.page
    .getByText('Administrator accounts require a reviewed offboarding process.', { exact: true })
    .waitFor();
  assert(
    await b.page.evaluate(async (account) => {
      const { protectedLocalGet, deviceEntry } =
        await import('/apps/portal/src/protected-local.mjs');
      return !!(await protectedLocalGet(deviceEntry(account)));
    }, b.account),
    'a rejected staff-account closure cannot erase local keys',
  );
  config.adminOwnerEmailKey = tokenHash(randomUUID());
  await b.page.getByRole('button', { name: 'Close my account', exact: true }).click();
  await b.page.getByRole('heading', { name: 'Start here.', exact: true }).waitFor();
  assert.equal(
    await b.page.evaluate(async (account) => {
      const { protectedLocalGet, deviceEntry } =
        await import('/apps/portal/src/protected-local.mjs');
      return protectedLocalGet(deviceEntry(account));
    }, b.account),
    null,
    'explicit account closure removes its encrypted local keys',
  );
  for (const actor of actors)
    for (const body of actor.requests) {
      for (const forbidden of [
        password,
        'PRIVATE KEY',
        'privateKey',
        'MUST_NOT_SEND_PRIVATE_FIELD_7210',
        'BROWSER_MLS_PRIVATE_NARRATIVE_7210',
        'PRIVATE_FILE_CANARY_7210',
      ])
        assert(
          !body.includes(forbidden),
          'all lifecycle network bodies exclude private material: ' + forbidden,
        );
    }
  console.log(
    'Protected local/lifecycle browser passed (signed revocation retry, root/linked-device rotation, no approval/history inheritance, lost-ACK root replacement and audited item export): encrypted-only IndexedDB, no private-key/report/attachment egress, lost enrollment/message ACK retries, root/device linking without inherited history, mutual verification, actual MLS replies, concurrent epoch reconciliation, inert attachments, cross-tab lock and mobile UI plaintext clearing.',
  );
} finally {
  await browser?.close();
  await vite?.close();
  await rm('/tmp/' + name + '-vite', { recursive: true, force: true });
  await app.close();
  await pool.end();
  await admin.query('DROP DATABASE ' + name);
  await admin.end();
}
