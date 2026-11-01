import test from "node:test";
import assert from "node:assert/strict";
import {
  readFileSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  validateRepository,
  validateContract,
  sourcePaths,
  storageFields,
} from "../scripts/security-contract.mjs";
import { loadConfig } from "../apps/api/src/config.mjs";
import { blobSha } from "../scripts/security-contract.mjs";

const contract = JSON.parse(
  readFileSync("security/source-flow-contract.json", "utf8"),
);
const inputs = {
  paths: sourcePaths(process.cwd()),
  read: (path) => readFileSync(path),
};
const check = (value) => validateContract(value, inputs);
const modified = (change) => {
  const value = structuredClone(contract);
  change(value);
  return value;
};

test("checked-in source and database fields have a current, non-certifying contract", () => {
  const result = validateRepository(process.cwd());
  assert.equal(result.sourceFiles, inputs.paths.length);
  assert(result.storageRecords >= 50);
  assert(result.flows >= 20);
});

test("new, removed, renamed and modified source cannot reuse an old assessment", () => {
  assert.throws(
    () =>
      validateContract(contract, {
        ...inputs,
        paths: [...inputs.paths, "apps/api/src/new-egress.mjs"],
      }),
    /source coverage changed/,
  );
  assert.throws(
    () =>
      validateContract(contract, { ...inputs, paths: inputs.paths.slice(1) }),
    /source coverage changed/,
  );
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.sourceFiles[0].path += ".renamed";
        }),
      ),
    /source coverage changed/,
  );
  assert.throws(
    () =>
      validateContract(contract, {
        ...inputs,
        read: (path) =>
          path === contract.sourceFiles[0].path
            ? Buffer.from("changed source")
            : inputs.read(path),
      }),
    /source changed/,
  );
  assert.throws(
    () => check(modified((c) => c.sourceFiles.push(c.sourceFiles[0]))),
    /source coverage changed/,
  );
});

test("source walker discovers new executable files and rejects symlinked scope", () => {
  const root = mkdtempSync(join(tmpdir(), "g28-security-"));
  try {
    for (const path of ["apps", "packages", "scripts", "db/migrations"])
      mkdirSync(join(root, path), { recursive: true });
    writeFileSync(join(root, "apps/new.ts"), "export const value = 1;");
    writeFileSync(
      join(root, "scripts/security-contract.mjs"),
      "// integrity control excluded from its own hash",
    );
    assert.deepEqual(sourcePaths(root), ["apps/new.ts"]);
    symlinkSync(join(root, "apps/new.ts"), join(root, "apps/linked.ts"));
    assert.throws(() => sourcePaths(root), /symlink/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

for (const id of [
  "recipient-enrollment",
  "protected-submission",
  "protected-attachment",
  "key-recovery",
  "protected-export",
]) {
  test(
    id +
      " cannot be omitted, enabled or downgraded to plaintext service processing",
    () => {
      assert.throws(
        () =>
          check(
            modified((c) => {
              c.flows = c.flows.filter((f) => f.id !== id);
            }),
          ),
        /protected obligation missing/,
      );
      assert.throws(
        () =>
          check(
            modified((c) => {
              c.flows.find((f) => f.id === id).classification =
                "identity-metadata";
            }),
          ),
        /protected obligation missing/,
      );
      for (const patch of [
        { blocked: false },
        { plaintextFallback: true },
        { profileDecision: "server" },
      ])
        assert.throws(
          () =>
            check(
              modified((c) =>
                Object.assign(
                  c.flows.find((f) => f.id === id),
                  patch,
                ),
              ),
            ),
          /cannot be downgraded/,
        );
    },
  );
}

test("unknown profiles and invented production eligibility fail closed", () => {
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.flows[0].profileDecision = "unknown";
        }),
      ),
    /unknown component\/profile/,
  );
  for (const patch of [
    { enabled: true },
    { profilePin: "invented-production-profile" },
    { requiredEvidence: [] },
  ])
    assert.throws(
      () =>
        check(
          modified((c) =>
            Object.assign(
              c.profileDecisions.find((p) => p.id === "protected"),
              patch,
            ),
          ),
        ),
      /fail closed/,
    );
  for (const key of [
    "productionE2eeClaim",
    "certificationClaim",
    "runtimeCoverageVerified",
  ])
    assert.throws(
      () =>
        check(
          modified((c) => {
            c[key] = true;
          }),
        ),
      /cannot certify/,
    );
});

test("the actual runtime cannot enable a missing protected adapter", () => {
  assert.throws(
    () => loadConfig({ PROTECTED_CONTENT_ENABLED: "true" }),
    (error) => error.code === "protected_unavailable" && error.status === 503,
  );
});

test("a reviewed SQL source change still needs a matching field inventory", () => {
  const path = "db/migrations/001_foundation.sql";
  const changed = Buffer.from(
    inputs
      .read(path)
      .toString("utf8")
      .replace(
        "email_key text UNIQUE",
        "new_personal_field text, email_key text UNIQUE",
      ),
  );
  const value = modified((c) => {
    c.sourceFiles.find((f) => f.path === path).blobSha = blobSha(changed);
  });
  assert.throws(
    () =>
      validateContract(value, {
        ...inputs,
        read: (p) => (p === path ? changed : inputs.read(p)),
      }),
    /database field coverage changed/,
  );
});

test("unmapped recipients, fields, egress, lifecycle, evidence and storage are rejected", () => {
  for (const key of ["fields", "recipients", "storage", "egress", "evidence"])
    assert.throws(
      () =>
        check(
          modified((c) => {
            c.flows[0][key] = [];
          }),
        ),
      /missing/,
    );
  for (const key of ["from", "authorization", "retention"])
    assert.throws(
      () =>
        check(
          modified((c) => {
            c.flows[0][key] = "";
          }),
        ),
      /boundary\/retention/,
    );
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.flows[0].storage = ["unknown-store"];
        }),
      ),
    /unknown storage/,
  );
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.flows[0].evidence = ["../outside.mjs"];
        }),
      ),
    /source-bound/,
  );
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.storage[0].retention = "";
        }),
      ),
    /storage lifecycle/,
  );
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.storage[0].columns.push("unreviewed_personal_field");
        }),
      ),
    /database field coverage changed/,
  );
  assert.throws(
    () =>
      check(
        modified((c) => {
          c.flows.push(c.flows[0]);
        }),
      ),
    /identifiers must be unique/,
  );
});

test("DDL discovery handles quoted fields, constraints, comments, strings and later added columns", () => {
  assert.deepEqual(
    storageFields([
      {
        path: "db/migrations/1.sql",
        source: `-- CREATE TABLE fake(x text);\nCREATE TABLE g28.example("userId" text, record jsonb DEFAULT '{"x": "--not a comment, (value)"}', n integer CHECK(n IN(1,2)), CONSTRAINT p PRIMARY KEY("userId")); /* CREATE TABLE fake(x text); */`,
      },
      {
        path: "db/migrations/2.sql",
        source:
          "ALTER TABLE g28.example ADD COLUMN IF NOT EXISTS expires_at timestamptz;",
      },
    ]),
    [
      {
        id: "g28.example",
        columns: ["expires_at", "n", "record", "userId"],
        paths: ["db/migrations/1.sql", "db/migrations/2.sql"],
      },
    ],
  );
  for (const source of [
    "CREATE TABLE g28.bad(a text",
    "CREATE TABLE g28.bad(a text, PRIMARY KEY(a)); ALTER TABLE g28.missing ADD COLUMN x text;",
    "CREATE TABLE g28.bad(a text DEFAULT 'unterminated)",
    "/* unterminated",
  ])
    assert.throws(
      () => storageFields([{ path: "bad.sql", source }]),
      /Security contract:/,
    );
});
