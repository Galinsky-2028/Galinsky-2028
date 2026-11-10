import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const fail = (message) => {
  throw new Error("Security contract: " + message);
};
const require = (condition, message) => {
  if (!condition) fail(message);
};
const text = (value) => typeof value === "string" && value.trim().length > 0;
const safePath = (value) =>
  text(value) &&
  !value.startsWith("/") &&
  !value.includes("\\") &&
  value.split("/").every((p) => p && p !== "." && p !== "..");
const controlPath = "scripts/security-contract.mjs";
export const sourceScopes = ["apps", "packages", "scripts", "db/migrations"];
export function sourcePaths(root) {
  const paths = [];
  function visit(relative) {
    for (const entry of readdirSync(join(root, relative), {
      withFileTypes: true,
    })) {
      const path = relative + "/" + entry.name;
      if (entry.isDirectory()) {
        // Dependency/build caches are not checked-in application source.
        if (!["node_modules", ".astro"].includes(entry.name)) visit(path);
      }
      else if (
        entry.isFile() &&
        /\.(?:mjs|js|ts|tsx|astro|sql|py)$/.test(path) &&
        path !== controlPath
      )
        paths.push(path);
      else if (entry.isSymbolicLink()) fail("symlink in source scope: " + path);
    }
  }
  for (const scope of sourceScopes) visit(scope);
  return paths.sort();
}
export function blobSha(bytes) {
  return createHash("sha1")
    .update("blob " + bytes.length + "\0")
    .update(bytes)
    .digest("hex");
}
function unique(items, name) {
  require(Array.isArray(items) && items.length > 0, name +
    " must not be empty");
  const ids = items.map((x) => x.id);
  require(ids.every(text) && new Set(ids).size === ids.length, name +
    " identifiers must be unique");
  return new Map(items.map((x) => [x.id, x]));
}

// Deliberately narrow PostgreSQL DDL reader, not a SQL executor. It accepts the
// checked-in CREATE TABLE/ADD COLUMN forms and rejects ambiguous definitions.
// Values and comments cannot introduce phantom columns or table delimiters.
function unquoteSql(sql) {
  let out = "",
    i = 0;
  while (i < sql.length) {
    if (sql.startsWith("--", i)) {
      while (i < sql.length && sql[i] !== "\n") i++;
      out += " ";
    } else if (sql.startsWith("/*", i)) {
      let depth = 1;
      i += 2;
      while (i < sql.length && depth) {
        if (sql.startsWith("/*", i)) {
          depth++;
          i += 2;
        } else if (sql.startsWith("*/", i)) {
          depth--;
          i += 2;
        } else i++;
      }
      require(depth === 0, "unterminated SQL comment");
      out += " ";
    } else if (sql[i] === "'") {
      i++;
      let closed = false;
      while (i < sql.length) {
        if (sql[i] !== "'") i++;
        else if (sql[i + 1] === "'") i += 2;
        else {
          i++;
          closed = true;
          break;
        }
      }
      require(closed, "unterminated SQL string");
      out += "''";
    } else out += sql[i++];
  }
  return out;
}
function fields(body) {
  let depth = 0,
    start = 0;
  const parts = [];
  for (let i = 0; i < body.length; i++) {
    if (body[i] === "(") depth++;
    if (body[i] === ")") depth--;
    if (body[i] === "," && depth === 0) {
      parts.push(body.slice(start, i));
      start = i + 1;
    }
    require(depth >= 0, "unbalanced table definition");
  }
  require(depth === 0, "unbalanced table definition");
  parts.push(body.slice(start));
  return parts.flatMap((part) => {
    if (/^\s*(?:CONSTRAINT|PRIMARY|FOREIGN|UNIQUE|CHECK|EXCLUDE)\b/i.test(part))
      return [];
    const match = part.match(
      /^\s*(?:"([A-Za-z_][A-Za-z0-9_]*)"|([a-z_][a-z0-9_]*))\s+\S/i,
    );
    require(match, "unrecognized column declaration");
    return [match[1] || match[2].toLowerCase()];
  });
}
export function storageFields(sources) {
  const tables = new Map();
  for (const { path, source } of sources) {
    const sql = unquoteSql(source);
    const pattern =
      /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:[a-z_][\w]*\.)?[a-z_][\w]*)\s*\(/gi;
    for (const match of sql.matchAll(pattern)) {
      let depth = 1,
        end = match.index + match[0].length;
      const start = end;
      while (end < sql.length && depth) {
        if (sql[end] === "(") depth++;
        if (sql[end] === ")") depth--;
        end++;
      }
      require(depth === 0, "unterminated table in " + path);
      const id = match[1].toLowerCase();
      require(!tables.has(id), "duplicate table declaration: " + id);
      tables.set(id, {
        id,
        columns: fields(sql.slice(start, end - 1)),
        paths: [path],
      });
    }
    for (const match of sql.matchAll(
      /ALTER\s+TABLE\s+([a-z_][\w.]+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([A-Za-z_][A-Za-z0-9_]*)"|([a-z_][\w]*))/gi,
    )) {
      const table = tables.get(match[1].toLowerCase());
      require(table, "ALTER references an unknown table: " + match[1]);
      const column = match[2] || match[3].toLowerCase();
      require(!table.columns.includes(column), "duplicate column: " +
        table.id +
        "." +
        column);
      table.columns.push(column);
      if (!table.paths.includes(path)) table.paths.push(path);
    }
  }
  return [...tables.values()]
    .map((t) => ({ ...t, columns: t.columns.sort(), paths: t.paths.sort() }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

export function validateContract(contract, { paths, read }) {
  require(contract?.schemaVersion === 1, "unsupported schema");
  require(contract.repository ===
    "neophilism/Galinsky-2028", "repository mismatch");
  require(/^[a-f0-9]{40}$/.test(
    contract.sourceCommit,
  ), "immutable source commit required");
  require(contract.standard?.repository ===
    "neophilism/End-To-End-Everywhere-Security-Architecture-Standard" &&
    /^[a-f0-9]{40}$/.test(contract.standard.commit) &&
    contract.standard.basis ===
      "development", "pinned development basis required");
  require(contract.productionE2eeClaim === false &&
    contract.certificationClaim === false &&
    contract.runtimeCoverageVerified ===
      false, "source contract cannot certify runtime or E2EE");
  const components = unique(contract.components, "components");
  const decisions = unique(contract.profileDecisions, "profile decisions");
  const flows = unique(contract.flows, "flows");
  for (const id of [
    "recipient-enrollment",
    "protected-submission",
    "protected-attachment",
    "key-recovery",
    "protected-export",
  ])
    require(flows.has(id) &&
      flows.get(id).classification ===
        "protected", "protected obligation missing: " + id);
  const storage = unique(contract.storage, "storage");
  const source = contract.sourceFiles;
  require(Array.isArray(source), "source files required");
  const actual = [...paths].sort();
  const listed = source.map((x) => x.path).sort();
  require(new Set(listed).size === listed.length &&
    JSON.stringify(actual) ===
      JSON.stringify(
        listed,
      ), "source coverage changed; review new, removed or renamed files");
  for (const file of source) {
    require(safePath(file.path) &&
      components.has(
        file.componentId,
      ), "unknown source component or unsafe path");
    require(/^[a-f0-9]{40}$/.test(file.blobSha) &&
      blobSha(read(file.path)) ===
        file.blobSha, "source changed; review binding for " + file.path);
  }
  for (const component of components.values()) {
    require(source.some((x) => x.componentId === component.id) ||
      component.blocked === true, "component has no source: " + component.id);
    require(text(component.purpose) &&
      text(component.trustBoundary), "component boundary required");
  }
  for (const decision of decisions.values()) {
    require([
      "public",
      "server-readable",
      "local-only",
      "protected-blocked",
      "protected-client-encrypted",
    ].includes(decision.mode) &&
      text(decision.rationale), "unknown or undocumented profile decision");
    if (decision.mode === "protected-blocked")
      require(decision.enabled === false &&
        decision.profilePin === null &&
        Array.isArray(decision.requiredEvidence) &&
        decision.requiredEvidence.length >=
          4, "protected profile must fail closed");
    if (decision.mode === "protected-client-encrypted") {
      const lock=JSON.parse(read("package-lock.json"));
      require(decision.profilePin === "G28-PGP-1/openpgp-6.3.2" &&
        decision.privateKeyCustody === "recipient-device-only" &&
        decision.plaintextFallback === false &&
        decision.dependencyIntegrity === lock.packages["node_modules/openpgp"]?.integrity &&
        lock.packages[""].dependencies.openpgp === "6.3.2" &&
        decision.review === "docs/security/PROTECTED_PROFILE.md",
        "protected profile must fail closed on a changed protocol, dependency, custody or review");
    }
  }
  for (const flow of flows.values()) {
    require(components.has(flow.componentId) &&
      decisions.has(
        flow.profileDecision,
      ), "flow has unknown component/profile");
    for (const key of ["fields", "recipients", "storage", "egress", "evidence"])
      require(Array.isArray(flow[key]) &&
        flow[key].length > 0 &&
        flow[key].every(text), "flow " + flow.id + " missing " + key);
    require(text(flow.from) &&
      text(flow.authorization) &&
      text(flow.retention), "flow boundary/retention required");
    require(flow.storage.every(
      (id) => id === "none" || storage.has(id),
    ), "flow references unknown storage");
    require(flow.evidence.every(
      (path) => safePath(path) && listed.includes(path),
    ), "flow evidence must be source-bound");
    if (flow.classification === "protected")
      require(((flow.blocked === true && decisions.get(flow.profileDecision).mode === "protected-blocked") ||
        (flow.blocked === false && decisions.get(flow.profileDecision).mode === "protected-client-encrypted")) &&
        flow.plaintextFallback ===
          false, "protected flow cannot be downgraded to server processing");
    else
      require([
        "public",
        "restricted-material",
        "identity-metadata",
        "operational-metadata",
        "financial",
        "local-only",
      ].includes(flow.classification), "unreviewed data classification");
  }
  for (const component of components.values())
    require([...flows.values()].some(
      (f) => f.componentId === component.id,
    ), "component has no flow");
  for (const record of storage.values()) {
    require(text(record.authority) &&
      text(record.retention) &&
      text(record.disposal) &&
      text(record.classification), "storage lifecycle required");
    require(Array.isArray(record.columns) &&
      record.columns.length > 0 &&
      new Set(record.columns).size ===
        record.columns.length, "storage fields required");
    require(Array.isArray(record.paths) &&
      record.paths.length > 0 &&
      record.paths.every((p) =>
        listed.includes(p),
      ), "storage evidence required");
  }
  const ddl = storageFields(
    source
      .filter((x) => x.path.endsWith(".sql"))
      .sort((a, b) => a.path.localeCompare(b.path))
      .map((x) => ({ path: x.path, source: read(x.path).toString("utf8") })),
  );
  const recorded = [...storage.values()]
    .filter((s) => s.kind === "postgres-table")
    .map(({ id, columns, paths }) => ({
      id,
      columns: [...columns].sort(),
      paths: [...paths].sort(),
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
  require(JSON.stringify(ddl) ===
    JSON.stringify(
      recorded,
    ), "database field coverage changed; review storage contract");
  require([...storage.values()].every((s) =>
    [...flows.values()].some((f) => f.storage.includes(s.id)),
  ), "storage lacks a mapped flow");
  return {
    sourceFiles: source.length,
    components: components.size,
    flows: flows.size,
    storageRecords: storage.size,
  };
}

export function validateRepository(root) {
  const contract = JSON.parse(
    readFileSync(join(root, "security/source-flow-contract.json"), "utf8"),
  );
  const status = JSON.parse(
    readFileSync(join(root, "security/e2eesa-status.json"), "utf8"),
  );
  const inventory = JSON.parse(
    readFileSync(join(root, "security/e2eesa-inventory.json"), "utf8"),
  );
  for (const basis of [status.standard, inventory.standardBasis])
    require(basis?.repository === contract.standard.repository &&
      basis?.commit ===
        contract.standard
          .commit, "upstream pin differs from canonical inventory/status");
  return validateContract(contract, {
    paths: sourcePaths(root),
    read: (path) => readFileSync(join(root, path)),
  });
}
