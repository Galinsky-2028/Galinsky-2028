import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { validateMaterialRelease } from "./material-publication.mjs";

// Only PUBLIC verification keys are committed. Private signing keys remain
// with independently authorized human operators, off the application server.
export function materialDigest(material) {
  const required = [
    "id",
    "revision",
    "title",
    "description",
    "body",
    "category",
    "youtubeId",
    "audience",
    "status",
    "author",
  ];
  const payload = Object.fromEntries(required.map((k) => [k, material[k]]));
  return createHash("sha256")
    .update(JSON.stringify(payload), "utf8")
    .digest("hex");
}
function statement(record, role, keyId, signedAt) {
  return Buffer.from(
    [
      "G28-SIGNED-MATERIAL-V2",
      role,
      keyId,
      signedAt,
      materialDigest(record),
      "",
    ].join("\n"),
    "utf8",
  );
}
function exactTimestamp(value, now) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
  )
    throw new Error("Approval requires an exact UTC ISO timestamp");
  const t = Date.parse(value);
  if (!Number.isFinite(t) || t > now + 300000 || t < now - 90 * 86400000)
    throw new Error("Approval expired or issued in the future");
}
function registryKeys(registry) {
  if (!registry || registry.version !== 1 || !Array.isArray(registry.keys))
    throw new Error("Invalid staff verification key registry");
  const byId = new Map();
  for (const k of registry.keys) {
    if (
      !k ||
      !/^staff-[a-z0-9-]{5,64}$/.test(k.id) ||
      byId.has(k.id) ||
      typeof k.subject !== "string" ||
      !k.subject.trim() ||
      !["author", "reviewer"].includes(k.role) ||
      typeof k.publicKeyPem !== "string"
    )
      throw new Error("Invalid or duplicate staff key");
    const key = createPublicKey(k.publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519")
      throw new Error("Staff signatures require Ed25519 keys");
    byId.set(k.id, { ...k, key });
  }
  return byId;
}
export function signStaffApproval(
  record,
  { role, keyId, privateKeyPem, signedAt = new Date().toISOString() },
) {
  if (!["author", "reviewer"].includes(role) || typeof keyId !== "string")
    throw new Error("Invalid signing role or key ID");
  exactTimestamp(signedAt, Date.now());
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519")
    throw new Error("Ed25519 private key required");
  return {
    keyId,
    signedAt,
    signature: sign(
      null,
      statement(record, role, keyId, signedAt),
      key,
    ).toString("base64"),
  };
}
export function validateSignedMaterialRelease(
  records,
  registry,
  { now = Date.now() } = {},
) {
  validateMaterialRelease(records);
  const keys = registryKeys(registry);
  for (const item of records) {
    const approved = item.approvals;
    if (
      !approved ||
      typeof approved !== "object" ||
      Array.isArray(approved) ||
      Object.keys(approved).sort().join(",") !== "author,reviewer"
    )
      throw new Error(
        "Independent author and reviewer signatures are required",
      );
    const actors = [];
    for (const role of ["author", "reviewer"]) {
      const a = approved[role];
      if (
        !a ||
        typeof a !== "object" ||
        typeof a.keyId !== "string" ||
        typeof a.signature !== "string" ||
        !/^[A-Za-z0-9+/]{86}==?$/.test(a.signature)
      )
        throw new Error("Missing or malformed approval signature");
      exactTimestamp(a.signedAt, now);
      const staff = keys.get(a.keyId);
      if (!staff || staff.active !== true || staff.role !== role)
        throw new Error("Signer not currently authorized for this role");
      const signature = Buffer.from(a.signature, "base64");
      if (
        signature.length !== 64 ||
        !verify(
          null,
          statement(item, role, a.keyId, a.signedAt),
          staff.key,
          signature,
        )
      )
        throw new Error(
          "Approval signature did not match this exact material revision",
        );
      actors.push(staff);
    }
    if (
      actors[0].id === actors[1].id ||
      actors[0].subject === actors[1].subject
    )
      throw new Error("A separate human reviewer is required");
    if (
      item.author !== actors[0].subject ||
      item.review.approvedBy !== actors[1].subject ||
      item.review.at !== approved.reviewer.signedAt
    )
      throw new Error(
        "Signed identities, revision review and publication metadata disagree",
      );
  }
  return records;
}
