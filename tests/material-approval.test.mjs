import test from "node:test";
import assert from "node:assert/strict";
import {
  canReadMaterial,
  materialSearch,
  publishDraft,
} from "../packages/core/content.mjs";
import { validateMaterialRelease } from "../packages/core/material-publication.mjs";
import { readableVersion } from "../packages/core/material-reading.mjs";

const account = { verified: true };
const actor = { scopes: ["content:publish"] };
const record = () => ({
  id: "guide",
  title: "Synthetic guide",
  description: "Reviewed description",
  category: "start",
  body: "Reviewed body",
  audience: "volunteer",
  status: "published",
  author: "fixture-author",
  revision: 1,
  review: {
    approvedBy: "fixture-reviewer",
    revision: 1,
    at: "2026-10-10T00:00:00Z",
  },
});

test("independent dated approval works consistently for release, read, search, acknowledgment and publication", () => {
  const material = record();
  assert.equal(validateMaterialRelease([material]).length, 1);
  assert.equal(canReadMaterial(material, account), true);
  assert.equal(materialSearch([material], "", "all", account).length, 1);
  assert.equal(readableVersion(material, account).revision, 1);
  assert.equal(
    publishDraft({ ...material, status: "draft" }, material.review, actor)
      .status,
    "published",
  );
});

const mutations = {
  "missing author": (m) => {
    delete m.author;
  },
  "empty author": (m) => {
    m.author = " ";
  },
  "non-string author": (m) => {
    m.author = { id: "author" };
  },
  "empty reviewer": (m) => {
    m.review.approvedBy = " ";
  },
  "non-string reviewer": (m) => {
    m.review.approvedBy = { id: "reviewer" };
  },
  "self approval": (m) => {
    m.review.approvedBy = m.author;
  },
  "padded self approval": (m) => {
    m.review.approvedBy = " " + m.author + " ";
  },
  "missing date": (m) => {
    delete m.review.at;
  },
  "invalid date": (m) => {
    m.review.at = "not-a-date";
  },
  "non-string date": (m) => {
    m.review.at = 1;
  },
  "future date": (m) => {
    m.review.at = "2999-01-01T00:00:00Z";
  },
  "stale revision": (m) => {
    m.review.revision = 2;
  },
  "string revision": (m) => {
    m.revision = m.review.revision = "1";
  },
  "zero revision": (m) => {
    m.revision = m.review.revision = 0;
  },
};
for (const [name, mutate] of Object.entries(mutations))
  test(name + " cannot enter any current-material surface", () => {
    const material = record();
    mutate(material);
    assert.equal(canReadMaterial(material, account), false);
    assert.deepEqual(materialSearch([material], "", "all", account), []);
    assert.throws(() => readableVersion(material, account));
    assert.throws(() => validateMaterialRelease([material]));
    assert.throws(() =>
      publishDraft({ ...material, status: "draft" }, material.review, actor),
    );
  });

test("truthy verification or scope strings cannot stand in for real account and permission types", () => {
  for (const verified of ["true", 1, {}, null])
    assert.equal(canReadMaterial(record(), { verified }), false);
  assert.equal(canReadMaterial(null, account), false);
  assert.throws(() =>
    publishDraft(record(), record().review, { scopes: "content:publish" }),
  );
});

test("published metadata has bounded, typed descriptions, categories and canonical video identifiers", () => {
  for (const patch of [
    { description: {} },
    { description: "x".repeat(1001) },
    { category: {} },
    { category: "../private" },
    { youtubeId: "https://youtu.be/AbcdefG123_" },
    { youtubeId: "javascript:alert(1)" },
  ])
    assert.throws(() => validateMaterialRelease([{ ...record(), ...patch }]));
  assert.equal(
    validateMaterialRelease([{ ...record(), youtubeId: "AbcdefG123_" }]).length,
    1,
  );
});
