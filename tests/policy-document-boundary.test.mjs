import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  renderSafePolicyHtml,
  isSafePolicyHtml,
} from "../packages/core/safe-policy-document.mjs";
import { publishedPolicyDocuments } from "../packages/core/policy-documents.mjs";
const render = () =>
  renderSafePolicyHtml({
    title: "Synthetic policy",
    source:
      "# First section\n\n[Safe link](https://example.test/?a=1&b=2)\n\n## Second section\n\n| Field | Value |\n| --- | --- |\n| Test | Safe |\n\n> Quote\n\n- Item",
  });
function fixture(fn) {
  const dir = mkdtempSync(join(tmpdir(), "g28-document-boundary-"));
  const root = join(dir, "public");
  mkdirSync(join(root, "documents"), { recursive: true });
  const file = join(root, "documents", "kirk-evers-summary-v1.html");
  const record = (bytes) => ({
    id: "summary-1",
    kind: "summary",
    label: "Reviewed synthetic summary",
    description: "Fixture only",
    path: "/documents/kirk-evers-summary-v1.html",
    revision: 1,
    status: "published",
    author: "fixture-author",
    review: {
      approvedBy: "fixture-reviewer",
      revision: 1,
      at: "2026-10-10T00:00:00Z",
    },
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
  try {
    return fn({ dir, root, file, record });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
test("actual generated documents retain accessible links, tables and restrictive security envelope", () =>
  fixture(({ root, file, record }) => {
    const html = render();
    assert.equal(isSafePolicyHtml(html), true);
    writeFileSync(file, html);
    assert.equal(
      publishedPolicyDocuments("kirk-evers", [record(html)], root).length,
      1,
    );
  }));
const attacks = {
  "weakened CSP": (h) =>
    h.replace("default-src &#39;none&#39;", "default-src *"),
  "late CSP": (h) =>
    h.replace(
      '<meta http-equiv="Content-Security-Policy"',
      '<!-- <meta http-equiv="Content-Security-Policy"',
    ),
  "event handler": (h) =>
    h.replace("<article>", '<article onclick="alert(1)">'),
  "unquoted event handler": (h) =>
    h.replace("<article>", "<article onmouseover=alert(1)>"),
  "quoted delimiter handler": (h) =>
    h.replace("<article>", '<article class=">" onclick="alert(1)">'),
  "refresh redirect": (h) =>
    h.replace(
      "<article>",
      '<article><meta http-equiv="refresh" content="0;url=https://example.test">',
    ),
  script: (h) => h.replace("<article>", "<article><script>alert(1)</script>"),
  "external image": (h) =>
    h.replace("<article>", '<article><img src="https://example.test/pixel">'),
  "active SVG": (h) =>
    h.replace("<article>", '<article><svg onload="alert(1)"></svg>'),
  "JavaScript URL": (h) =>
    h.replace("https://example.test/?a=1&amp;b=2", "javascript:alert(1)"),
  "entity encoded URL": (h) =>
    h.replace("https://example.test/?a=1&amp;b=2", "&#106;avascript:alert(1)"),
  "protocol-relative URL": (h) =>
    h.replace("https://example.test/?a=1&amp;b=2", "//example.test/tracker"),
  "opener access": (h) =>
    h.replace('rel="noopener noreferrer"', 'rel="opener"'),
  "altered style": (h) =>
    h.replace("<style>", '<style>@import "https://example.test/style";'),
  "nested tag": (h) =>
    h.replace("<article>", "<article <script>alert(1)</script>>"),
};
for (const [name, mutate] of Object.entries(attacks))
  test(name + " rejected even with matching digest and approval", () =>
    fixture(({ root, file, record }) => {
      const html = mutate(render());
      assert.equal(isSafePolicyHtml(html), false, name);
      writeFileSync(file, html);
      assert.throws(
        () => publishedPolicyDocuments("kirk-evers", [record(html)], root),
        (e) => e.code === "unsafe_html",
      );
    }),
  );
test("final file and parent-directory symlinks cannot expose assets outside the public root", () =>
  fixture(({ dir, root, file, record }) => {
    const html = render(),
      outside = join(dir, "private.html");
    writeFileSync(outside, html);
    symlinkSync(outside, file);
    assert.throws(
      () => publishedPolicyDocuments("kirk-evers", [record(html)], root),
      (e) => e.code === "invalid_document_path",
    );
    rmSync(join(root, "documents"), { recursive: true, force: true });
    const privateDir = join(dir, "private");
    mkdirSync(privateDir);
    writeFileSync(join(privateDir, "kirk-evers-summary-v1.html"), html);
    symlinkSync(privateDir, join(root, "documents"));
    assert.throws(
      () => publishedPolicyDocuments("kirk-evers", [record(html)], root),
      (e) => e.code === "invalid_document_path",
    );
  }));
test("a directory cannot be admitted as a document", () =>
  fixture(({ root, file, record }) => {
    mkdirSync(file);
    assert.throws(
      () => publishedPolicyDocuments("kirk-evers", [record("directory")], root),
      (e) => e.code === "invalid_document_size",
    );
  }));
