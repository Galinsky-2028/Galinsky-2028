import { escapeHtml } from "./validation.mjs";
import { parseMaterialMarkdown, materialLinks } from "./material-outline.mjs";

// Validate the supported generator's security envelope, not a forgeable marker.
// The exact head installs restrictive CSP before any author-controlled body.
// This is intentionally narrower than a general-purpose HTML sanitizer.
export function isSafePolicyHtml(html) {
  if (typeof html !== "string") return false;
  const template = renderSafePolicyHtml({
    title: "Security envelope",
    source: "Synthetic envelope reference.",
  });
  const titleStart = template.indexOf("<title>") + 7;
  const prefix = template.slice(0, titleStart);
  const suffix = template.slice(
    template.indexOf("</title>"),
    template.indexOf("</head><body>") + 13,
  );
  if (!html.startsWith(prefix)) return false;
  const titleEnd = html.indexOf("</title>", prefix.length);
  if (
    titleEnd < 0 ||
    html.slice(prefix.length, titleEnd).includes("<") ||
    !html.slice(titleEnd).startsWith(suffix)
  )
    return false;
  const body = html.slice(titleEnd + suffix.length);
  if (
    !body.endsWith("</body></html>") ||
    body.includes("<!--") ||
    body.includes("<!")
  )
    return false;
  const allowed = new Set([
    "a",
    "header",
    "main",
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "nav",
    "ol",
    "ul",
    "li",
    "article",
    "blockquote",
    "pre",
    "code",
    "hr",
    "div",
    "table",
    "thead",
    "tr",
    "th",
    "tbody",
    "td",
    "footer",
    "body",
    "html",
    "br",
  ]);
  const attributes = new Set([
    "href",
    "rel",
    "target",
    "class",
    "id",
    "role",
    "aria-label",
    "tabindex",
    "scope",
  ]);
  for (const token of body.matchAll(/<[^<>]*>/g)) {
    const tag = token[0].match(/^<(\/?)([a-z][a-z0-9]*)([\s\S]*?)>$/i);
    if (!tag || !allowed.has(tag[2].toLowerCase())) return false;
    const tail = tag[3];
    if (tag[1]) {
      if (tail.trim()) return false;
      continue;
    }
    let consumed = 0;
    const seen = new Map();
    for (const attr of tail.matchAll(/\s+([a-z][a-z0-9-]*)="([^"<>]*)"/gi)) {
      const name = attr[1].toLowerCase();
      if (attr.index !== consumed || !attributes.has(name) || seen.has(name))
        return false;
      seen.set(name, attr[2]);
      consumed += attr[0].length;
    }
    if (tail.slice(consumed).trim()) return false;
    if (seen.has("href")) {
      if (tag[2].toLowerCase() !== "a") return false;
      const value = seen.get("href");
      if (/&(?!(?:amp|lt|gt|quot|#39);)/.test(value)) return false;
      const href = value.replace(
        /&(amp|lt|gt|quot|#39);/g,
        (_, name) =>
          ({ amp: "&", lt: "<", gt: ">", quot: '"', "#39": "'" })[name],
      );
      if (href.startsWith("#")) {
        if (!/^#[a-z0-9_-]+$/i.test(href)) return false;
      } else if (href.startsWith("/")) {
        if (
          href.startsWith("//") ||
          href.includes("\\") ||
          href.includes("..") ||
          /[\u0000-\u0020]/.test(href)
        )
          return false;
      } else {
        try {
          const url = new URL(href);
          if (
            url.protocol !== "https:" ||
            url.username ||
            url.password ||
            url.port
          )
            return false;
        } catch {
          return false;
        }
      }
    }
    if (
      seen.has("target") &&
      (seen.get("target") !== "_blank" ||
        seen.get("rel") !== "noopener noreferrer")
    )
      return false;
  }
  // Generated values escape all angle brackets. Reject malformed or nested
  // tag tokens instead of relying on browser error recovery for their meaning.
  return !body.replace(/<\/?[a-z][a-z0-9:-]*\b[^<>]*>/gi, "").includes("<");
}

const safe = (v) => escapeHtml(String(v ?? ""));
function inline(value) {
  return materialLinks(value)
    .map((p) => {
      if (p.type !== "link") return safe(p.text);
      const url = safe(p.url),
        text = safe(p.text);
      return (
        '<a href="' +
        url +
        '"' +
        (p.external ? ' rel="noopener noreferrer" target="_blank"' : "") +
        ">" +
        text +
        "</a>"
      );
    })
    .join("");
}
export function renderSafePolicyHtml({
  title,
  source,
  edition = "Publication draft - pending review",
}) {
  if (typeof title !== "string" || !title.trim() || title.length > 160)
    throw Error("A short accessible document title is required.");
  if (typeof edition !== "string" || edition.length > 200)
    throw Error("Invalid document edition label.");
  if (
    typeof source !== "string" ||
    source.length > 200000 ||
    !source.trim() ||
    source.includes("\0") ||
    source.includes("\uFFFD")
  )
    throw Error("Use a reviewed, nonempty UTF-8 text source below 200 KB.");
  const { blocks, headings } = parseMaterialMarkdown(source);
  if (blocks.length > 2000) throw Error("Document contains too many sections.");
  const parts = blocks
    .map((b) => {
      if (b.type === "heading") {
        const level = b.level === 1 ? 2 : b.level === 2 ? 3 : 4;
        return (
          "<h" +
          level +
          ' id="' +
          safe(b.id) +
          '">' +
          inline(b.text) +
          "</h" +
          level +
          ">"
        );
      }
      if (b.type === "ul" || b.type === "ol")
        return (
          "<" +
          b.type +
          ">" +
          b.items.map((v) => "<li>" + inline(v) + "</li>").join("") +
          "</" +
          b.type +
          ">"
        );
      if (b.type === "quote")
        return "<blockquote>" + inline(b.text) + "</blockquote>";
      if (b.type === "code")
        return "<pre><code>" + safe(b.text) + "</code></pre>";
      if (b.type === "rule") return "<hr>";
      if (b.type === "table") {
        const th = b.headers
          .map((v) => '<th scope="col">' + inline(v) + "</th>")
          .join("");
        const rows = b.rows
          .map(
            (row) =>
              "<tr>" +
              row.map((v) => "<td>" + inline(v) + "</td>").join("") +
              "</tr>",
          )
          .join("");
        return (
          '<div class="table-scroll" role="region" aria-label="Document table" tabindex="0"><table><thead><tr>' +
          th +
          "</tr></thead><tbody>" +
          rows +
          "</tbody></table></div>"
        );
      }
      return "<p>" + inline(b.text) + "</p>";
    })
    .join("\n");
  const toc =
    headings.length > 1
      ? '<nav aria-label="On this page" class="contents"><h2>In this document</h2><ol>' +
        headings
          .map(
            (h) =>
              '<li><a href="#' + safe(h.id) + '">' + safe(h.text) + "</a></li>",
          )
          .join("") +
        "</ol></nav>"
      : "";
  const css =
    ":root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#fff;color:#202b38;font:18px/1.65 system-ui,Arial,sans-serif}header{background:#0a3161;color:#fff;padding:19px 30px;font-weight:700;letter-spacing:.07em}main{max-width:1020px;margin:auto;padding:45px 30px 80px}h1,h2,h3,h4{font-family:Georgia,serif;line-height:1.16}h1{font-size:clamp(34px,4vw,55px);margin:12px 0}h2{font-size:30px;margin:36px 0 15px}h3{font-size:24px;margin:30px 0 12px}h4{font-size:21px}a{color:#0a3161;text-decoration:underline;text-underline-offset:3px}a:focus-visible{outline:3px solid #b31942;outline-offset:3px}.skip{position:absolute;left:-9999px;top:8px;background:#fff;color:#000;padding:12px}.skip:focus{left:8px}.edition{color:#586779}.contents{background:#f4f7fb;border-left:4px solid #b31942;padding:18px 25px;margin:35px 0}.contents h2{font:700 13px/1.5 system-ui,sans-serif;text-transform:uppercase;letter-spacing:.1em;margin:0}.contents ol{columns:2}.contents li{break-inside:avoid;padding:5px 0}p{white-space:pre-line}blockquote{border-left:4px solid #0a3161;padding-left:20px;margin:27px 0}pre{white-space:pre;overflow:auto;background:#101d31;color:#fff;padding:20px;font-size:14px}table{width:100%;border-collapse:collapse;min-width:340px}.table-scroll{overflow-x:auto;max-width:100%}th,td{border:1px solid #d1d7de;text-align:left;padding:11px 14px}th{background:#eef2f7}footer{border-top:1px solid #ddd;color:#586779;padding:25px 30px;font-size:13px}@media(max-width:650px){main{padding:30px 20px}.contents ol{columns:1}}@media print{header,.skip,.contents,footer{display:none}main{padding:0}body{font-size:13pt}a{color:#000}pre{background:#fff;color:#000;border:1px solid #aaa}}";
  const csp =
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-src 'none'";
  return (
    '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="generator" content="g28-safe-document-v1"><meta http-equiv="Content-Security-Policy" content="' +
    safe(csp) +
    '"><meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,follow"><title>' +
    safe(title) +
    "</title><style>" +
    css +
    '</style></head><body><a href="#main" class="skip">Skip to document</a><header>GALINSKY 2028&nbsp; / &nbsp; JUSTICE FOR ALL</header><main id="main"><p class="edition">' +
    safe(edition) +
    "</p><h1>" +
    safe(title) +
    "</h1>" +
    toc +
    "<article>" +
    parts +
    "</article></main><footer>Publication copy is provided for public information. Verify its version and status on the official campaign issue page.</footer></body></html>"
  );
}
