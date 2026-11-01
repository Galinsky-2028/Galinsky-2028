# Public document and raster admission

On 1 November 2026, a credential-free reproduction against source
`4be888089106a0e36acc238ae7d1d8713059a2a6` showed that the publication validator
accepted an HTML fixture with a copied generator marker, weakened CSP and inline
body event handler, even though the metadata digest matched. A marker and
approval do not establish safe document structure.

Admission now requires the supported generator's exact head, including its
restrictive CSP and fixed stylesheet before author-controlled body content.
Body markup is limited to the generated semantic tags and quoted attributes;
active elements, event attributes, refresh metadata, malformed tags, unsafe or
entity-obscured URL schemes, protocol-relative links and opener access are
rejected. Escaped prose/code remains text. This is a narrow generator-envelope
validator, not a general-purpose HTML sanitizer. An edited, otherwise benign
standalone HTML file must be regenerated with the supported tool before review.

The document reader resolves the canonical public root and asset path, rejects
outside-root and final symlink targets, opens without following a replacement
final symlink and checks the opened descriptor is a bounded regular file. The
read itself is bounded to the observed size plus one byte, rejects size changes
and hashes those exact bytes. This protects publication-time admission; it does
not claim to replace deployment filesystem permissions or prove that a separate
static file server cannot later be modified by an authorized filesystem writer.
The static build and deployed artifact must preserve the validated files.

The PNG normalizer also checks raw chunk-name bytes before Node's ASCII decoder
can mask high bits, and rejects an invalid reserved third-letter bit. Existing
pixel/decompression/size limits, checksum and chunk ordering checks, ancillary
metadata stripping and lossless normalized raster output remain in place.

Local validation passed 38 tests across malicious HTML/path fixtures, policy
publication, safe-document generation/preparation and raster normalization,
with zero failures or skips. Tests include valid generated links, headings,
tables, unchanged legitimate PDFs and idempotent PNG round trips, as well as
correctly checksummed malicious fixtures. Local Node was 24.22.1 rather than the
repository's pinned Node 22; no full build, browser, deployment or actual policy
publication is claimed. Inspect the exact committed head's CI before merge.

Public document hashes and independent publication approvals remain mandatory.
No actual bill, source archive, protected attachment, new public asset or
unapproved campaign content was published by this change.
