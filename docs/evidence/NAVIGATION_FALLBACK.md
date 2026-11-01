# Shared navigation without JavaScript

G28-003 closes the remaining mobile navigation fallback gap. The approved
header markup and navigation destinations are preserved; a noscript stylesheet
exposes the same links when scripting is disabled. The header expands in normal
flow so the additional links do not cover the page. The inactive menu button is
hidden. Scripting-enabled desktop and mobile styles remain unchanged.

The existing public interaction browser suite now runs shared navigation checks
in Chromium, Firefox and WebKit. Each engine visits the home, issues and legal
notices routes at 320, 390, 780, 781 and 1280 CSS pixels with scripting enabled
and disabled. Checks cover link visibility and focusability, horizontal overflow,
fallback header containment, keyboard opening, Escape closing and focus
restoration. Screenshots and per-engine JSON are written under the existing
test-results/public-interactions directory. A result is recorded only after the
checks finish successfully; no browser coverage is skipped when unavailable.

Local validation on 1 November 2026 rendered the three real routes successfully
and passed JavaScript syntax checks. Local browser execution was unavailable:
Playwright reported `Executable doesn't exist` for its Chromium headless shell.
The attempted browser installation failed with `End of central directory record
signature not found. Either not a zip file, or file is truncated.` This is not a
browser test pass. The committed head's GitHub Actions results must supply the
remaining browser evidence before acceptance or merge. Local Node was 24.22.1,
outside this repository's pinned Node 22 runtime.
