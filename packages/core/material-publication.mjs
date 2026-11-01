import { assert, id, safeText } from "./validation.mjs";
import { hasMaterialApproval } from "./material-approval.mjs";
import { parseYouTubeId } from "./video.mjs";
export function validateMaterialRelease(records) {
  assert(
    Array.isArray(records) && records.length > 0,
    "empty_release",
    "Supply reviewed material records before publishing.",
  );
  const ids = new Set();
  for (const m of records) {
    id(m.id);
    assert(
      !ids.has(m.id),
      "duplicate_material",
      "Each material ID must occur once.",
    );
    ids.add(m.id);
    safeText(m.title, 200);
    safeText(m.body, 100000);
    assert(m.body.trim(), "empty_material", "Material text is required.");
    if (m.description !== undefined) safeText(m.description, 1000);
    if (m.category !== undefined) id(m.category);
    if (m.youtubeId !== undefined && m.youtubeId !== null)
      assert(
        parseYouTubeId(m.youtubeId) === m.youtubeId,
        "invalid_video",
        "Material video must use the canonical YouTube identifier.",
      );
    assert(
      m.status === "published" && m.audience === "volunteer",
      "publication_state",
      "Only approved volunteer publication records are accepted.",
    );
    assert(
      Number.isSafeInteger(m.revision) && m.revision > 0,
      "revision",
      "A positive revision is required.",
    );
    assert(
      m.author && m.review?.approvedBy && m.review.approvedBy !== m.author,
      "review_authority",
      "An actual independent review record is required.",
    );
    assert(
      m.review.revision === m.revision &&
        Number.isFinite(Date.parse(m.review.at)),
      "review_revision",
      "Approval must identify this revision and a review date.",
    );
    assert(
      hasMaterialApproval(m),
      "review_authority",
      "A distinct author and reviewer with a dated current revision approval are required.",
    );
  }
  return records;
}
