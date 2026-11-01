// Shared admission predicate for publication and every volunteer read surface.
// This checks metadata consistency, not signatures or staff key authority;
// signed publication still verifies both current authorized signing keys.
const subject = (value) =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  value.length <= 180 &&
  !/[\u0000-\u001f\u007f]/.test(value);
export function hasMaterialApproval(material, { now = Date.now() } = {}) {
  const review = material?.review;
  return Boolean(
    material &&
    subject(material.author) &&
    subject(review?.approvedBy) &&
    material.author.trim() !== review.approvedBy.trim() &&
    Number.isSafeInteger(material.revision) &&
    material.revision > 0 &&
    review.revision === material.revision &&
    typeof review.at === "string" &&
    Number.isFinite(Date.parse(review.at)) &&
    Date.parse(review.at) <= now + 300000,
  );
}
