import { assert, exactKeys, id, safeText } from "./validation.mjs";
import { parseYouTubeId } from "./video.mjs";
import { hasMaterialApproval } from "./material-approval.mjs";
export function canReadMaterial(material, account) {
  return Boolean(
    account?.verified === true &&
    material?.status === "published" &&
    material.audience === "volunteer" &&
    hasMaterialApproval(material),
  );
}
export function materialSearch(
  materials,
  query = "",
  category = "all",
  account,
) {
  const q = query.trim().toLowerCase().slice(0, 300);
  return materials.filter(
    (m) =>
      canReadMaterial(m, account) &&
      (category === "all" || m.category === category) &&
      (!q || `${m.title} ${m.description} ${m.body}`.toLowerCase().includes(q)),
  );
}
export function normalizeDraft(input) {
  exactKeys(input, [
    "id",
    "title",
    "description",
    "body",
    "category",
    "revision",
    "youtubeId",
  ]);
  id(input.id);
  safeText(input.title, 200);
  safeText(input.description || "", 1000);
  safeText(input.body || "", 100000);
  assert(
    Number.isSafeInteger(input.revision) && input.revision >= 1,
    "revision",
    "A positive revision is required.",
  );
  return {
    ...input,
    youtubeId:
      input.youtubeId === undefined
        ? undefined
        : parseYouTubeId(input.youtubeId),
    status: "draft",
    review: null,
  };
}
export function publishDraft(draft, review, actor) {
  assert(
    Array.isArray(actor?.scopes) && actor.scopes.includes("content:publish"),
    "forbidden",
    "Publication permission required.",
    403,
  );
  assert(
    review?.approvedBy !== draft?.author,
    "self_review",
    "The author cannot approve their own publication.",
  );
  assert(
    hasMaterialApproval({ ...draft, review }),
    "missing_review",
    "This revision needs an independent dated approval.",
  );
  return { ...draft, status: "published", review };
}
export function publicMaterial(m) {
  return {
    id: m.id,
    title: m.title,
    description: m.description,
    category: m.category,
    revision: m.revision,
    body: m.body,
    reviewedAt: m.review?.at,
  };
}
