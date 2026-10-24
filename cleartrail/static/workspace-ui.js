/* Shared, side-effect-free workspace presentation rules. No customer data persists. */
const ClearTrailUI = (() => {
  const normalize = (value) =>
    String(value ?? "")
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .trim();
  const matches = (values, query) =>
    normalize(query)
      .split(/\s+/)
      .filter(Boolean)
      .every((term) => normalize(values.join(" ")).includes(term));
  function documents(items, filters) {
    return items.filter(
      (item) =>
        (filters.status === "all" ||
          item.latest_version.status === filters.status) &&
        matches(
          [
            item.title,
            item.owner,
            item.latest_version.filename,
            ...(item.control_ids || []),
          ],
          filters.query,
        ),
    );
  }
  function governance(items, filters) {
    return items.filter(
      (item) =>
        (filters.kind === "all" || item.kind === filters.kind) &&
        (filters.status === "all" ||
          (filters.status === "overdue"
            ? item.overdue
            : item.status === filters.status)) &&
        matches(
          [
            item.title,
            item.owner,
            item.reference,
            item.kind.replaceAll("_", " "),
          ],
          filters.query,
        ),
    );
  }
  function errorMessage(status, fallback) {
    return (
      {
        401: "Your session expired. Sign in again to continue.",
        403: "Your role cannot perform this action. Contact your workspace administrator if you need access.",
        409: "The workspace or record changed. Reopen its latest details before trying again.",
        413: "This upload is too large. Choose a file no larger than 512 KiB.",
        429: "Too many requests. Wait a moment, then try again.",
        503: "The service could not complete this action safely. Try again shortly; contact your operator if it continues.",
      }[status] ||
      fallback ||
      "The request failed. Check your connection and try again."
    );
  }
  function mustRenderContext(previous, next) {
    return (
      !previous ||
      previous.workspace_id !== next.workspace_id ||
      previous.role !== next.role ||
      previous.subject !== next.subject
    );
  }
  return Object.freeze({
    documents,
    governance,
    errorMessage,
    mustRenderContext,
  });
})();
if (typeof module !== "undefined" && module.exports)
  module.exports = ClearTrailUI;
