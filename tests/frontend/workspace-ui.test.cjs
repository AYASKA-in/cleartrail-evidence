const test = require("node:test");
const assert = require("node:assert/strict");
const ui = require("../../cleartrail/static/workspace-ui.js");
const files = [
  {
    title: "Café access review",
    owner: "alice",
    control_ids: ["MAN-ACCESS"],
    latest_version: { filename: "review.txt", status: "approved" },
  },
  {
    title: "Incident exercise",
    owner: "bob",
    control_ids: ["MAN-INCIDENT"],
    latest_version: { filename: "exercise.pdf", status: "pending" },
  },
];
const records = [
  {
    title: "Privileged access",
    owner: "alice",
    kind: "risk",
    status: "approved",
    overdue: true,
    reference: null,
  },
  {
    title: "Policy decision",
    owner: "bob",
    kind: "applicability",
    status: "pending",
    overdue: false,
    reference: "A.5.1",
  },
];
test("document search combines terms across title, filename, owner and control", () => {
  assert.deepEqual(
    ui.documents(files, { status: "all", query: "cafe MAN-ACCESS alice" }),
    [files[0]],
  );
  assert.deepEqual(ui.documents(files, { status: "pending", query: "PDF" }), [
    files[1],
  ]);
});
test("a filter does not expose a different review state or mutate source records", () => {
  const before = JSON.stringify(files);
  assert.deepEqual(
    ui.documents(files, { status: "approved", query: "incident" }),
    [],
  );
  assert.equal(JSON.stringify(files), before);
});
test("governance supports exact type, reference and overdue filtering", () => {
  assert.deepEqual(
    ui.governance(records, { kind: "risk", status: "overdue", query: "alice" }),
    [records[0]],
  );
  assert.deepEqual(
    ui.governance(records, { kind: "all", status: "pending", query: "a.5.1" }),
    [records[1]],
  );
  assert.deepEqual(
    ui.governance(records, {
      kind: "applicability",
      status: "overdue",
      query: "",
    }),
    [],
  );
});
test("clearing filters restores all visible records without searching payload secrets", () => {
  assert.deepEqual(
    ui.governance(records, { kind: "all", status: "all", query: "  " }),
    records,
  );
  const scoped = {
    ...records[0],
    payload: { data: { plan: "private-note-content" } },
  };
  assert.deepEqual(
    ui.governance([scoped], {
      kind: "all",
      status: "all",
      query: "private-note-content",
    }),
    [],
  );
});
test("untrusted markup remains a plain query and is never evaluated", () => {
  assert.deepEqual(
    ui.documents(files, {
      status: "all",
      query: "<img src=x onerror=alert(1)>",
    }),
    [],
  );
});
test("membership and workspace changes must refresh even with unsaved input", () => {
  const a = { workspace_id: "a", role: "operator", subject: "alice" };
  assert.equal(ui.mustRenderContext(a, { ...a }), false);
  for (const patch of [
    { workspace_id: "b" },
    { role: "auditor" },
    { subject: "bob" },
  ])
    assert.equal(ui.mustRenderContext(a, { ...a, ...patch }), true);
  assert.equal(ui.mustRenderContext(null, a), true);
});
test("errors explain permission, conflict, size and retry recovery without leaking exception text", () => {
  for (const status of [401, 403, 409, 413, 429, 503])
    assert.ok(
      !ui.errorMessage(status, "secret upstream exception").includes("secret"),
    );
  assert.match(ui.errorMessage(409), /latest details/);
  assert.match(ui.errorMessage(429), /Wait/);
  assert.equal(ui.errorMessage(422, "File rejected."), "File rejected.");
});
