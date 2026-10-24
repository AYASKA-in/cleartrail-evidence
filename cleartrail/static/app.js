"use strict";
const $ = (selector) => document.querySelector(selector);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (ch) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        ch
      ],
  );
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const names = {
  github: "GitHub",
  google: "Google Workspace",
  aws: "Amazon Web Services",
  manual: "Team evidence",
};
const labels = {
  pass: "Passing",
  fail: "Needs attention",
  unknown: "Unknown",
  manual: "Human review",
};
const marks = { github: "GH", google: "G", aws: "aws", manual: "CT" };
const views = {
  overview: [
    "Overview",
    "Your security, backed by evidence.",
    "One place to collect the proof, spot the gaps, and keep moving.",
  ],
  controls: [
    "Controls",
    "Small checks. A stronger foundation.",
    "Review configuration checks and the human work behind your security program.",
  ],
  evidence: [
    "Evidence library",
    "The proof behind every check.",
    "Source details, collection timestamps, and integrity hashes in one place.",
  ],
  integrations: [
    "Integrations",
    "Connect your security stack.",
    "Read-only collection from the tools your team already uses.",
  ],
  reports: [
    "Reports",
    "Make your evidence reviewable.",
    "Export a portable package with results, source records, and a file manifest.",
  ],
  monitoring: [
    "Monitoring",
    "Keep your evidence current.",
    "Schedule collection, review gaps, and track missed runs.",
  ],
  documents: [
    "Team documents",
    "Evidence your team can stand behind.",
    "Assign owners, retain each version, and record independent review.",
  ],
  governance: [
    "Governance",
    "Turn decisions into a reviewable record.",
    "Manage risks, applicability, audits, management reviews and corrective actions.",
  ],
};
let state,
  selected = "all",
  query = "",
  evidenceQuery = "",
  provider = "all",
  framework = "all",
  lastRunning = false,
  toastTimer,
  loading = false,
  contextSwitching = false,
  refreshGeneration = 0,
  refreshAbort = null;
let governanceLibrary = null,
  dialogDirty = false,
  dialogOpener = null,
  dialogLastField = null;
const idleButtonLabels = new WeakMap();
function setButtonBusy(button, busy) {
  if (busy && !idleButtonLabels.has(button)) {
    const error = button.closest("form")?.querySelector('[role="alert"]');
    if (error) error.textContent = "";
    idleButtonLabels.set(button, button.innerHTML);
    button.textContent =
      button.hasAttribute("data-governance-export") ||
      button.closest("#audit-package-form")
        ? "Preparing export…"
        : button.closest("#document-upload-form")
          ? "Checking and saving…"
          : "Saving…";
  } else if (!busy && idleButtonLabels.has(button)) {
    button.innerHTML = idleButtonLabels.get(button);
    idleButtonLabels.delete(button);
  }
  button.toggleAttribute("disabled", busy);
  button.setAttribute("aria-busy", String(busy));
}
let identityLabels = Object.create(null);
const libraryPages = {
  documents: { page: 1, page_size: 25, sort: "newest" },
  governance: { page: 1, page_size: 25, sort: "newest" },
};
const libraryTimers = {};
const libraryFilters = {
  documents: { query: "", status: "all" },
  governance: { query: "", kind: "all", status: "all" },
};
function resetLibraryContext() {
  identityLabels = Object.create(null);
  for (const type of ["documents", "governance"]) {
    clearTimeout(libraryTimers[type]);
    libraryPages[type] = { page: 1, page_size: 25, sort: "newest" };
  }
  documentLibrary = null;
  governanceLibrary = null;
  libraryFilters.documents = { query: "", status: "all" };
  libraryFilters.governance = { query: "", kind: "all", status: "all" };
  evidenceQuery = "";
}
function setMenu(open) {
  $("#workspace-nav").classList.toggle("is-open", open);
  $("#menu-toggle").setAttribute("aria-expanded", String(open));
}
function announce(message) {
  $("#announcer").textContent = message;
}
function closeDialogSafely() {
  if (dialogDirty) {
    $("#discard-panel").hidden = false;
    $("#discard-panel p").textContent = draftContexts.has(
      $("#dialog-body form"),
    )
      ? "Keep editing, retain a private recovery draft, or discard these changes."
      : "Closing this form discards the changes you have entered.";
    $("#keep-draft").hidden = !draftContexts.has($("#dialog-body form"));
    $("#keep-editing").focus();
  } else $("#detail").close();
}
$(".skip").addEventListener("click", (event) => {
  event.preventDefault();
  $("#main").focus();
  $("#main").scrollIntoView({ block: "start" });
});
$("#workspace-nav").addEventListener("click", (event) => {
  const link = event.target.closest("a");
  if (link) {
    setMenu(false);
    if (link.hash === location.hash) $("#main").focus();
  }
});
$("#menu-toggle").addEventListener("click", () =>
  setMenu($("#menu-toggle").getAttribute("aria-expanded") !== "true"),
);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("#detail").open) {
    const wasOpen = $("#menu-toggle").getAttribute("aria-expanded") === "true";
    setMenu(false);
    if (wasOpen) $("#menu-toggle").focus();
  }
});
$("#detail").addEventListener("cancel", (event) => {
  event.preventDefault();
  closeDialogSafely();
});
$("#keep-editing").addEventListener("click", () => {
  $("#discard-panel").hidden = true;
  if (dialogLastField?.isConnected) dialogLastField.focus();
  else $("#dialog-body").querySelector("textarea,input,select,button")?.focus();
});
$("#keep-draft").addEventListener("click", async () => {
  try {
    await flushDraft($("#dialog-body form"), undefined, true);
    $("#detail").close();
  } catch (error) {
    toast(error.message, true);
  }
});
$("#discard-changes").addEventListener("click", async () => {
  try {
    const form = $("#dialog-body form");
    if (form) await clearDraft(form);
    $("#detail").close();
  } catch (error) {
    toast("Draft could not be discarded. " + error.message, true);
  }
});
$("#detail").addEventListener("close", () => {
  dialogDirty = false;
  $("#discard-panel").hidden = true;
  dialogLastField = null;
  if (dialogOpener?.isConnected && !dialogOpener.disabled) dialogOpener.focus();
  else $("#main").focus();
});
for (const name of ["input", "change"])
  document.addEventListener(name, (event) => {
    const form = event.target.closest("form");
    if (form?.closest("#detail")) dialogDirty = true;
    if (form?.closest("#content")) form.dataset.unsaved = "true";
    if (form?.closest("#detail")) updateSelectionCounts(form);
  });
document.addEventListener("focusin", (event) => {
  if (
    event.target.matches("input,textarea,select") &&
    event.target.closest("#detail")
  )
    dialogLastField = event.target;
});
function updateSelectionCounts(form) {
  form.querySelectorAll("fieldset").forEach((fieldset) => {
    const legend = fieldset.querySelector("legend");
    if (!legend || !fieldset.querySelector('input[type="checkbox"]')) return;
    let counter = legend.querySelector(".selection-count");
    if (!counter) {
      counter = document.createElement("span");
      counter.className = "selection-count";
      counter.setAttribute("role", "status");
      legend.append(counter);
    }
    counter.textContent = `${fieldset.querySelectorAll('input[type="checkbox"]:checked').length} selected`;
  });
}
window.addEventListener("beforeunload", (event) => {
  const modalForm = $("#dialog-body form"),
    inlineForm = $("#content form[data-unsaved]");
  if (
    (dialogDirty && !draftDurable(modalForm)) ||
    (inlineForm && !draftDurable(inlineForm))
  ) {
    event.preventDefault();
    event.returnValue = "";
  }
});
const view = () =>
  location.hash.slice(1) in views ? location.hash.slice(1) : "overview";
const mark = (p) =>
  `<span class="provider-mark ${p}">${marks[p] || "CT"}</span>`;
const badge = (status) =>
  `<span class="tag ${esc(status)}"><i class="dot"></i>${labels[status] || "Unknown"}</span>`;
const date = (value) =>
  value
    ? new Date(value).toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "No collection yet";
function toast(text, error = false) {
  clearTimeout(toastTimer);
  $("#toast").textContent = text;
  $("#toast").className = "toast" + (error ? " error" : "");
  $("#toast").hidden = false;
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 6500);
}
async function request(path, body, workspace = state?.workspace_id) {
  const response = await fetch(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-ClearTrail-Token": state?.csrf || "",
      "X-ClearTrail-Workspace": workspace || "",
    },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(ClearTrailUI.errorMessage(response.status, data.error));
  if (workspace !== state?.workspace_id && path !== "/api/workspace")
    throw new Error(
      "Workspace changed. Reopen the record in your current workspace.",
    );
  if (path !== "/api/drafts") dialogDirty = false;
  return data;
}
function integrationState(p) {
  if (state.demo)
    return {
      label: "Demo data",
      description: "Synthetic configuration fixtures",
      active: true,
    };
  const cfg = state.config.providers[p];
  if (!cfg || cfg.enabled === false)
    return {
      label: "Not configured",
      description: "Set up read-only collection",
      active: false,
    };
  const checks = state.run?.checks.filter((c) => c.provider === p) || [];
  if (!checks.length)
    return {
      label: "Configured",
      description: "Run collection to check access",
      active: false,
    };
  if (checks.some((c) => c.has_unknown || c.status === "unknown"))
    return {
      label: "Check access",
      description: "Collection has coverage gaps",
      active: false,
    };
  return {
    label: "Collected",
    description: "Evidence captured in latest snapshot",
    active: true,
  };
}
function integrationMini(p) {
  const info = integrationState(p);
  return `<div class="integration-mini">${mark(p)}<div><strong>${names[p]}</strong><small>${esc(info.description)}</small></div><span class="connection-status ${info.active ? "" : "idle"}"><i class="dot"></i>${info.label}</span></div>`;
}
function firstRunView() {
  const auditor = state.role === "auditor",
    hosted = state.mode === "hosted";
  return `<section class="panel welcome-panel"><span class="eyebrow">${auditor ? "REVIEW WORKSPACE" : "GET STARTED"}</span><h2>${auditor ? "Your evidence will appear here." : "Build your first evidence trail."}</h2><p>${auditor ? "Approved team records are available in their libraries. Automated results appear after your team collects a snapshot." : "Start with the evidence you already have, then connect a source and collect a snapshot. Missing access remains unknown."}</p><div class="onboarding-grid"><a class="onboarding-step" href="#integrations"><span class="step-number">1</span><h3>${auditor ? "View collection scope" : "Configure a source"}</h3><p>${state.role === "operator" ? "Your administrator manages provider credentials and scope." : "Review the read-only GitHub, Google Workspace and AWS setup."}</p>${icon("arrow")}</a>${hosted ? `<a class="onboarding-step" href="#documents"><span class="step-number">2</span><h3>${auditor ? "Review approved files" : "Add team evidence"}</h3><p>Policies, access reviews and other documents, with independent approval.</p>${icon("arrow")}</a><a class="onboarding-step" href="#governance"><span class="step-number">3</span><h3>${auditor ? "Review governance" : "Record your decisions"}</h3><p>Risks, applicability and follow-up actions in one reviewable register.</p>${icon("arrow")}</a>` : `<div class="onboarding-step"><span class="step-number">2</span><h3>Collect a snapshot</h3><p>Use Collect evidence after configuration. Export the result from Reports.</p></div>`}</div></section>`;
}
function stats() {
  const s = state.run.summary;
  return `<div class="metrics"><div class="metric metric-highlight"><div class="metric-label">Snapshot passes ${icon("shield")}</div><div class="metric-value">${s.passed}<small>/ ${s.total}</small></div><div class="metric-foot good">${s.pass_percent}% of the starter catalog</div></div><div class="metric"><div class="metric-label">Needs attention ${icon("alert")}</div><div class="metric-value">${s.failed.toString().padStart(2, "0")}</div><div class="metric-foot warn">Configuration gaps to review</div></div><div class="metric"><div class="metric-label">Evidence collected ${icon("folder")}</div><div class="metric-value">${s.evidence_count}</div><div class="metric-foot">Traceable configuration records</div></div><div class="metric"><div class="metric-label">Human review ${icon("file")}</div><div class="metric-value">${s.manual.toString().padStart(2, "0")}</div><div class="metric-foot">Policies, access & incident response</div></div></div>`;
}
function overviewPanels() {
  const s = state.run.summary;
  return `<div class="panel-grid"><section class="panel"><div class="panel-header"><div><h2>Your control snapshot</h2><p>A clear view of where things stand.</p></div><span class="tiny-pill">${s.total} starter checks</span></div><div class="posture"><div class="ring" role="img" aria-label="${s.passed} of ${s.total} controls passing"><svg class="ring-chart" viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="44"/><circle class="ring-value" cx="50" cy="50" r="44" pathLength="100" stroke-dasharray="${Math.max(0, Math.min(100, Number(s.pass_percent) || 0))} 100"/></svg><div><strong>${s.pass_percent}%</strong><span>checks passing</span></div></div><div class="legend">${["pass", "fail", "unknown", "manual"].map((k) => `<div><i class="dot ${k}"></i>${labels[k]}<b>${{ pass: s.passed, fail: s.failed, unknown: s.unknown, manual: s.manual }[k]}</b></div>`).join("")}</div></div><p class="panel-note">${s.coverage_percent}% evaluated automatically. Passing checks reflect collected settings, not certification.</p></section><section class="panel"><div class="panel-header"><div><h2>Your connected stack</h2><p>The sources behind your evidence.</p></div><span class="tiny-pill">Read-only</span></div>${["github", "google", "aws"].map(integrationMini).join("")}<a class="text-button" href="#integrations">Manage integrations ${icon("arrow")}</a></section></div>`;
}
function controlsTable() {
  const checks = state.run.checks;
  const counts = {
    all: checks.length,
    fail: checks.filter((c) => c.status === "fail").length,
    unknown: checks.filter((c) => c.status === "unknown").length,
    manual: checks.filter((c) => c.status === "manual").length,
  };
  return `<div class="section-title"><div><h2>${view() === "overview" ? "Keep your controls on track" : "Control catalog"}</h2><p>Every result has a source. Every gap has a next step.</p></div><span>${checks.length} controls</span></div><div class="table-panel"><div class="table-toolbar"><div class="tabs" role="group" aria-label="Filter by status">${["all", "fail", "unknown", "manual"].map((k) => `<button class="tab ${selected === k ? "selected" : ""}" data-filter="${k}" aria-pressed="${selected === k}">${k === "all" ? "All controls" : labels[k]}<b>${counts[k]}</b></button>`).join("")}</div><div class="filters"><label class="search">${icon("search")}<input id="search" aria-label="Search controls" placeholder="Find a control…" value="${esc(query)}"></label><select id="framework-filter" aria-label="Filter by framework"><option value="all">All frameworks</option><option value="SOC 2" ${framework === "SOC 2" ? "selected" : ""}>SOC 2</option><option value="ISO 27001:2022" ${framework === "ISO 27001:2022" ? "selected" : ""}>ISO 27001:2022</option></select><select id="provider-filter" aria-label="Filter by source"><option value="all">All sources</option>${Object.keys(
    names,
  )
    .map(
      (p) =>
        `<option value="${p}" ${provider === p ? "selected" : ""}>${names[p]}</option>`,
    )
    .join(
      "",
    )}</select></div></div><div class="table-scroll"><table><thead><tr><th scope="col">CONTROL</th><th scope="col">SOURCE</th><th scope="col">STATUS</th><th scope="col">REFERENCE</th><th scope="col">EVIDENCE</th></tr></thead><tbody id="control-rows"></tbody></table></div><div class="table-bottom"><span id="result-count"></span><span>Original checks · Indicative mappings</span></div></div>`;
}
function filterRows() {
  if (!$("#control-rows")) return;
  const checks = state.run.checks.filter(
    (c) =>
      (selected === "all" || selected === c.status) &&
      (provider === "all" || provider === c.provider) &&
      (framework === "all" || c.frameworks[framework]) &&
      `${c.title} ${c.id} ${c.category}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  $("#control-rows").innerHTML = checks.length
    ? checks
        .map(
          (c) =>
            `<tr><td><button class="control-title" data-control="${c.id}">${esc(c.title)}</button><div class="control-sub">${esc(c.id)} · ${esc(c.category)}</div></td><td><div class="source-cell">${mark(c.provider)}${names[c.provider]}</div></td><td>${badge(c.status)}${c.has_unknown ? '<div class="control-sub text-warning">Incomplete coverage</div>' : ""}</td><td>${Object.entries(
              c.frameworks,
            )
              .filter(([k]) => framework === "all" || framework === k)
              .map(
                ([k, v]) =>
                  `<span class="framework" title="${esc(k)}">${esc(v)}</span>`,
              )
              .join(
                "",
              )}</td><td><button class="evidence-button" data-control="${c.id}">${icon(c.provider === "manual" ? "file" : "folder")}${c.resource_count ? `${c.resource_count} record${c.resource_count === 1 ? "" : "s"}` : c.provider === "manual" ? (state.role === "auditor" ? "View note" : "Review note") : "No records"}${icon("arrow")}</button></td></tr>`,
        )
        .join("")
    : '<tr><td colspan="5" class="empty-cell">No controls match these filters. Try another search or source.</td></tr>';
  $("#result-count").textContent =
    `Showing ${checks.length} of ${state.run.checks.length} controls`;
}
function evidenceView() {
  const records = state.run.evidence;
  return `<div class="section-title"><div><h2>Collected evidence</h2><p>Captured ${date(state.run.collected_at)} · ${records.length} records</p></div><a class="text-button" href="/api/csv">Download control index ${icon("download")}</a></div><div class="table-panel"><div class="table-toolbar"><label class="search">${icon("search")}<input id="evidence-search" aria-label="Search evidence" placeholder="Find evidence…" value="${esc(evidenceQuery)}"></label><span class="small muted">SHA-256 integrity hashes</span></div><div class="table-scroll"><table><thead><tr><th scope="col">RESOURCE / CONTROL</th><th scope="col">SOURCE</th><th scope="col">RESULT</th><th scope="col">COLLECTED</th><th scope="col">RECORD</th></tr></thead><tbody id="evidence-rows"></tbody></table></div><div class="table-bottom"><span>${records.length} point-in-time records</span><span>${state.demo ? "Synthetic demonstration" : state.mode === "hosted" ? "Organization evidence storage" : "Local evidence storage"}</span></div></div>`;
}
function evidenceRows(q = evidenceQuery) {
  const records = state.run.evidence.filter((e) =>
    `${e.resource} ${e.control_id} ${e.id}`
      .toLowerCase()
      .includes(q.toLowerCase()),
  );
  $("#evidence-rows").innerHTML = records.length
    ? records
        .map(
          (e) =>
            `<tr><td><button class="control-title" data-evidence="${e.id}">${esc(e.resource)}</button><div class="control-sub">${esc(e.control_id)}</div></td><td><div class="source-cell">${mark(e.provider)}${names[e.provider]}</div></td><td>${badge(e.status)}</td><td class="nowrap">${date(e.collected_at)}</td><td><button class="evidence-button mono" data-evidence="${e.id}">${esc(e.id.slice(0, 11))}… ${icon("arrow")}</button></td></tr>`,
        )
        .join("")
    : '<tr><td colspan="5" class="empty-cell">No evidence matches this search.</td></tr>';
}
function integrationsView() {
  const descriptions = {
    github:
      "Organization MFA and default branch review, CI, and administrator protection settings.",
    google:
      "Active-user 2-step verification enrollment, enforcement, and recovery administrator coverage.",
    aws: "Root MFA, CloudTrail logging, S3 bucket access blocks, and regional EBS encryption defaults.",
  };
  return `<div class="integration-grid">${Object.keys(descriptions)
    .map((p) => {
      const info = integrationState(p);
      return `<section class="integration-card">${mark(p)}<h2>${names[p]}</h2><p>${descriptions[p]}</p><span class="tag ${info.active ? "pass" : "unknown"}"><i class="dot"></i>${info.label}</span><button class="button secondary" data-setup="${p}">${state.mode === "hosted" ? (state.role === "admin" ? "Configure integration" : "View scope") : "Setup instructions"} ${icon("arrow")}</button></section>`;
    })
    .join(
      "",
    )}</div><div class="bottom-callout">${icon("lock")}<div><h3>Credentials stay out of your reports.</h3><p>Use environment variables or your AWS credential chain. Setup happens on your machine.</p></div></div><section class="panel section-space"><h2>Collection boundaries</h2><p class="small">Only configured sources are collected. Missing access and unsupported settings are recorded as unknown. The current release checks classic GitHub branch protection and one configured AWS region. Google access tokens must be refreshed by your own identity workflow.</p></section>`;
}
function reportsView() {
  const snapshot = state.run;
  return `<div class="section-title"><div><h2>Choose what to share</h2><p>Each export serves a different review. Retain its digest through a trusted channel.</p></div></div><div class="export-grid"><section class="panel export-card">${icon("shield")}<h2>Configuration snapshot</h2><p>Collected settings, source records, HTML report and control index.</p><span class="small">${snapshot ? date(snapshot.collected_at) : "Collect a snapshot to enable this export."}</span>${snapshot ? `<a class="button primary" href="/api/export?run_id=${encodeURIComponent(snapshot.id)}">${icon("download")}Download snapshot</a>` : '<a class="button secondary" href="#integrations">Review integrations</a>'}</section>${state.mode === "hosted" ? `<section class="panel export-card">${icon("folder")}<h2>Document audit package</h2><p>Select exact approved files, their reviews and scan records, with a declared audit period.</p><span class="small">An automated snapshot is optional.</span><button class="button primary" data-audit-package>Create audit package</button></section><section class="panel export-card">${icon("file")}<h2>Governance register</h2><p>Approved decisions, review histories and the governance versions they depend on.</p><span class="small">JSON register. Supporting file bytes are separate.</span><button class="button secondary" data-governance-export>Export register</button></section>` : ""}</div><div id="governance-export-result" class="export-result" role="status"></div><details class="panel section-space"><summary>What these exports prove</summary><p>Evidence supports human review. It does not establish certification, full-period operating effectiveness or auditor acceptance. Exports are unsigned; retain a trusted digest separately.</p><p class="small">Snapshot: <code>python -m cleartrail verify snapshot.zip</code><br>Files: <code>python -m cleartrail verify-audit audit-package.zip --manifest-sha256 TRUSTED_HASH</code><br>Governance: <code>python -m cleartrail verify-governance register.json --expected-sha256 TRUSTED_HASH</code></p></details><div class="section-title section-space"><div><h2>Collection history</h2><p>Latest 20 snapshots in this workspace.</p></div></div><div class="table-panel"><div class="table-scroll" tabindex="0" role="region" aria-label="Collection history"><table><thead><tr><th scope="col">Collected</th><th scope="col">Snapshot</th><th scope="col">Passing</th><th scope="col">Evidence</th><th scope="col">Mode</th></tr></thead><tbody>${state.history.map((r) => `<tr><td>${date(r.collected_at)}</td><td class="mono"><a href="/api/export?run_id=${encodeURIComponent(r.id)}">${esc(r.id)}</a></td><td>${r.summary.passed} / ${r.summary.total}</td><td>${r.summary.evidence_count} records</td><td>${r.demo ? "Demo" : "Live"}</td></tr>`).join("") || '<tr><td colspan="5" class="empty-cell">No snapshots yet. Approved documents and governance can be exported independently.</td></tr>'}</tbody></table></div></div>`;
}

function render() {
  if (!state) return;
  const v = view();
  $("#monitoring-nav").hidden = state.mode !== "hosted";
  $("#documents-nav").hidden = state.mode !== "hosted";
  $("#governance-nav").hidden = state.mode !== "hosted";
  $("#page-name").textContent = views[v][0];
  $("#mobile-page-name").textContent = views[v][0];
  $("#heading").textContent = views[v][1];
  $("#subtitle").textContent = views[v][2];
  $("#workspace-name").textContent = state.config.organization;
  $(".avatar").textContent = state.config.organization
    .slice(0, 1)
    .toUpperCase();
  document.querySelectorAll("nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.view === v);
    if (a.dataset.view === v) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  const run = state.run;
  $("#banner").hidden = !state.demo;
  if (state.demo)
    $("#banner").innerHTML =
      `<span><strong>DEMO WORKSPACE</strong> · All evidence is synthetic. Explore the workflow without connecting an account.</span><button data-setup="live">Set up live collection ${icon("arrow")}</button>`;
  $("#snapshot-time").innerHTML =
    icon("clock") +
    `<span>${run ? "Last collection: " + date(run.collected_at) : "No collection yet"}${run && Date.now() - new Date(run.collected_at).getTime() > 86400000 ? " · Over 24 hours old" : ""}</span>`;
  $("#export").hidden = !run;
  if (run)
    $("#export").href = "/api/export?run_id=" + encodeURIComponent(run.id);
  $("#collect").disabled = state.job.running || state.role === "auditor";
  $("#collect span").textContent = state.job.running
    ? state.job.status === "queued"
      ? "Queued…"
      : "Collecting…"
    : "Collect evidence";
  let content;
  if (v === "governance") content = governanceView();
  else if (v === "documents") content = documentsView();
  else if (v === "monitoring") content = monitoringView();
  else if (v === "integrations") content = integrationsView();
  else if (v === "reports") content = reportsView();
  else if (!run) content = firstRunView();
  else if (v === "evidence") content = evidenceView();
  else
    content =
      (v === "overview" ? stats() + overviewPanels() : "") +
      controlsTable() +
      (v === "overview"
        ? `<div class="bottom-callout">${icon("file")}<div><h3>Keep the human work reviewable.</h3><p>Policies, access reviews and incident exercises need supporting evidence.</p></div><button class="text-button" data-control="MAN-POLICY">${state.role === "auditor" ? "View policy evidence" : "Review team evidence"} ${icon("arrow")}</button></div>`
        : "");
  $("#content").innerHTML = content;
  document.querySelectorAll(".table-scroll").forEach((region) => {
    region.tabIndex = 0;
    region.setAttribute("role", "region");
    if (!region.hasAttribute("aria-label"))
      region.setAttribute("aria-label", views[v][0] + " table");
  });
  if (v === "documents" && state.mode === "hosted") loadDocuments();
  if (v === "governance" && state.mode === "hosted") loadGovernance();
  if (run) {
    filterRows();
    if (v === "evidence") evidenceRows();
  }
  decorateWorkspace();
  renderHealthStatus();
  if (v === "monitoring" && state.role === "admin")
    attachDraft($("#schedule-form"), "schedule:policy");
  if (state.job.error && state.mode !== "hosted")
    toast(
      "Collection did not complete: " +
        state.job.error +
        ". Review access and retry.",
      true,
    );
}
function showDialog(title, content, eyebrow = "EVIDENCE DETAIL") {
  if (!$("#detail").open) dialogOpener = document.activeElement;
  dialogDirty = false;
  $("#discard-panel").hidden = true;
  dialogLastField = null;
  $("#dialog-eyebrow").textContent = eyebrow;
  $("#dialog-body").innerHTML =
    `<h2 id="dialog-title">${esc(title)}</h2>${content}`;
  if (!$("#detail").open) $("#detail").showModal();
  $("#dialog-body").querySelectorAll("form").forEach(updateSelectionCounts);
  const noteForm = $("#attest-form");
  if (noteForm) attachDraft(noteForm, "attestation:" + noteForm.dataset.id);
}
function recordHTML(e) {
  return `<section class="evidence-record"><h3>${esc(e.resource)}</h3>${badge(e.status)}<p>${esc(e.summary)}</p><p>Source: ${esc(e.source)}<br>Collected: ${date(e.collected_at)}</p><pre>${esc(JSON.stringify(e.data, null, 2))}</pre><div class="hash mono">${esc(e.id)}<br>SHA-256 ${esc(e.sha256)}</div></section>`;
}
function controlDetail(id) {
  const c = state.run?.checks.find((c) => c.id === id);
  if (!c) return;
  let content = `<div class="detail-meta">${badge(c.status)}<span class="framework">${esc(c.id)}</span>${Object.values(
    c.frameworks,
  )
    .map((x) => `<span class="framework">${esc(x)}</span>`)
    .join("")}</div><p>${esc(c.remediation)}</p>`;
  if (c.has_unknown)
    content +=
      '<p class="text-warning">This result has incomplete collection coverage. Review unknown evidence records.</p>';
  if (c.provider === "manual" && state.role !== "auditor") {
    const a = state.attestations[c.id];
    content += `<p>Team notes are self-attestations. Supporting documents and independent review remain necessary.</p><form id="attest-form" data-id="${c.id}"><div class="field"><label for="owner">Evidence owner</label><input id="owner" name="owner" value="${esc(a?.owner || "")}" maxlength="120" required autocomplete="name"></div><div class="field"><label for="note">Review notes & document reference</label><textarea id="note" name="note" maxlength="4000" required>${esc(a?.note || "")}</textarea><small>Include the review date, outcome, and a reference to the supporting document. Keep secrets out of notes.</small></div><p id="form-error" class="form-error" role="alert"></p><button type="submit" class="button primary">Save team note</button><p class="small">Collect a new snapshot after saving to include the note in reports. The control remains marked for human review.</p></form>`;
  }
  const records = state.run.evidence.filter((e) =>
    c.evidence_ids.includes(e.id),
  );
  content += records.length
    ? records.map(recordHTML).join("")
    : '<p class="small muted section-space">No source records collected for this control yet.</p>';
  showDialog(c.title, content, "CONTROL / " + c.id);
}
function setup(p) {
  if (state?.mode === "hosted") {
    hostedSetup(p);
    return;
  }
  const snippets = {
    github: '$env:GITHUB_TOKEN = "YOUR_READ_ONLY_TOKEN"',
    google: '$env:GOOGLE_ACCESS_TOKEN = "YOUR_SHORT_LIVED_ACCESS_TOKEN"',
    aws: '# Use your existing AWS profile or workload identity\npython -m pip install ".[aws]"',
  };
  const cfg = {
    github: { github: { enabled: true, org: "your-github-org" } },
    google: { google: { enabled: true, customer: "my_customer" } },
    aws: { aws: { enabled: true, profile: "default", region: "us-east-1" } },
  };
  const permissions = {
    github:
      "Use a token approved for the organization. Repository Administration: read and Contents: read support the branch checks. The organization MFA field needs owner-visible access; missing fields remain unknown. Repository metadata is collected only from repositories visible to the token. Classic branch protection is supported; ruleset-only protection requires review.",
    google:
      "Use an administrator-authorized OAuth access token with admin.directory.user.readonly. The admin_view directory response must include 2-step verification fields. No service account private keys are accepted by the dashboard.",
    aws: "Use the AWS standard credential chain or an existing profile. Required read actions are documented in docs/SETUP.md. Collection includes one EBS region; a failed bucket-level block check does not establish actual public exposure.",
  };
  const live = p === "live";
  showDialog(
    live ? "Start a live workspace" : `Set up ${names[p]}`,
    `<p>${live ? "Demo data lives in a separate database. Start a live workspace using your own configuration file and credentials." : permissions[p]}</p><p><strong>1.</strong> Copy <code>config.example.json</code> to <code>config.json</code> and enable the relevant source.</p><pre>${esc(JSON.stringify({ organization: "Your organization", providers: live ? { github: { enabled: true, org: "your-github-org" } } : cfg[p] }, null, 2))}</pre><p><strong>2.</strong> Set credentials in your shell. Do not add secrets to configuration files.</p><pre>${esc(live ? snippets.github : snippets[p])}</pre><p><strong>3.</strong> Start a live workspace on a new port.</p><pre>python -m cleartrail serve --config config.json --port 8091</pre><p class="small muted">Open http://127.0.0.1:8091 and collect evidence. Full permissions and limits are in docs/SETUP.md. Provider subscriptions, infrastructure, and audit fees are separate from this free software.</p>`,
    "READ-ONLY INTEGRATION",
  );
}
async function refresh(full = true) {
  if (loading || !authenticated || contextSwitching) return;
  loading = true;
  const generation = refreshGeneration;
  refreshAbort = new AbortController();
  try {
    const response = await fetch(
      "/api/state" +
        (state?.run?.id ? "?since=" + encodeURIComponent(state.run.id) : ""),
      { cache: "no-store", signal: refreshAbort.signal },
    );
    if (generation !== refreshGeneration || !authenticated) return;
    if (response.status === 401) {
      authenticated = false;
      state = null;
      showSignIn();
      return;
    }
    if (!response.ok) throw new Error("The workspace could not be loaded.");
    const next = await response.json();
    if (generation !== refreshGeneration || !authenticated) return;
    if (next.unchanged && state?.run) next.run = state.run;
    const contextChanged = ClearTrailUI.mustRenderContext(state, next);
    const changed =
      !state ||
      next.run?.id !== state.run?.id ||
      next.job.running !== state.job.running ||
      next.job.error !== state.job.error ||
      next.workspace_id !== state.workspace_id ||
      next.role !== state.role ||
      monitoringKey(next) !== monitoringKey(state);
    if (contextChanged && state) {
      resetLibraryContext();
      if ($("#detail").open) $("#detail").close();
    }
    state = next;
    $("#connection-status").hidden = true;
    if (full || changed || contextChanged) {
      if (
        !full &&
        !contextChanged &&
        ($("#content form[data-unsaved]") || $("#detail").open)
      ) {
        renderHealthStatus();
        $("#collect").disabled = state.job.running || state.role === "auditor";
        $("#collect span").textContent = state.job.running
          ? "Collecting…"
          : "Collect evidence";
      } else render();
    }
    if (lastRunning && !state.job.running && !state.job.error)
      toast("Collection saved. Your latest evidence package is ready.");
    lastRunning = state.job.running;
  } catch (e) {
    if (generation !== refreshGeneration || !authenticated) return;
    $("#connection-status").hidden = false;
    $("#connection-status").innerHTML =
      '<div><strong>Workspace connection interrupted</strong><p>Showing the last loaded data. Your form stays in place while we retry.</p></div><button class="button secondary" id="retry-workspace">Retry now</button>';
  } finally {
    if (generation === refreshGeneration) loading = false;
  }
}
$("#collect").addEventListener("click", async () => {
  try {
    $("#collect").disabled = true;
    await request("/api/scan", {});
    lastRunning = true;
    await refresh();
  } catch (e) {
    toast(e.message, true);
    $("#collect").disabled = false;
  }
});
$("#close-dialog").addEventListener("click", closeDialogSafely);
document.addEventListener("click", (e) => {
  if (e.target.closest("#retry-workspace")) refresh(false);
  const control = e.target.closest("[data-control]");
  if (control) controlDetail(control.dataset.control);
  const record = e.target.closest("[data-evidence]");
  if (record) {
    const item = state.run.evidence.find(
      (x) => x.id === record.dataset.evidence,
    );
    if (item) showDialog(item.resource, recordHTML(item));
  }
  const setupButton = e.target.closest("[data-setup]");
  if (setupButton) setup(setupButton.dataset.setup);
  const filter = e.target.closest("[data-filter]");
  if (filter) {
    selected = filter.dataset.filter;
    document.querySelectorAll("[data-filter]").forEach((b) => {
      b.classList.toggle("selected", b === filter);
      b.setAttribute("aria-pressed", b === filter ? "true" : "false");
    });
    filterRows();
  }
});
document.addEventListener("input", (e) => {
  if (e.target.id === "search") {
    query = e.target.value;
    filterRows();
  }
  if (e.target.id === "evidence-search") {
    evidenceQuery = e.target.value;
    evidenceRows();
  }
});
document.addEventListener("change", (e) => {
  if (e.target.id === "provider-filter") provider = e.target.value;
  if (e.target.id === "framework-filter") framework = e.target.value;
  if (["provider-filter", "framework-filter"].includes(e.target.id))
    filterRows();
});
document.addEventListener("submit", async (e) => {
  if (e.target.id !== "attest-form") return;
  e.preventDefault();
  const form = e.target;
  const button = form.querySelector("button[type=submit]");
  setButtonBusy(button, true);
  try {
    const result = await request("/api/attest", {
      control_id: form.dataset.id,
      owner: form.owner.value,
      note: form.note.value,
    });
    await completeDraft(form);
    await refresh(false);
    $("#detail").close();
    toast(result.message);
  } catch (err) {
    $("#form-error").textContent = err.message;
  } finally {
    setButtonBusy(button, false);
  }
});
let renderedHash = location.hash;
window.addEventListener("hashchange", async () => {
  try {
    await preserveEditing();
  } catch (error) {
    history.replaceState(null, "", location.pathname + renderedHash);
    toast(error.message, true);
    return;
  }
  if ($("#detail").open) $("#detail").close();
  renderedHash = location.hash;
  query = "";
  selected = "all";
  provider = "all";
  framework = "all";
  evidenceQuery = "";
  setMenu(false);
  render();
  if (authenticated && state) {
    $("#main").focus();
    announce(views[view()][0]);
  }
});
let authenticated = false,
  authMode = "local";

function showSignIn() {
  resetLibraryContext();
  $("#connection-status").hidden = true;
  $("#export").hidden = true;
  $("#collect").disabled = true;
  $("#banner").hidden = true;
  $("#health-status").hidden = true;
  $("#monitoring-nav").hidden = true;
  $("#documents-nav").hidden = true;
  $("#governance-nav").hidden = true;
  $(".top-meta").textContent = "Sign-in required";
  if ($("#detail").open) $("#detail").close();
  $("#workspace-name").textContent = "Sign-in required";
  $("#content").innerHTML =
    `<section class="panel empty"><h2>Open your evidence workspace.</h2>${authMode === "oidc" ? '<p>Sign in with your organization identity. Workspace access is granted by your administrator.</p><a class="button primary" href="/auth/login">Sign in with your organization</a>' : '<p>Open the complete private launch URL printed by the local server, or enter its access token below.</p><form id="local-login"><div class="field"><label for="launch-token">Local access token</label><input id="launch-token" name="token" type="password" required autocomplete="off" maxlength="43"></div><button class="button primary" type="submit">Open workspace</button><p class="form-error" id="login-error" role="alert"></p></form>'}</section>`;
}

async function exchangeToken(token) {
  const response = await fetch("/api/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!response.ok)
    throw new Error(
      "Access could not be verified. Use the current launch URL from the server.",
    );
  authenticated = true;
}

async function initialize() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  let token = fragment.get("access");
  if (token) history.replaceState(null, "", "/#overview");
  try {
    const mode = await fetch("/api/auth", { cache: "no-store" });
    if (mode.ok) authMode = (await mode.json()).mode;
    if (token && authMode !== "oidc") await exchangeToken(token);
    authenticated = true;
    await refresh();
  } catch (error) {
    authenticated = false;
    showSignIn();
    toast(error.message, true);
  } finally {
    renderedHash = location.hash;
    token = null;
  }
}

function decorateWorkspace() {
  if (state.mode !== "hosted") return;
  const pill = $(".local-pill");
  if (pill) pill.textContent = "Hosted · " + state.role;
  $(".local-card strong").textContent = "Your organization’s evidence.";
  $(".local-card p").textContent =
    "Customer-scoped storage. Read-only collection.";
  $("footer span").textContent =
    "Evidence is retained in your organization workspace.";
  $(".top-meta").innerHTML =
    `<label class="sr-only" for="workspace-switch">Workspace</label><select id="workspace-switch">${state.workspaces.map((w) => `<option value="${esc(w.id)}" ${w.id === state.workspace_id ? "selected" : ""}>${esc(w.name)} · ${esc(w.role)}</option>`).join("")}</select>${state.role !== "auditor" ? '<button class="text-button" id="my-drafts">My drafts</button>' : ""}${state.role === "admin" ? '<button class="text-button" id="manage-members">Members</button>' : ""}<button class="text-button" id="sign-out">Sign out</button>`;
  if (view() === "integrations") {
    const callout = $(".bottom-callout p");
    if (callout)
      callout.textContent =
        "An administrator can configure provider scope and update encrypted credentials. Saved secrets are never returned to the browser.";
  }
}

function hostedSetup(provider) {
  if (!(provider in names) || provider === "manual") return;
  if (state.role !== "admin") {
    showDialog(
      names[provider],
      `<p>Your workspace administrator manages this integration.</p><pre>${esc(JSON.stringify(state.config.providers[provider] || {}, null, 2))}</pre>`,
      "INTEGRATION SCOPE",
    );
    return;
  }
  const cfg = state.config.providers[provider] || {};
  const stored = state.credentials.some((c) => c.provider === provider);
  const input = (name, label, value = "", type = "text", required = true) =>
    `<div class="field"><label for="integration-${name}">${label}</label><input id="integration-${name}" name="${name}" type="${type}" value="${esc(value)}" ${required ? "required" : ""} ${name === "external_id" ? "readonly" : ""} maxlength="${type === "password" ? 16384 : 256}" autocomplete="off"></div>`;
  let fields;
  if (provider === "github")
    fields =
      input("org", "GitHub organization", cfg.org) +
      `<div class="field"><label for="expected-repositories">Expected repository names (one per line)</label><textarea id="expected-repositories" name="repositories" maxlength="100000">${esc((cfg.expected_repositories || []).join("\n"))}</textarea><small>Declare the expected population to detect repositories hidden from the token.</small></div>` +
      input(
        "token",
        stored
          ? "New read-only token (leave blank to keep saved token)"
          : "Read-only organization token",
        "",
        "password",
        !stored,
      );
  if (provider === "google")
    fields =
      input("customer", "Explicit Workspace customer ID", cfg.customer) +
      input(
        "access_token",
        stored
          ? "New access token (leave blank to keep saved token)"
          : "Administrator-authorized access token",
        "",
        "password",
        !stored,
      ) +
      '<p class="small">Requires admin.directory.user.readonly and admin-visible security fields. Short-lived tokens must be renewed before collection.</p>';
  if (provider === "aws")
    fields =
      input(
        "expected_account_id",
        "Expected 12-digit account ID",
        cfg.expected_account_id,
      ) +
      input("region", "EBS region", cfg.region || "us-east-1") +
      input(
        "role_arn",
        stored
          ? "New read-only role ARN (leave blank to keep saved role)"
          : "Customer read-only role ARN",
        "",
        "text",
        !stored,
      ) +
      input(
        "external_id",
        "Workspace external ID (copy into the role trust policy)",
        state.aws_external_id,
        "text",
        true,
      ) +
      '<p class="small">Configure the customer role trust policy with this service’s worker identity and a unique external ID. Static AWS access keys are not accepted.</p>';
  showDialog(
    `Configure ${names[provider]}`,
    `<form id="integration-form" data-provider="${provider}">${fields}<label><input type="checkbox" name="enabled" ${cfg.enabled !== false ? "checked" : ""}> Enable collection</label><p id="integration-error" role="alert" class="form-error"></p><button type="submit" class="button primary">Save integration</button>${stored ? '<button type="button" class="button secondary" id="revoke-credential" data-provider="' + provider + '">Revoke saved credential</button>' : ""}<p class="small">Missing access remains unknown. Collect evidence after saving to validate the connection.</p></form>`,
    "WORKSPACE ADMINISTRATION",
  );
}

async function manageMembers() {
  try {
    const response = await fetch("/api/members");
    if (!response.ok) throw new Error("Workspace members could not be loaded.");
    const result = await response.json();
    Object.assign(identityLabels, result.identity_labels || {});
    showDialog(
      "Workspace access",
      `<p>Membership uses the exact subject from the configured identity provider. Each identity must sign in through that provider.</p><ul>${result.members.map((m) => `<li>${identityHTML(m.subject)} · ${esc(m.role)}</li>`).join("")}</ul><form id="member-form"><div class="field"><label for="member-subject">Identity provider subject</label><input id="member-subject" name="subject" required maxlength="255"></div><div class="field"><label for="member-role">Role</label><select id="member-role" name="role"><option value="auditor">Auditor · read and export</option><option value="operator">Operator · manage evidence and governance</option><option value="admin">Administrator · manage integrations and access</option><option value="remove">Remove access</option></select></div><p class="form-error" id="member-error" role="alert"></p><button class="button primary" type="submit">Save membership</button></form><form id="member-label-form" class="section-space"><h3>Friendly identity labels</h3><p>Labels help people recognize owners. Exact subjects still determine permissions and approvals. Duplicate labels do not merge identities.</p><div class="field"><label for="label-subject">Workspace member</label><select id="label-subject" name="subject">${result.members.map((m) => `<option value="${esc(m.subject)}">${esc(identityText(m.subject))}</option>`).join("")}</select></div><div class="field"><label for="identity-label">Display label</label><input id="identity-label" name="label" maxlength="80"><small>Leave blank to remove the label.</small></div><p class="form-error" role="alert"></p><button class="button primary" type="submit">Save label</button></form>`,
      "WORKSPACE ADMINISTRATION",
    );
  } catch (error) {
    toast(error.message, true);
  }
}

document.addEventListener("change", async (event) => {
  if (event.target.id !== "workspace-switch") return;
  const selector = event.target,
    previous = state.workspace_id;
  contextSwitching = true;
  refreshGeneration++;
  refreshAbort?.abort();
  loading = false;
  selector.disabled = true;
  try {
    await preserveEditing();
    await request("/api/workspace", { tenant_id: selector.value });
    if ($("#detail").open) $("#detail").close();
    resetLibraryContext();
    state = null;
    $("#content").innerHTML =
      '<p class="loading-line">Loading selected workspace…</p>';
  } catch (error) {
    selector.value = previous;
    toast(error.message, true);
  } finally {
    contextSwitching = false;
    selector.disabled = false;
    await refresh();
  }
});

document.addEventListener("click", async (event) => {
  if (event.target.closest("#manage-members")) manageMembers();
  if (event.target.closest("#my-drafts"))
    manageDrafts().catch((error) => toast(error.message, true));
  if (event.target.closest("#sign-out")) {
    try {
      await preserveEditing();
      await request("/api/logout", {});
      authenticated = false;
      state = null;
      showSignIn();
    } catch (error) {
      toast(error.message, true);
    }
  }
  const revoke = event.target.closest("#revoke-credential");
  if (revoke) {
    try {
      await request("/api/credentials", {
        provider: revoke.dataset.provider,
        credentials: null,
      });
      await refresh();
      $("#detail").close();
      toast("Saved credential revoked.");
    } catch (error) {
      $("#integration-error").textContent = error.message;
    }
  }
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (
    ![
      "local-login",
      "integration-form",
      "member-form",
      "member-label-form",
    ].includes(form.id)
  )
    return;
  event.preventDefault();
  const button = form.querySelector('[type="submit"]');
  setButtonBusy(button, true);
  try {
    if (form.id === "local-login") {
      await exchangeToken(form.elements.token.value.trim());
      form.reset();
      await refresh();
    } else if (form.id === "integration-form") {
      const value = new FormData(form),
        provider = form.dataset.provider;
      const settings = { enabled: value.has("enabled") };
      let credentials = null;
      if (provider === "github") {
        settings.org = value.get("org").trim();
        const repositories = value
          .get("repositories")
          .split(/\r?\n/)
          .map((x) => x.trim())
          .filter(Boolean);
        if (repositories.length) settings.expected_repositories = repositories;
        if (value.get("token")) credentials = { token: value.get("token") };
      } else if (provider === "google") {
        settings.customer = value.get("customer").trim();
        if (value.get("access_token"))
          credentials = { access_token: value.get("access_token") };
      } else {
        settings.expected_account_id = value.get("expected_account_id").trim();
        settings.region = value.get("region").trim();
        if (value.get("role_arn"))
          credentials = {
            role_arn: value.get("role_arn").trim(),
            external_id: value.get("external_id"),
          };
      }
      await request("/api/integration", { provider, settings, credentials });
      form.reset();
      $("#detail").close();
      await refresh();
      toast("Integration saved. Collect evidence to check access.");
    } else if (form.id === "member-label-form") {
      await request("/api/member-label", {
        subject: form.elements.subject.value,
        label: form.elements.label.value.trim(),
      });
      await manageMembers();
      toast("Display label saved. Identity and permissions are unchanged.");
    } else {
      await request("/api/members", {
        subject: form.elements.subject.value,
        role:
          form.elements.role.value === "remove"
            ? null
            : form.elements.role.value,
      });
      $("#detail").close();
      await refresh();
      toast("Workspace membership updated.");
    }
  } catch (error) {
    const target = form.querySelector('[role="alert"]');
    if (target) target.textContent = error.message;
  } finally {
    setButtonBusy(button, false);
  }
});

function monitoringKey(value) {
  return JSON.stringify([
    value?.collection_health?.status,
    value?.collection_health?.schedule_status,
    value?.collection_health?.worker_status,
    value?.schedule?.revision,
    (value?.notifications || []).map((n) => [n.id, n.read_at]),
  ]);
}

const epochDate = (value) =>
  value == null ? "Not scheduled" : date(new Date(value * 1000).toISOString());
const healthLabels = {
  current: "Recent evidence",
  stale: "Stale evidence",
  missing: "No evidence yet",
  scope_changed: "Scope changed",
  incomplete: "Incomplete collection",
  collection_failed: "Collection failed",
  clock_error: "Check service clock",
  no_sources: "No providers configured",
  updating: "Snapshot updating",
  catalog_changed: "Catalog changed",
};

function renderHealthStatus() {
  const element = $("#health-status"),
    health = state?.collection_health;
  element.hidden = !health;
  if (!health) return;
  const delayed = ["queue_delayed", "lease_expired"].includes(
    health.worker_status,
  );
  const overdue = health.schedule_status === "overdue";
  const warning =
    health.status !== "current" ||
    overdue ||
    delayed ||
    health.schedule_status === "blocked";
  element.className = "health-status" + (warning ? " warning" : "");
  const extra = delayed
    ? " Worker processing is delayed; contact the service operator."
    : overdue
      ? " A scheduled collection is overdue. Check the scheduler and workers."
      : health.schedule_status === "blocked"
        ? " Scheduled collection is blocked by a workspace quota."
        : "";
  const message =
    health.status === "no_sources" && state.role !== "admin"
      ? "Ask a workspace administrator to configure a source before relying on automated evidence."
      : health.message;
  element.innerHTML = `<div><strong>${esc(healthLabels[health.status] || "Evidence status")}</strong><p>${esc(message + extra)}</p></div><a class="text-button" href="#monitoring">Review monitoring ${icon("arrow")}</a>`;
}

function monitoringView() {
  if (state.mode !== "hosted")
    return '<section class="panel"><h2>Hosted monitoring</h2><p>Recurring collection is managed in a hosted organization workspace. Local collection remains on demand.</p></section>';
  const schedule = state.schedule,
    health = state.collection_health;
  const choices = {
    1: "Every hour",
    6: "Every 6 hours",
    12: "Every 12 hours",
    24: "Daily",
    168: "Weekly",
  };
  const policy =
    state.role === "admin"
      ? `<form id="schedule-form"><label class="schedule-enable"><input type="checkbox" name="enabled" ${schedule.enabled ? "checked" : ""}> Enable recurring collection</label><div class="field"><label for="schedule-interval">Collection frequency</label><select id="schedule-interval" name="interval_hours">${Object.entries(
          choices,
        )
          .map(
            ([value, label]) =>
              `<option value="${value}" ${Number(value) === schedule.interval_hours ? "selected" : ""}>${label}</option>`,
          )
          .join(
            "",
          )}</select></div><div class="field"><label for="schedule-freshness">Evidence becomes stale after (hours)</label><input id="schedule-freshness" name="freshness_hours" type="number" min="${schedule.interval_hours}" max="720" value="${schedule.freshness_hours}" required><small>Choose at least the collection interval. Freshness does not mean a control passed.</small></div><p id="schedule-error" class="form-error" role="alert"></p><button class="button primary" type="submit">Save monitoring policy</button></form>`
      : `<p>${schedule.enabled ? "Recurring collection enabled" : "Recurring collection disabled"} · ${esc(choices[schedule.interval_hours])}</p><p>Freshness policy: ${schedule.freshness_hours} hours. A workspace administrator can change this policy.</p>`;
  const notices = state.notifications || [];
  const noticeNames = {
    collection_failed: "Collection did not complete",
    missed_collection: "Scheduled collection was delayed or missed",
    schedule_blocked: "A quota prevented scheduled collection",
  };
  return `<div class="panel-grid"><section class="panel"><h2>Collection policy</h2>${policy}<p class="small section-space">Next due: ${epochDate(schedule.next_due_at)}<br>Last scheduled dispatch: ${epochDate(schedule.last_dispatched_at)}</p><p class="small muted">Enabling or changing frequency makes a collection due immediately. Existing queued jobs finish normally. Missed periods are recorded and coalesced into one collection.</p></section><section class="panel"><h2>Provider evidence</h2><p class="small">${esc(health.message)}</p>${
    Object.entries(health.providers)
      .map(
        ([provider, info]) =>
          `<div class="integration-mini">${mark(provider)}<div><strong>${names[provider]}</strong><small>Oldest observation: ${Math.floor(info.age_seconds / 3600)} hours ago</small></div><span class="tag ${info.status === "current" ? "pass" : "unknown"}">${esc(info.status === "current" ? "Recent" : info.status === "stale" ? "Stale" : "Incomplete")}</span></div>`,
      )
      .join("") ||
    '<p class="small muted">No provider observations in the current scope.</p>'
  }<p class="small section-space">Worker status: ${esc(health.worker_status.replaceAll("_", " "))}<br>Schedule status: ${esc(health.schedule_status)}</p><p class="small muted">Check outcomes below remain the original snapshot results. Current scope, freshness and collection errors are evaluated separately.</p></section></div><section class="panel section-space"><h2>Collection notices</h2><p class="small">Latest event for each notice type; the audit chain preserves collection events. Acknowledging a notice does not change evidence or fix an outage.</p>${notices.map((n) => `<article class="monitor-notice"><div><h3>${esc(noticeNames[n.kind] || "Monitoring notice")}</h3><p class="small">${epochDate(n.created_at)} · ${n.event_count} event(s) of this type${n.details.missed_count != null ? ` · ${n.details.missed_count} earlier occurrence(s) missed` : ""}${n.details.code ? ` · ${esc(n.details.code)}` : ""}</p><span class="small muted">${n.read_at ? "Acknowledged " + epochDate(n.read_at) : "Unacknowledged"}</span></div>${!n.read_at && state.role !== "auditor" ? `<button class="button secondary" data-notice-id="${esc(n.id)}">Acknowledge</button>` : ""}</article>`).join("") || '<p class="small muted">No collection notices.</p>'}</section>`;
}

document.addEventListener("change", (event) => {
  if (event.target.id === "schedule-interval")
    $("#schedule-freshness").min = event.target.value;
});
document.addEventListener("submit", async (event) => {
  if (event.target.id !== "schedule-form") return;
  event.preventDefault();
  const form = event.target,
    button = form.querySelector('[type="submit"]');
  setButtonBusy(button, true);
  try {
    const values = new FormData(form);
    await request("/api/schedule", {
      enabled: values.has("enabled"),
      interval_hours: Number(values.get("interval_hours")),
      freshness_hours: Number(values.get("freshness_hours")),
    });
    await completeDraft(form);
    delete form.dataset.unsaved;
    await refresh();
    toast("Monitoring policy saved.");
  } catch (error) {
    $("#schedule-error").textContent = error.message;
  } finally {
    setButtonBusy(button, false);
  }
});
document.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-notice-id]");
  if (!target) return;
  target.disabled = true;
  try {
    await request("/api/notifications/acknowledge", {
      id: target.dataset.noticeId,
    });
    await refresh();
  } catch (error) {
    toast(error.message, true);
    target.disabled = false;
  }
});

let documentLibrary = null;
function localDateInput(value) {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60000)
    .toISOString()
    .slice(0, 19);
}

async function auditPackageDialog() {
  const workspace = state.workspace_id;
  const data = await documentGet("/api/audit-package-options", workspace);
  const end = new Date(Date.now() + 1000);
  const start = new Date(end.getTime() - 30 * 86400000);
  showDialog(
    "Create an audit review package",
    `<form id="audit-package-form"><p>Select approved versions and an optional automated snapshot. The package records the declared period and missing selected evidence; it does not establish operating effectiveness.</p><div class="field"><label for="audit-start">Period start (your local time)</label><input type="datetime-local" step="1" id="audit-start" name="period_start" value="${localDateInput(start)}" required></div><div class="field"><label for="audit-end">Period end, exclusive (your local time)</label><input type="datetime-local" step="1" id="audit-end" name="period_end" value="${localDateInput(end)}" required></div><div class="field"><label for="audit-snapshot">Automated snapshot</label><select id="audit-snapshot" name="run_id"><option value="">Documents only</option>${state.history
      .filter((run) => !run.demo)
      .map(
        (run) =>
          `<option value="${esc(run.id)}">${esc(date(run.collected_at))} · ${esc(run.id)}</option>`,
      )
      .join(
        "",
      )}</select></div><fieldset class="document-controls"><legend>Approved, unexpired versions (select up to 100)</legend>${data.versions.map((version) => `<label><input type="checkbox" name="version_ids" value="${esc(version.id)}"><span>${esc(version.title)} · v${version.number} · ${esc(version.filename)}</span></label>`).join("") || "<p>No approved versions are available.</p>"}</fieldset><p class="form-error" role="alert"></p><button class="button primary" type="submit">Generate ZIP package</button><div id="audit-package-result" aria-live="polite"></div></form>`,
    "AUDIT EVIDENCE SELECTION",
  );
  $("#audit-package-form").packageWorkspace = workspace;
}

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-audit-package]"))
    auditPackageDialog().catch((error) => toast(error.message, true));
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (form.id !== "audit-package-form") return;
  event.preventDefault();
  const workspace = form.packageWorkspace;
  $("#audit-package-result").textContent = "";
  const button = form.querySelector('[type="submit"]');
  setButtonBusy(button, true);
  try {
    const versions = [
      ...form.querySelectorAll('[name="version_ids"]:checked'),
    ].map((input) => input.value);
    if (
      (!versions.length && !form.elements.run_id.value) ||
      versions.length > 100
    )
      throw new Error("Select a snapshot or 1–100 approved versions.");
    if (workspace !== state?.workspace_id)
      throw new Error("Workspace changed. Reopen the package form.");
    const response = await fetch("/api/audit-packages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ClearTrail-Token": state.csrf,
        "X-ClearTrail-Workspace": workspace,
      },
      body: JSON.stringify({
        run_id: form.elements.run_id.value || null,
        version_ids: versions,
        period_start: new Date(form.elements.period_start.value).toISOString(),
        period_end: new Date(form.elements.period_end.value).toISOString(),
      }),
    });
    if (!response.ok)
      throw new Error(
        ClearTrailUI.errorMessage(
          response.status,
          (await response.json()).error || "Package generation failed.",
        ),
      );
    const blob = await response.blob();
    if (workspace !== state?.workspace_id)
      throw new Error("Workspace changed. Reopen the package form.");
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "cleartrail-audit-package.zip";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    dialogDirty = false;
    $("#audit-package-result").innerHTML =
      `<p>Package downloaded. Retain this manifest SHA-256 separately through a trusted channel:</p><p class="mono document-hash">${esc(response.headers.get("X-ClearTrail-Manifest-SHA256"))}</p><p class="small">Verify offline: <code>python -m cleartrail verify-audit cleartrail-audit-package.zip --manifest-sha256 &lt;trusted hash&gt;</code></p>`;
  } catch (error) {
    form.querySelector('[role="alert"]').textContent = error.message;
  } finally {
    setButtonBusy(button, false);
  }
});
let documentLoadSequence = 0;
let governanceLoadSequence = 0;
const governanceKinds = {
  risk: "Risk",
  applicability: "Applicability decision",
  internal_audit: "Internal audit",
  management_review: "Management review",
  corrective_action: "Corrective action",
};
const governanceFields = {
  risk: {
    scope: "Scope and assets",
    scenario: "Risk scenario",
    likelihood: "Inherent likelihood (1–5)",
    impact: "Inherent impact (1–5)",
    treatment: ["Treatment", "mitigate", "accept", "avoid", "transfer"],
    plan: "Treatment plan and acceptance rationale",
    residual_likelihood: "Residual likelihood (1–5)",
    residual_impact: "Residual impact (1–5)",
    review_date: "Next review due (UTC date)",
  },
  applicability: {
    reference: "Annex A reference",
    applicability: ["Applicability", "applicable", "not_applicable"],
    basis: "Inclusion or exclusion rationale",
    implementation: [
      "Implementation",
      "planned",
      "in_progress",
      "implemented",
      "not_applicable",
    ],
    description: "Customer control description or exclusion details",
    review_date: "Next review due (UTC date)",
  },
  internal_audit: {
    scope: "Audit scope",
    criteria: "Audit criteria and policy references",
    auditor: "Independent assessor’s exact identity subject",
    period_start: "Period start",
    period_end: "Period end",
    findings: "Findings and supporting sample references",
    conclusion: "Conclusion",
    review_date: "Next review due (UTC date)",
  },
  management_review: {
    review_date: "Review meeting date",
    participants: "Participants",
    inputs: "Inputs considered (including context changes)",
    decisions: "Decisions and resources",
    actions: "Actions, owners and due dates",
    next_review_date: "Next review due (UTC date)",
  },
  corrective_action: {
    finding: "Finding and source",
    cause: "Root cause",
    action: "Corrective action and responsible parties",
    due_date: "Action due date",
    state: ["Action status", "open", "in_progress", "completed"],
    verification: "Effectiveness verification or verification plan",
    review_date: "Next review due (UTC date)",
  },
};

function libraryToolbar(type) {
  const filters = libraryFilters[type],
    governance = type === "governance";
  const statuses =
    state.role === "auditor"
      ? governance
        ? ["all", "approved", "overdue"]
        : ["all", "approved"]
      : governance
        ? ["all", "pending", "approved", "rejected", "withdrawn", "overdue"]
        : ["all", "pending", "approved", "rejected", "withdrawn", "expired"];
  return `<section class="library-toolbar ${type}" aria-label="${governance ? "Governance" : "Document"} filters"><div class="field library-search"><label for="${type}-search">Search ${governance ? "records" : "documents"}</label><input type="search" maxlength="200" id="${type}-search" data-library="${type}" data-filter-key="query" value="${esc(filters.query)}" placeholder="${governance ? "Title, owner or reference" : "Title, file, owner or control"}" autocomplete="off"></div>${
    governance
      ? `<div class="field"><label for="governance-kind">Record type</label><select id="governance-kind" data-library="governance" data-filter-key="kind"><option value="all">All types</option>${Object.entries(
          governanceKinds,
        )
          .map(
            ([key, label]) =>
              `<option value="${key}"${filters.kind === key ? " selected" : ""}>${esc(label)}</option>`,
          )
          .join("")}</select></div>`
      : ""
  }<div class="field"><label for="${type}-status">Review status</label><select id="${type}-status" data-library="${type}" data-filter-key="status">${statuses.map((value) => `<option value="${value}"${filters.status === value ? " selected" : ""}>${value === "all" ? "All statuses" : value === "overdue" ? "Review overdue" : value[0].toUpperCase() + value.slice(1)}</option>`).join("")}</select></div><div class="field"><label for="${type}-sort">Sort by</label><select id="${type}-sort" data-library-order="${type}" data-page-key="sort">${Object.entries(
    {
      newest: "Newest first",
      oldest: "Oldest first",
      title: "Title A–Z",
      owner: "Owner A–Z",
      review_date: governance ? "Review date" : "Expiry date",
    },
  )
    .map(
      ([value, label]) =>
        `<option value="${value}"${libraryPages[type].sort === value ? " selected" : ""}>${label}</option>`,
    )
    .join(
      "",
    )}</select></div><div class="field"><label for="${type}-size">Per page</label><select id="${type}-size" data-library-order="${type}" data-page-key="page_size">${[10, 25, 50].map((value) => `<option value="${value}"${Number(libraryPages[type].page_size) === value ? " selected" : ""}>${value}</option>`).join("")}</select></div><button class="button secondary" data-library-clear="${type}">Clear filters</button></section>`;
}
function libraryFailure(type, error) {
  const root = $(
    type === "governance" ? "#governance-register" : "#document-library",
  );
  root.setAttribute("aria-busy", "false");
  root.innerHTML = `<section class="panel load-error" role="alert"><h3>We couldn’t load this library.</h3><p>${esc(error.message)}</p><button class="button secondary" ${type === "governance" ? "data-governance-refresh" : "data-document-refresh"}>Try again</button></section>`;
}
function libraryPath(type) {
  const params = new URLSearchParams({
    ...libraryPages[type],
    ...libraryFilters[type],
  });
  return (
    "/api/" + (type === "documents" ? "documents" : "governance") + "?" + params
  );
}
function libraryPagination(type, data) {
  const p = data.pagination;
  libraryPages[type].page = p.page;
  return `<nav class="pagination" aria-label="${type === "documents" ? "Document" : "Governance"} pages"><span role="status">Page ${p.page} of ${p.pages}</span><button class="button secondary" data-page-type="${type}" data-page="${p.page - 1}" ${p.page <= 1 ? "disabled" : ""}>Previous</button><button class="button secondary" data-page-type="${type}" data-page="${p.page + 1}" ${p.page >= p.pages ? "disabled" : ""}>Next</button></nav>`;
}
function filterLibrary(type) {
  const source = type === "governance" ? governanceLibrary : documentLibrary;
  if (!source || source.workspace !== state?.workspace_id) return;
  const items = type === "governance" ? source.records : source.documents;
  const target = $(
    type === "governance" ? "#governance-rows" : "#document-rows",
  );
  if (!target) return;
  target.innerHTML =
    items
      .map((item) =>
        type === "governance" ? governanceRow(item) : documentRow(item),
      )
      .join("") ||
    `<tr><td colspan="5" class="empty-cell"><strong>${source.pagination.available ? "No matches for these filters." : "No records available yet."}</strong><p>${source.pagination.available ? "Try a different title, owner or review status." : state.role === "auditor" ? "Approved records will appear after your team’s independent review." : "Use the create or upload action above to add your first record."}</p></td></tr>`;
  const p = source.pagination,
    start = p.total ? (p.page - 1) * p.page_size + 1 : 0;
  $("#" + type + "-count").textContent =
    `Showing ${start}–${p.total ? start + items.length - 1 : 0} of ${p.total} matches · ${p.available} available`;
}
function reloadLibrary(type, reset = false, delay = 0) {
  clearTimeout(libraryTimers[type]);
  if (reset) libraryPages[type].page = 1;
  // Invalidate an older search response before the debounce delay ends.
  if (type === "documents") documentLoadSequence++;
  else governanceLoadSequence++;
  libraryTimers[type] = setTimeout(
    () => (type === "documents" ? loadDocuments() : loadGovernance()),
    delay,
  );
}
function identityText(subject) {
  return identityLabels[subject]
    ? `${identityLabels[subject]} · ${subject}`
    : subject;
}
function identityHTML(subject) {
  return identityLabels[subject]
    ? `<span class="identity-label">${esc(identityLabels[subject])}</span><span class="identity-subject mono">${esc(subject)}</span>`
    : esc(subject);
}
function governanceRow(r) {
  return `<tr><td><button class="control-title" data-governance-open="${esc(r.record_id)}">${esc(r.title)}</button><span class="control-sub">Version ${r.number}</span></td><td data-label="Type / reference">${esc(governanceKinds[r.kind])}${r.reference ? `<br><span class="mono">${esc(r.reference)}</span>` : ""}</td><td data-label="Owner" class="document-subject">${identityHTML(r.owner)}</td><td data-label="Review">${documentStatus(r.status)}</td><td data-label="Risk / next review">${r.risk_scores ? `<span class="risk-band ${esc(r.risk_scores.residual.band)}">${r.risk_scores.residual.score} · ${esc(r.risk_scores.residual.band)}</span><br>` : ""}<span class="${r.overdue ? "text-warning" : ""}">${r.overdue ? "Review overdue" : "Review due"}</span><br>${esc(r.payload.data.next_review_date || r.payload.data.review_date)}</td></tr>`;
}
function documentRow(item) {
  return `<tr><td><button class="control-title" data-document-open="${esc(item.id)}">${esc(item.title)}</button><div class="control-sub">${item.control_ids.map(esc).join(" · ")}</div></td><td data-label="Owner" class="document-subject">${identityHTML(item.owner)}</td><td data-label="Latest version">v${item.latest_version.number}<div class="control-sub">${esc(item.latest_version.filename)}</div></td><td data-label="Review">${documentStatus(item.latest_version.status)}</td><td data-label="Expires">${documentDate(item.latest_version.expires_at)}</td></tr>`;
}
for (const eventName of ["input", "change"])
  document.addEventListener(eventName, (event) => {
    const { library, filterKey } = event.target.dataset;
    if (
      library &&
      Object.hasOwn(libraryFilters, library) &&
      Object.hasOwn(libraryFilters[library], filterKey)
    ) {
      libraryFilters[library][filterKey] = event.target.value;
      reloadLibrary(
        library,
        true,
        eventName === "input" && event.target.type === "search" ? 300 : 0,
      );
    }
  });
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-library-clear]");
  if (!button) return;
  const type = button.dataset.libraryClear;
  if (!Object.hasOwn(libraryFilters, type)) return;
  for (const key of Object.keys(libraryFilters[type]))
    libraryFilters[type][key] = key === "query" ? "" : "all";
  document
    .querySelectorAll(`[data-library="${type}"]`)
    .forEach(
      (input) => (input.value = libraryFilters[type][input.dataset.filterKey]),
    );
  reloadLibrary(type, true);
  $("#" + type + "-search")?.focus();
});
document.addEventListener("change", (event) => {
  const type = event.target.dataset.libraryOrder,
    key = event.target.dataset.pageKey;
  if (
    !Object.hasOwn(libraryPages, type) ||
    !["sort", "page_size"].includes(key)
  )
    return;
  libraryPages[type][key] = event.target.value;
  reloadLibrary(type, true);
});
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-page-type]");
  if (!button) return;
  const type = button.dataset.pageType;
  libraryPages[type].page = Number(button.dataset.page);
  const loader = type === "documents" ? loadDocuments : loadGovernance;
  button.disabled = true;
  loader().then(() => {
    const region = $(
      type === "documents"
        ? "#document-library .table-scroll"
        : "#governance-register .table-scroll",
    );
    region?.focus();
  });
});
function governanceView() {
  if (state.mode !== "hosted")
    return '<section class="panel"><h2>Governance</h2><p>Governance records require a hosted organization workspace.</p></section>';
  return `<section class="panel governance"><div class="section-title"><div><h2>Governance register</h2><p>Keep risks, decisions and follow-up work ready for independent review.</p></div><div class="document-actions"><button class="button secondary" data-governance-refresh>Refresh</button><button class="button secondary" data-governance-export>Export register</button>${state.role !== "auditor" ? '<button class="button primary" data-governance-new>Create record</button>' : '<span class="role-note">Read-only auditor access</span>'}</div></div><details class="scope-details"><summary>Scope, scoring and export details</summary><p class="small">The 93 Annex A reference IDs help organize your own rationale. Entry counts and approvals are not a compliance score. Risk scores use the fixed starter convention: likelihood × impact, each 1–5. Review dates use UTC. Register exports contain approved records; supporting file bytes require a separate document audit package.</p></details><div id="governance-export-result" role="status"></div></section>${libraryToolbar("governance")}<div id="governance-register" class="governance" aria-busy="true"><p class="loading-line">Loading governance records…</p></div>`;
}
async function loadGovernance() {
  const workspace = state.workspace_id,
    sequence = ++governanceLoadSequence;
  const root = $("#governance-register");
  if (!root) return;
  root.setAttribute("aria-busy", "true");
  try {
    const data = await documentGet(libraryPath("governance"), workspace);
    if (!$("#governance-register") || sequence !== governanceLoadSequence)
      return;
    governanceLibrary = { ...data, workspace };
    const decisions = data.summary.applicability;
    root.innerHTML = `<div class="register-summary"><span><strong>${data.summary.pending}</strong> awaiting review</span><span><strong>${data.summary.overdue}</strong> ${data.summary.overdue === 1 ? "review" : "reviews"} overdue</span><span><strong>${decisions} / ${data.reference_count}</strong> applicability entries${state.role === "auditor" ? " approved" : " recorded"}</span></div><div class="table-panel"><div class="table-scroll" tabindex="0" role="region" aria-label="Governance records"><table class="library-table" role="table"><thead><tr><th scope="col">Record</th><th scope="col">Type / reference</th><th scope="col">Owner</th><th scope="col">Review</th><th scope="col">Risk / next review</th></tr></thead><tbody id="governance-rows"></tbody></table></div><div class="table-bottom"><span id="governance-count" role="status" aria-live="polite"></span><span>${data.pagination.available} / ${data.limits.records} records retained</span></div>${libraryPagination("governance", data)}</div>`;
    filterLibrary("governance");
    root.setAttribute("aria-busy", "false");
  } catch (error) {
    if (
      $("#governance-register") &&
      sequence === governanceLoadSequence &&
      workspace === state?.workspace_id
    )
      libraryFailure("governance", error);
  }
}

function governanceField(key, spec, value, options) {
  const label = Array.isArray(spec) ? spec[0] : spec;
  let input;
  if (key === "reference" || Array.isArray(spec)) {
    const choices =
      key === "reference" ? options.annex_references : spec.slice(1);
    input = `<select name="${key}" id="gov-${key}" required>${choices.map((v) => `<option value="${esc(v)}"${v === value ? " selected" : ""}>${esc(v.replaceAll("_", " "))}</option>`).join("")}</select>`;
  } else if (key.includes("likelihood") || key.includes("impact")) {
    input = `<input name="${key}" id="gov-${key}" type="number" min="1" max="5" step="1" value="${esc(value ?? 1)}" required>`;
  } else if (key.includes("date") || key.startsWith("period_")) {
    input = `<input name="${key}" id="gov-${key}" type="date" value="${esc(value || "")}" required>`;
  } else if (key === "auditor") {
    input = `<input name="${key}" id="gov-${key}" maxlength="255" value="${esc(value || "")}" required><small>Use an existing workspace member’s exact identity subject, different from the responsible owner.</small>`;
  } else {
    input = `<textarea name="${key}" id="gov-${key}" maxlength="3000" required>${esc(value || "")}</textarea>`;
  }
  return `<div class="field${key.includes("date") || key.startsWith("period_") || key.includes("likelihood") || key.includes("impact") ? " compact-field" : ""}"><label for="gov-${key}">${esc(label)}</label>${input}</div>`;
}

async function governanceForm(item = null, preferredKind = null) {
  const workspace = state.workspace_id;
  const options = await documentGet("/api/governance/options", workspace);
  const kind = item?.kind || preferredKind || "risk";
  showDialog(
    item ? "Create next governance version" : "Create governance record",
    `<p class="form-intro">Saving creates a pending version. A separate administrator or operator reviews it before it appears in approved exports. Each record type has its own private draft; choose the same type to restore it.</p><form id="governance-form" class="governance"><div class="field"><label for="gov-kind">Record type</label><select id="gov-kind" name="kind"${item ? " disabled" : ""}>${Object.entries(
      governanceKinds,
    )
      .map(
        ([v, label]) =>
          `<option value="${v}"${v === kind ? " selected" : ""}>${esc(label)}</option>`,
      )
      .join(
        "",
      )}</select></div><div class="field"><label for="gov-title">Record title</label><input id="gov-title" name="title" maxlength="160" value="${esc(item?.title || "")}" required></div><div class="field"><label for="gov-owner">Responsible owner</label><select id="gov-owner" name="owner">${options.owners.map((v) => `<option value="${esc(v)}"${v === (item?.owner || state.subject) ? " selected" : ""}>${esc(identityText(v))}</option>`).join("")}</select></div><h3 class="form-section-title">Record details</h3><div id="governance-fields" class="form-grid"></div><p class="small">All fields are required. Use a reasoned “none identified” where appropriate. Implemented applicability decisions and completed actions need at least one approved supporting file before approval. Keep credentials out of records.</p><fieldset class="document-controls"><legend>Exact supporting evidence versions (up to 10)</legend>${options.evidence.map((v) => `<label><input type="checkbox" name="evidence" value="${esc(v.id)}"${item?.payload.evidence_version_ids.includes(v.id) ? " checked" : ""}><span>${esc(v.title)} · v${v.number} · ${esc(v.filename)}</span></label>`).join("") || '<p class="small">No approved files available. Upload and independently review evidence first.</p>'}${(
      item?.payload.evidence_version_ids || []
    )
      .filter((id) => !options.evidence.some((v) => v.id === id))
      .map(
        (id) =>
          `<label><input type="checkbox" name="evidence" value="${esc(id)}" checked><span>Previously linked version ${esc(id)} (currently unavailable; remove or restore its approval)</span></label>`,
      )
      .join(
        "",
      )}</fieldset><fieldset class="document-controls"><legend>Related approved governance versions (up to 10)</legend><div id="governance-related"></div></fieldset><p class="form-error" role="alert"></p><button class="button primary" type="submit">Save pending version</button></form>`,
    "GOVERNANCE / VERSIONED RECORD",
  );
  const form = $("#governance-form");
  const fields = () => {
    const selectedKind = $("#gov-kind").value;
    $("#governance-fields").innerHTML = Object.entries(
      governanceFields[selectedKind],
    )
      .map(([key, spec]) =>
        governanceField(key, spec, item?.payload.data[key], options),
      )
      .join("");
    if (item?.kind === "applicability") $("#gov-reference").disabled = true;
    delete form.syncDraftFields;
    if (selectedKind === "applicability") {
      const syncImplementation = () => {
        const control = $("#gov-implementation"),
          previous = control.value;
        const choices =
          $("#gov-applicability").value === "not_applicable"
            ? ["not_applicable"]
            : ["planned", "in_progress", "implemented"];
        control.innerHTML = choices
          .map(
            (v) =>
              `<option value="${v}"${v === previous ? " selected" : ""}>${esc(v.replaceAll("_", " "))}</option>`,
          )
          .join("");
      };
      form.syncDraftFields = syncImplementation;
      $("#gov-applicability").addEventListener("change", syncImplementation);
      syncImplementation();
    }
    const related = options.related.filter(
      (v) =>
        (!item || v.id !== item.id) &&
        (selectedKind !== "applicability" || v.kind === "risk"),
    );
    $("#governance-related").innerHTML =
      related
        .map(
          (v) =>
            `<label><input type="checkbox" name="related" value="${esc(v.id)}"${item?.payload.related_version_ids.includes(v.id) ? " checked" : ""}><span>${esc(v.title)} · ${esc(governanceKinds[v.kind])} · v${v.number}</span></label>`,
        )
        .join("") +
      (item?.payload.related_version_ids || [])
        .filter((id) => !related.some((v) => v.id === id))
        .map(
          (id) =>
            `<label><input type="checkbox" name="related" value="${esc(id)}" checked><span>Previously linked version ${esc(id)} (approval rechecked on review)</span></label>`,
        )
        .join("");
  };
  const installDraft = () =>
    attachDraft(
      form,
      "governance:" + (item?.record_id || "new") + "-" + $("#gov-kind").value,
      $("#gov-kind").value,
    );
  $("#gov-kind").addEventListener("change", async () => {
    const context = draftContexts.get(form),
      selectedKind = $("#gov-kind").value;
    try {
      if (context) {
        await context.ready;
        if (
          !context.pendingRestore ||
          JSON.stringify(context.fields) !== context.persisted
        )
          await flushDraft(form, context);
      }
    } catch (error) {
      $("#gov-kind").value = context.recordKind;
      toast(error.message, true);
      return;
    }
    $("#gov-kind").value = selectedKind;
    fields();
    updateSelectionCounts(form);
    installDraft();
  });
  fields();
  updateSelectionCounts(form);
  installDraft();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector('[type="submit"]');
    setButtonBusy(button, true);
    try {
      const values = new FormData(form),
        selectedKind = $("#gov-kind").value,
        data = {};
      for (const key of Object.keys(governanceFields[selectedKind])) {
        data[key] =
          key === "reference" && item
            ? item.reference
            : key.includes("likelihood") || key.includes("impact")
              ? Number(values.get(key))
              : values.get(key);
      }
      await request(
        "/api/governance/save",
        {
          record_id: item?.record_id || null,
          kind: selectedKind,
          title: values.get("title"),
          owner: values.get("owner"),
          expected_revision: item?.number || null,
          payload: {
            data,
            evidence_version_ids: values.getAll("evidence"),
            related_version_ids: values.getAll("related"),
          },
        },
        workspace,
      );
      if (workspace !== state.workspace_id) return;
      await completeDraft(form);
      $("#detail").close();
      await loadGovernance();
      toast("Pending governance version saved.");
    } catch (error) {
      form.querySelector('[role="alert"]').textContent = error.message;
    } finally {
      setButtonBusy(button, false);
    }
  });
}

async function governanceDetail(id) {
  const workspace = state.workspace_id,
    item = await documentGet(
      "/api/governance/" + encodeURIComponent(id),
      workspace,
    );
  const head = item.versions[0],
    writer = state.role !== "auditor";
  showDialog(
    head.title,
    `<div class="governance"><p>${esc(governanceKinds[head.kind])} · Owner: <span class="document-subject">${esc(head.owner)}</span></p>${writer ? '<button class="button secondary" id="governance-edit">Create next version</button>' : ""}${item.versions
      .map(
        (v) =>
          `<section class="document-version"><h3>Version ${v.number} · ${documentStatus(v.status)}</h3><p class="small">${documentDate(v.created_at)} · ${esc(v.created_by)}<br>Version ID: <span class="mono">${esc(v.id)}</span></p><dl class="governance-details">${Object.keys(
            governanceFields[v.kind],
          )
            .map(
              (key) =>
                `<dt>${esc(Array.isArray(governanceFields[v.kind][key]) ? governanceFields[v.kind][key][0] : governanceFields[v.kind][key])}</dt><dd>${esc(v.payload.data[key])}</dd>`,
            )
            .join(
              "",
            )}</dl>${v.risk_scores ? `<p>Inherent score: ${v.risk_scores.inherent.score} (${esc(v.risk_scores.inherent.band)}) · Residual: ${v.risk_scores.residual.score} (${esc(v.risk_scores.residual.band)})</p>` : ""}<p class="small">Supporting files: ${v.payload.evidence_version_ids.map((ref) => `<a href="/api/documents/versions/${encodeURIComponent(ref)}/download">${esc(ref)}</a>`).join(", ") || "None"}<br>Related governance version IDs: ${v.payload.related_version_ids.map(esc).join(", ") || "None"}</p><p class="mono document-hash">Payload SHA-256 ${esc(v.sha256)}</p><ol class="document-reviews">${v.reviews.map((r) => `<li><strong>${esc(r.decision)}</strong> · ${esc(r.reviewer)} · ${documentDate(r.created_at)}<p>${esc(r.comment)}</p></li>`).join("") || "<li>Pending independent review.</li>"}</ol>${writer && ((v.number === item.revision && ![v.owner, v.created_by, head.owner].includes(state.subject)) || v.status === "approved") ? `<form class="governance-review" data-version="${esc(v.id)}"><div class="field"><label for="gov-decision-${esc(v.id)}">Review decision for version ${v.number}</label><select id="gov-decision-${esc(v.id)}" name="decision">${v.number === item.revision && ![v.owner, v.created_by, head.owner].includes(state.subject) ? '<option value="approved">Approve</option><option value="rejected">Reject</option>' : ""}<option value="withdrawn">Withdraw approval</option></select></div><div class="field"><label for="gov-comment-${esc(v.id)}">Review rationale</label><textarea id="gov-comment-${esc(v.id)}" name="comment" maxlength="2000" required></textarea></div><p class="form-error" role="alert"></p><button type="submit" class="button primary">Record review</button></form>` : ""}</section>`,
      )
      .join(
        "",
      )}<p class="small">Review linked evidence and the exact data above before approving. Approval records a customer decision; it does not establish certification or independent assurance.</p></div>`,
    "GOVERNANCE / REVIEW HISTORY",
  );
  if (writer)
    $("#governance-edit").onclick = () =>
      governanceForm(head).catch((e) => toast(e.message, true));
  document.querySelectorAll(".governance-review").forEach((form) =>
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = form.querySelector('[type="submit"]');
      setButtonBusy(button, true);
      try {
        const version = item.versions.find(
            (v) => v.id === form.dataset.version,
          ),
          values = new FormData(form);
        await request(
          "/api/governance/review",
          {
            version_id: version.id,
            decision: values.get("decision"),
            comment: values.get("comment"),
            expected_review_id: version.reviews.at(-1)?.id || null,
          },
          workspace,
        );
        if (workspace !== state.workspace_id) return;
        await governanceDetail(id);
        await loadGovernance();
        toast("Governance review recorded.");
      } catch (error) {
        form.querySelector('[role="alert"]').textContent = error.message;
      } finally {
        setButtonBusy(button, false);
      }
    }),
  );
}

async function governanceExport(button) {
  const workspace = state.workspace_id;
  setButtonBusy(button, true);
  try {
    const response = await fetch("/api/governance/export", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-ClearTrail-Token": state.csrf,
        "X-ClearTrail-Workspace": workspace,
      },
      body: "{}",
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(
        ClearTrailUI.errorMessage(
          response.status,
          data.error ||
            "Export failed. Check approved records and linked evidence.",
        ),
      );
    }
    const blob = await response.blob();
    if (workspace !== state.workspace_id || !$("#governance-export-result"))
      return;
    const url = URL.createObjectURL(blob),
      link = document.createElement("a");
    link.href = url;
    link.download = "cleartrail-governance-register.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
    $("#governance-export-result").innerHTML =
      `<p>Register downloaded. Retain this SHA-256 through a trusted channel:</p><p class="mono document-hash">${esc(response.headers.get("X-ClearTrail-SHA256"))}</p><p class="small"><code>python -m cleartrail verify-governance cleartrail-governance-register.json --expected-sha256 &lt;trusted hash&gt;</code></p>`;
  } catch (error) {
    toast(error.message, true);
  } finally {
    setButtonBusy(button, false);
  }
}

document.addEventListener("click", (event) => {
  const open = event.target.closest("[data-governance-open]"),
    exportButton = event.target.closest("[data-governance-export]");
  if (event.target.closest("[data-governance-new]"))
    governanceForm().catch((e) => toast(e.message, true));
  if (event.target.closest("[data-governance-refresh]")) loadGovernance();
  if (open)
    governanceDetail(open.dataset.governanceOpen).catch((e) =>
      toast(e.message, true),
    );
  if (exportButton) governanceExport(exportButton);
});
const documentDate = (seconds) =>
  seconds ? date(new Date(seconds * 1000).toISOString()) : "No expiry";
const documentStatus = (status) =>
  `<span class="tag ${status === "approved" ? "pass" : status === "rejected" || status === "expired" ? "fail" : "unknown"}">${esc(status)}</span>`;

function documentsView() {
  if (state.mode !== "hosted")
    return '<section class="panel"><h2>Team documents</h2><p>Versioned documents and independent review require a hosted organization workspace.</p></section>';
  return `<section class="panel"><div class="section-title"><div><h2>Team evidence</h2><p>Exact file versions, accountable owners and independent review.</p></div><div class="document-actions"><button class="button secondary" data-document-refresh>Refresh</button>${state.role !== "auditor" ? '<button class="button primary" data-document-new>Upload evidence</button>' : '<span class="role-note">Approved, unexpired files only</span>'}</div></div><details class="scope-details"><summary>Accepted files and review requirements</summary><p class="small">Text, PDF, DOCX, XLSX and PPTX, up to 512 KiB each. Binary files require fresh scanning and download as attachments. New versions start pending; their uploader and owner cannot approve them. Files and approvals do not change automated control results.</p></details></section>${libraryToolbar("documents")}<div id="document-library" aria-busy="true"><p class="loading-line">Loading team evidence…</p></div>`;
}

async function documentGet(path, workspace) {
  const response = await fetch(path, { cache: "no-store" });
  const data = await response.json();
  if (workspace !== state?.workspace_id)
    throw new Error(
      "Workspace changed. Reopen the evidence in the current workspace.",
    );
  if (!response.ok)
    throw new Error(
      ClearTrailUI.errorMessage(
        response.status,
        data.error || "Evidence could not be loaded.",
      ),
    );
  Object.assign(identityLabels, data.identity_labels || {});
  return data;
}

async function loadDocuments() {
  const workspace = state.workspace_id,
    sequence = ++documentLoadSequence;
  const root = $("#document-library");
  if (!root) return;
  root.setAttribute("aria-busy", "true");
  try {
    const data = await documentGet(libraryPath("documents"), workspace);
    if (!$("#document-library") || sequence !== documentLoadSequence) return;
    documentLibrary = { ...data, workspace };
    root.innerHTML = `<div class="table-panel"><div class="table-scroll" tabindex="0" role="region" aria-label="Team documents"><table class="library-table" role="table"><thead><tr><th scope="col">Document / controls</th><th scope="col">Owner</th><th scope="col">Latest version</th><th scope="col">Review</th><th scope="col">Expires</th></tr></thead><tbody id="document-rows"></tbody></table></div><div class="table-bottom"><span id="documents-count" role="status" aria-live="polite"></span><span>${data.used_bytes === null ? "Approved history is available in document details." : `${(data.used_bytes / 1048576).toFixed(2)} / 25 MiB retained`}</span></div>${libraryPagination("documents", data)}</div>`;
    filterLibrary("documents");
    root.setAttribute("aria-busy", "false");
  } catch (error) {
    if (
      $("#document-library") &&
      sequence === documentLoadSequence &&
      workspace === state?.workspace_id
    )
      libraryFailure("documents", error);
  }
}

async function uploadDocumentDialog(item = null) {
  const workspace = state.workspace_id;
  const owners = await documentGet("/api/documents/owners", workspace);
  if (!documentLibrary || documentLibrary.workspace !== workspace)
    throw new Error("Refresh the document library before uploading.");
  const controls = documentLibrary.controls;
  showDialog(
    item ? "Upload a replacement version" : "Upload team evidence",
    `<p>Retain the original bytes and request independent review. Uploading a replacement starts a new pending review.</p><form id="document-upload-form">${item ? `<p><strong>${esc(item.title)}</strong><br>${item.control_ids.map(esc).join(" · ")} · Owner: ${esc(item.owner)}</p>` : `<div class="field"><label for="document-title">Document title</label><input id="document-title" name="title" maxlength="160" required></div><div class="field"><label for="document-owner">Responsible owner</label><select id="document-owner" name="owner">${owners.owners.map((owner) => `<option value="${esc(owner)}"${owner === state.subject ? " selected" : ""}>${esc(identityText(owner))}</option>`).join("")}</select></div><fieldset class="document-controls"><legend>Controls supported by this evidence</legend>${controls.map((control) => `<label><input type="checkbox" name="control_ids" value="${esc(control.id)}"> <span>${esc(control.id)} · ${esc(control.title)}</span></label>`).join("")}</fieldset>`}<div class="field"><label for="document-file">Evidence file (text, PDF or modern Office)</label><input id="document-file" name="file" type="file" accept=".txt,.md,.csv,.pdf,.docx,.xlsx,.pptx" required><small>Up to 512 KiB. PDF and modern Office files require fresh scanning; encrypted files, macros and embedded objects are rejected. Do not upload credentials.</small></div><div class="field"><label for="document-expiry">Expires at (optional, your local time)</label><input id="document-expiry" name="expires_at" type="datetime-local"></div><p class="form-error" role="alert"></p><button class="button primary" type="submit">Save pending version</button></form>`,
    "TEAM EVIDENCE",
  );
  $("#document-upload-form").evidenceContext = { workspace, item };
  attachDraft($("#document-upload-form"), "document:" + (item?.id || "new"));
}

async function documentDetail(id) {
  const workspace = state.workspace_id;
  const item = await documentGet(
    "/api/documents/" + encodeURIComponent(id),
    workspace,
  );
  const writer = state.role !== "auditor";
  const latest = item.versions[0];
  const currentReview = latest.reviews.at(-1);
  const independent =
    writer &&
    ![item.owner, latest.owner_at_upload, latest.uploaded_by].includes(
      state.subject,
    );
  showDialog(
    item.title,
    `<p>${item.control_ids.map(esc).join(" · ")}<br>Responsible owner: <strong class="document-subject">${identityHTML(item.owner)}</strong></p>${writer ? '<div class="document-actions"><button class="button secondary" id="document-replace">Upload next version</button><button class="button secondary" id="document-assign">Assign owner</button></div>' : ""}<h3 class="section-space">Version history</h3>${item.versions.map((version) => `<section class="document-version"><div class="section-title"><h3>Version ${version.number} · ${esc(version.filename)}</h3>${documentStatus(version.status)}</div><p class="small">Uploaded ${documentDate(version.created_at)} by <span class="document-subject">${identityHTML(version.uploaded_by)}</span><br>${version.size} bytes · Expires: ${documentDate(version.expires_at)}</p><p class="mono document-hash">SHA-256 ${esc(version.sha256)}</p><p class="small">Scan: ${esc(version.scan?.status || "legacy text; not scanned")}${version.scan?.engine ? " · " + esc(version.scan.engine) + " · definitions " + esc(version.scan.definitions_version) : ""}</p><a class="text-button" href="/api/documents/versions/${encodeURIComponent(version.id)}/download">Download exact version ${icon("download")}</a><ol class="document-reviews">${version.reviews.map((review) => `<li><strong>${esc(review.decision)}</strong> · <span class="document-subject">${identityHTML(review.reviewer)}</span> · ${documentDate(review.created_at)}<p>${esc(review.comment)}</p></li>`).join("") || "<li>Pending independent review.</li>"}</ol>${writer && version.reviews.at(-1)?.decision === "approved" ? `<button class="button secondary" data-document-withdraw="${esc(version.id)}">Withdraw this version’s approval</button>` : ""}</section>`).join("")}${independent ? `<form id="document-review-form" class="section-space"><h3>Review version ${latest.number}</h3><p class="small">Download and inspect the exact version above. Your decision applies to those bytes. The review history is retained.</p><div class="field"><label for="document-decision">Decision</label><select id="document-decision" name="decision"><option value="approved">Approve</option><option value="rejected">Reject</option><option value="withdrawn">Withdraw approval</option></select></div><div class="field"><label for="document-comment">Review rationale</label><textarea id="document-comment" name="comment" maxlength="2000" required></textarea></div><p class="form-error" role="alert"></p><button class="button primary" type="submit">Record review</button></form>` : writer ? '<p class="small section-space">An independent administrator or operator must review this version. Its uploader and owner cannot approve their own evidence.</p>' : ""}`,
    "IMMUTABLE VERSION HISTORY",
  );
  if (writer) {
    document.querySelectorAll("[data-document-withdraw]").forEach((button) => {
      button.addEventListener("click", () => {
        const version = item.versions.find(
          (saved) => saved.id === button.dataset.documentWithdraw,
        );
        showDialog(
          "Withdraw version approval",
          `<form id="document-withdraw-form"><p>${esc(item.title)} · version ${version.number}</p><p>Withdraw sharing of this version with auditors. The original file and approval remain in the history.</p><input name="decision" type="hidden" value="withdrawn"><div class="field"><label for="document-withdraw-reason">Reason for withdrawal</label><textarea id="document-withdraw-reason" name="comment" maxlength="2000" required></textarea></div><p class="form-error" role="alert"></p><button class="button primary" type="submit">Withdraw approval</button></form>`,
          "REVOKE AUDITOR ACCESS",
        );
        $("#document-withdraw-form").evidenceContext = {
          workspace,
          item,
          versionId: version.id,
          expectedReview: version.reviews.at(-1).id,
        };
      });
    });
    $("#document-replace").addEventListener("click", () =>
      uploadDocumentDialog(item).catch((error) => toast(error.message, true)),
    );
    $("#document-assign").addEventListener("click", async () => {
      try {
        const data = await documentGet("/api/documents/owners", workspace);
        showDialog(
          "Assign responsible owner",
          `<form id="document-assign-form"><p>${esc(item.title)}</p><div class="field"><label for="document-new-owner">Owner</label><select id="document-new-owner" name="owner">${data.owners.map((owner) => `<option value="${esc(owner)}"${owner === item.owner ? " selected" : ""}>${esc(identityText(owner))}</option>`).join("")}</select></div><p class="small">Ownership changes retain all version and review history.</p><p class="form-error" role="alert"></p><button class="button primary" type="submit">Assign owner</button></form>`,
          "EVIDENCE RESPONSIBILITY",
        );
        $("#document-assign-form").evidenceContext = { workspace, item };
      } catch (error) {
        toast(error.message, true);
      }
    });
  }
  if (independent)
    $("#document-review-form").evidenceContext = {
      workspace,
      item,
      expectedReview: currentReview?.id || null,
    };
}

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-document-new]"))
    uploadDocumentDialog().catch((error) => toast(error.message, true));
  if (event.target.closest("[data-document-refresh]")) loadDocuments();
  const target = event.target.closest("[data-document-open]");
  if (target)
    documentDetail(target.dataset.documentOpen).catch((error) =>
      toast(error.message, true),
    );
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!form.evidenceContext) return;
  event.preventDefault();
  const { workspace, item, expectedReview, versionId } = form.evidenceContext;
  const button = form.querySelector('[type="submit"]');
  setButtonBusy(button, true);
  try {
    if (form.id === "document-upload-form") {
      const file = form.elements.file.files[0];
      if (!file || !file.size || file.size > 524288)
        throw new Error("Choose a nonempty supported file up to 512 KiB.");
      const controls =
        item?.control_ids ||
        [...form.querySelectorAll('[name="control_ids"]:checked')].map(
          (input) => input.value,
        );
      if (!controls.length)
        throw new Error(
          "Select at least one control supported by this evidence.",
        );
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (let offset = 0; offset < bytes.length; offset += 16384)
        binary += String.fromCharCode(
          ...bytes.subarray(offset, offset + 16384),
        );
      await request(
        "/api/documents/upload",
        {
          document_id: item?.id || null,
          title: item?.title || form.elements.title.value,
          control_ids: controls,
          owner: item?.owner || form.elements.owner.value,
          filename: file.name,
          content_base64: btoa(binary),
          expires_at: form.elements.expires_at.value
            ? Math.floor(
                new Date(form.elements.expires_at.value).getTime() / 1000,
              )
            : null,
          expected_version_id: item?.versions[0].id || null,
          expected_revision: item?.revision || null,
        },
        workspace,
      );
    } else if (form.id === "document-assign-form") {
      await request(
        "/api/documents/assign",
        {
          document_id: item.id,
          owner: form.elements.owner.value,
          expected_revision: item.revision,
        },
        workspace,
      );
    } else {
      await request(
        "/api/documents/review",
        {
          version_id: versionId || item.versions[0].id,
          decision: form.elements.decision.value,
          comment: form.elements.comment.value,
          expected_review_id: expectedReview,
        },
        workspace,
      );
    }
    if (workspace !== state?.workspace_id) return;
    await completeDraft(form);
    $("#detail").close();
    await loadDocuments();
    toast("Evidence history saved.");
  } catch (error) {
    form.querySelector('[role="alert"]').textContent = error.message;
  } finally {
    setButtonBusy(button, false);
  }
});

// Private drafts live in the encrypted server store, never localStorage.
const draftContexts = new WeakMap();
const draftAllowed = {
  governance: new Set([
    "kind",
    "title",
    "owner",
    ...Object.values(governanceFields).flatMap((fields) => Object.keys(fields)),
    "evidence",
    "related",
  ]),
  document: new Set(["title", "owner", "control_ids", "expires_at"]),
  schedule: new Set(["enabled", "interval_hours", "freshness_hours"]),
  attestation: new Set(["owner", "note"]),
};
function draftSnapshot(form, context) {
  return ClearTrailUI.draftFields(
    [...form.elements],
    draftAllowed[context.kind],
    context.kind === "governance" ? context.recordKind : null,
  );
}
function draftStatus(context, message, error = false) {
  if (!context.form.isConnected || draftContexts.get(context.form) !== context)
    return;
  const line = context.panel.querySelector("[role=status]");
  line.textContent = message;
  line.classList.toggle("form-error", error);
}
function currentDraftContext(context) {
  return (
    authenticated &&
    state?.mode === "hosted" &&
    state.workspace_id === context.workspace &&
    state.subject === context.subject &&
    state.role === context.role
  );
}
async function draftWrite(context, fields) {
  if (!currentDraftContext(context))
    throw new Error("Workspace or access changed. The draft was not sent.");
  const response = await fetch("/api/drafts", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-ClearTrail-Token": state.csrf,
      "X-ClearTrail-Workspace": context.workspace,
    },
    body: JSON.stringify({
      key: context.key,
      fields,
      expected_revision: context.revision,
    }),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      response.status === 409
        ? "The workspace or saved draft changed. The saved copy was not overwritten. Reopen the correct workspace and form before saving again."
        : ClearTrailUI.errorMessage(response.status, data.error),
    );
  if (!currentDraftContext(context))
    throw new Error("Workspace changed while the draft was saving.");
  context.revision = data.draft?.revision || null;
  return data;
}
async function flushDraft(
  form,
  context = draftContexts.get(form),
  force = false,
) {
  if (!context) return;
  clearTimeout(context.timer);
  const task = context.enqueue(async () => {
    await context.ready;
    if (context.pendingRestore)
      throw new Error(
        "Restore or discard the saved draft before leaving this form.",
      );
    const fields = structuredClone(context.fields),
      encoded = JSON.stringify(fields);
    if (encoded === context.persisted && (!force || context.revision)) return;
    draftStatus(context, "Saving private draft…");
    await draftWrite(context, fields);
    context.persisted = encoded;
    if (context.panel.isConnected)
      context.panel.querySelector("[data-draft-discard]").hidden = false;
    draftStatus(
      context,
      "Private draft saved for 7 days. It is visible only to you in this workspace.",
    );
  });
  context.saving = task;
  try {
    await task;
  } catch (error) {
    draftStatus(context, error.message, true);
    throw error;
  } finally {
    if (context.saving === task) context.saving = null;
  }
}
async function clearDraft(form) {
  const context = draftContexts.get(form);
  if (!context) return;
  clearTimeout(context.timer);
  await context.ready;
  if (context.saving) await context.saving;
  await draftWrite(context, null);
  context.persisted = JSON.stringify(context.fields);
  context.pendingRestore = false;
}
async function completeDraft(form) {
  try {
    await clearDraft(form);
  } catch (error) {
    toast(
      "Record saved. Its private draft could not be cleared; reopen and discard it before reuse.",
      true,
    );
  }
}
function restoreDraftFields(form, fields) {
  let unavailable = 0;
  for (const input of form.elements) {
    if (
      !Object.hasOwn(fields, input.name) ||
      ["file", "password"].includes(input.type)
    )
      continue;
    const value = fields[input.name];
    if (input.type === "checkbox")
      input.checked = Array.isArray(value)
        ? value.includes(input.value)
        : value === "true";
    else if (input.tagName === "SELECT") {
      if ([...input.options].some((option) => option.value === value))
        input.value = value;
      else unavailable++;
    } else input.value = value;
    if (input.name === "applicability") form.syncDraftFields?.();
  }
  if (form.id === "schedule-form")
    form.elements.freshness_hours.min = form.elements.interval_hours.value;
  for (const name of ["evidence", "related", "control_ids"]) {
    if (Array.isArray(fields[name]))
      unavailable += fields[name].filter(
        (value) =>
          ![...form.elements].some(
            (input) => input.name === name && input.value === value,
          ),
      ).length;
  }
  updateSelectionCounts(form);
  return unavailable;
}
function attachDraft(form, key, recordKind = null) {
  if (!form || state?.mode !== "hosted" || state.role === "auditor") return;
  form.querySelector(".private-draft")?.remove();
  const kind = key.split(":")[0],
    panel = document.createElement("section");
  panel.className = "private-draft";
  panel.setAttribute("aria-label", "Private draft recovery");
  panel.innerHTML =
    '<p role="status">Checking for a private draft…</p><p class="small">Encrypted recovery for 7 days, only for your identity and workspace. Upload files and credentials are never retained. Evidence links are rechecked before publication. Saving a draft does not publish evidence.</p><div class="document-actions"><button type="button" class="button secondary" data-draft-restore hidden>Restore draft</button><button type="button" class="button secondary" data-draft-save>Save draft now</button><button type="button" class="button secondary" data-draft-discard hidden>Discard saved draft</button></div>';
  form.prepend(panel);
  const context = {
    form,
    panel,
    key,
    kind,
    recordKind,
    workspace: state.workspace_id,
    subject: state.subject,
    role: state.role,
    revision: null,
    persisted: null,
    pendingRestore: false,
    saving: null,
    enqueue: ClearTrailUI.serialQueue(),
  };
  context.fields = draftSnapshot(form, context);
  context.persisted = JSON.stringify(context.fields);
  draftContexts.set(form, context);
  context.ready = (async () => {
    const data = await documentGet(
      "/api/drafts?key=" + encodeURIComponent(key),
      context.workspace,
    );
    if (!currentDraftContext(context)) return;
    context.revision = data.draft?.revision || null;
    if (data.draft) {
      context.pendingRestore = true;
      context.savedFields = data.draft.fields;
      draftStatus(
        context,
        "A private draft is available from " +
          documentDate(data.draft.updated_at) +
          ". Review it before publishing; previously selected files must be chosen again.",
      );
      panel.querySelector("[data-draft-restore]").hidden = false;
      panel.querySelector("[data-draft-discard]").hidden = false;
    } else
      draftStatus(
        context,
        "Private recovery is ready. Supported fields save automatically while you edit.",
      );
  })().catch((error) => {
    draftStatus(
      context,
      "Private recovery unavailable: " + error.message,
      true,
    );
    throw error;
  });
  // The UI reports load failures; retain a rejection for explicit flush/save.
  context.ready.catch(() => {});
  panel
    .querySelector("[data-draft-save]")
    .addEventListener("click", () =>
      flushDraft(form, context, true).catch(() => {}),
    );
  panel.querySelector("[data-draft-restore]").addEventListener("click", () => {
    if (
      JSON.stringify(context.fields) !== context.persisted &&
      !context.restoreConfirmed
    ) {
      context.restoreConfirmed = true;
      panel.querySelector("[data-draft-restore]").textContent =
        "Replace current edits";
      draftStatus(
        context,
        "Restoring replaces the text currently in this form. Select Replace current edits to confirm.",
        true,
      );
      return;
    }
    const unavailable = restoreDraftFields(form, context.savedFields);
    context.pendingRestore = false;
    context.fields = draftSnapshot(form, context);
    context.persisted = JSON.stringify(context.fields);
    panel.querySelector("[data-draft-restore]").hidden = true;
    form.dataset.unsaved = "true";
    if (form.closest("#detail")) dialogDirty = true;
    draftStatus(
      context,
      "Draft restored. Review all fields before saving." +
        (unavailable
          ? ` ${unavailable} selections are no longer available; choose current evidence/owners.`
          : ""),
    );
    form.querySelector("input:not([type=hidden]),textarea,select")?.focus();
  });
  panel
    .querySelector("[data-draft-discard]")
    .addEventListener("click", async () => {
      try {
        await clearDraft(form);
        panel.querySelector("[data-draft-restore]").hidden = true;
        panel.querySelector("[data-draft-discard]").hidden = true;
        draftStatus(
          context,
          "Saved draft discarded. Current form values remain.",
        );
      } catch (error) {
        draftStatus(context, error.message, true);
      }
    });
}
for (const eventName of ["input", "change"])
  document.addEventListener(eventName, (event) => {
    const form = event.target.closest("form"),
      context = draftContexts.get(form);
    if (!context || !draftAllowed[context.kind].has(event.target.name)) return;
    context.fields = draftSnapshot(form, context);
    clearTimeout(context.timer);
    context.timer = setTimeout(
      () => flushDraft(form, context).catch(() => {}),
      1000,
    );
  });
function draftDescription(key) {
  const [kind, id] = key.split(":");
  if (kind === "governance") {
    const type = Object.keys(governanceKinds).find((k) => id.endsWith("-" + k));
    return (
      (id.startsWith("new-") ? "New " : "") +
      (governanceKinds[type] || "governance record")
    );
  }
  return (
    {
      document: id === "new" ? "New team document" : "Document metadata",
      schedule: "Monitoring policy",
      attestation: "Team note · " + id,
    }[kind] || "Private form draft"
  );
}
function draftTitle(draft) {
  return draft.title && draft.title !== draft.key
    ? draft.title
    : draftDescription(draft.key);
}
async function manageDrafts() {
  const data = await documentGet("/api/draft-index", state.workspace_id);
  showDialog(
    "Your private drafts",
    `<p>Only you can recover these copies in this workspace. They expire after seven days and are excluded from approved exports. Resume opens the relevant form; choose Restore draft to review its contents.</p><p>${data.drafts.length} / ${data.limit} private drafts</p><ul class="draft-list">${data.drafts.map((d) => `<li><div><strong>${esc(draftTitle(d))}</strong><p class="small">${esc(draftDescription(d.key))}<br>Saved ${documentDate(d.updated_at)} · Expires ${documentDate(d.expires_at)}</p></div><div class="document-actions"><button class="button secondary" aria-label="Resume ${esc(draftTitle(d))}" data-resume-draft="${esc(d.key)}">Resume</button><button class="button secondary" aria-label="Discard draft ${esc(draftTitle(d))}" data-delete-draft="${esc(d.key)}" data-revision="${esc(d.revision)}">Discard draft</button></div></li>`).join("") || "<li>No private drafts. Supported forms save recovery copies while you edit.</li>"}</ul>`,
    "PRIVATE RECOVERY",
  );
}
async function activateView(target) {
  $("#detail").close();
  if (view() === target) {
    render();
    return;
  }
  await new Promise((resolve) => {
    window.addEventListener("hashchange", resolve, { once: true });
    location.hash = target;
  });
}
async function resumeDraft(key) {
  const [kind, id] = key.split(":");
  if (kind === "governance") {
    const match =
      /^(new|[a-f0-9-]{36})-(risk|applicability|internal_audit|management_review|corrective_action)$/.exec(
        id,
      );
    if (!match)
      throw new Error("Open the original record to recover this draft.");
    await activateView("governance");
    const item =
      match[1] === "new"
        ? null
        : (
            await documentGet(
              "/api/governance/" + encodeURIComponent(match[1]),
              state.workspace_id,
            )
          ).versions[0];
    await governanceForm(item, match[2]);
  } else if (kind === "document") {
    await activateView("documents");
    await loadDocuments();
    const item =
      id === "new"
        ? null
        : await documentGet(
            "/api/documents/" + encodeURIComponent(id),
            state.workspace_id,
          );
    await uploadDocumentDialog(item);
  } else if (kind === "schedule") {
    await activateView("monitoring");
  } else if (kind === "attestation") {
    if (!state.run?.checks.some((c) => c.id === id && c.provider === "manual"))
      throw new Error(
        "Collect a current snapshot before reopening this team note.",
      );
    await activateView("controls");
    controlDetail(id);
  }
}
document.addEventListener("click", async (event) => {
  const resume = event.target.closest("[data-resume-draft]"),
    discard = event.target.closest("[data-delete-draft]");
  try {
    if (resume) await resumeDraft(resume.dataset.resumeDraft);
    if (discard) {
      await request("/api/drafts", {
        key: discard.dataset.deleteDraft,
        fields: null,
        expected_revision: discard.dataset.revision,
      });
      await manageDrafts();
      announce("Private draft discarded.");
    }
  } catch (error) {
    toast(error.message, true);
  }
});
function draftDurable(form) {
  const context = draftContexts.get(form);
  return (
    context &&
    !context.pendingRestore &&
    !context.saving &&
    context.persisted === JSON.stringify(context.fields)
  );
}
async function preserveEditing() {
  const form = $("#detail[open] form") || $("#content form[data-unsaved]");
  if (!form || (form.closest("#detail") && !dialogDirty)) return;
  if (draftContexts.has(form)) await flushDraft(form);
  else if (dialogDirty || form.dataset.unsaved)
    throw new Error("Finish or close the current form before changing pages.");
}

initialize();
setInterval(() => {
  if (!document.hidden) refresh(false);
}, 5000);
