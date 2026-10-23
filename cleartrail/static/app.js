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
};
let state,
  selected = "all",
  query = "",
  provider = "all",
  framework = "all",
  lastRunning = false,
  toastTimer,
  loading = false;
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
  if (!response.ok) throw new Error(data.error || "Request failed.");
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
              )}</td><td><button class="evidence-button" data-control="${c.id}">${icon(c.provider === "manual" ? "file" : "folder")}${c.resource_count ? `${c.resource_count} record${c.resource_count === 1 ? "" : "s"}` : c.provider === "manual" ? "Add note" : "No records"}${icon("arrow")}</button></td></tr>`,
        )
        .join("")
    : '<tr><td colspan="5" class="empty-cell">No controls match these filters. Try another search or source.</td></tr>';
  $("#result-count").textContent =
    `Showing ${checks.length} of ${state.run.checks.length} controls`;
}
function evidenceView() {
  const records = state.run.evidence;
  return `<div class="section-title"><div><h2>Collected evidence</h2><p>Captured ${date(state.run.collected_at)} · ${records.length} records</p></div><a class="text-button" href="/api/csv">Download control index ${icon("download")}</a></div><div class="table-panel"><div class="table-toolbar"><label class="search">${icon("search")}<input id="evidence-search" aria-label="Search evidence" placeholder="Find evidence…"></label><span class="small muted">SHA-256 integrity hashes</span></div><div class="table-scroll"><table><thead><tr><th scope="col">RESOURCE / CONTROL</th><th scope="col">SOURCE</th><th scope="col">RESULT</th><th scope="col">COLLECTED</th><th scope="col">RECORD</th></tr></thead><tbody id="evidence-rows"></tbody></table></div><div class="table-bottom"><span>${records.length} point-in-time records</span><span>${state.demo ? "Synthetic demonstration" : state.mode === "hosted" ? "Organization evidence storage" : "Local evidence storage"}</span></div></div>`;
}
function evidenceRows(q = "") {
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
      return `<section class="integration-card">${mark(p)}<h2>${names[p]}</h2><p>${descriptions[p]}</p><span class="tag ${info.active ? "pass" : "unknown"}"><i class="dot"></i>${info.label}</span><button class="button secondary" data-setup="${p}">Setup instructions ${icon("arrow")}</button></section>`;
    })
    .join(
      "",
    )}</div><div class="bottom-callout">${icon("lock")}<div><h3>Credentials stay out of your reports.</h3><p>Use environment variables or your AWS credential chain. Setup happens on your machine.</p></div></div><section class="panel section-space"><h2>Collection boundaries</h2><p class="small">Only configured sources are collected. Missing access and unsupported settings are recorded as unknown. The current release checks classic GitHub branch protection and one configured AWS region. Google access tokens must be refreshed by your own identity workflow.</p></section>`;
}
function reportsView() {
  return `<section class="report-callout">${icon("file")}<div><h2>Ready for a closer look.</h2><p>A printable HTML report, control index, JSON source records, and a SHA-256 manifest — packaged together for your reviewer.</p><span class="small muted">${state.run ? date(state.run.collected_at) : "Collect evidence to create a package"} · ${state.demo ? "Synthetic demo" : "Point-in-time snapshot"}</span></div>${state.run ? `<a class="button primary" href="/api/export">${icon("download")}Download package</a>` : ""}</section>${state.mode === "hosted" ? '<section class="panel"><p class="small">Snapshot packages contain automated evidence and manual notes. Create an audit package to include selected approved team files, scan records and review history. <button class="button secondary" data-audit-package>Create audit package</button></p></section>' : ""}<section class="panel"><h2>Know what the report proves</h2><p class="small">These checks support evidence review. They do not cover the full framework, establish that controls operated throughout an audit period, or guarantee auditor acceptance. File hashes detect changes against a trusted manifest; the manifest is unsigned.</p><pre>python -m cleartrail verify path/to/cleartrail-package.zip</pre>${state.run ? '<a class="text-button" href="/api/report" target="_blank" rel="noopener">Open printable report ' + icon("arrow") + "</a>" : ""}</section><div class="section-title section-space"><div><h2>Collection history</h2><p>The latest 20 snapshots retained in this workspace.</p></div></div><div class="table-panel"><div class="table-scroll"><table><thead><tr><th scope="col">COLLECTED</th><th scope="col">SNAPSHOT</th><th scope="col">PASSING</th><th scope="col">EVIDENCE</th><th scope="col">MODE</th></tr></thead><tbody>${state.history.map((r) => `<tr><td>${date(r.collected_at)}</td><td class="mono"><a href="/api/export?run_id=${encodeURIComponent(r.id)}">${esc(r.id)}</a></td><td>${r.summary.passed} / ${r.summary.total}</td><td>${r.summary.evidence_count} records</td><td>${r.demo ? "Demo" : "Live"}</td></tr>`).join("") || '<tr><td colspan="5" class="empty-cell">No snapshots collected yet.</td></tr>'}</tbody></table></div></div>`;
}
function render() {
  if (!state) return;
  const v = view();
  $("#monitoring-nav").hidden = state.mode !== "hosted";
  $("#documents-nav").hidden = state.mode !== "hosted";
  $("#page-name").textContent = views[v][0];
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
  $("#collect").disabled = state.job.running || state.role === "auditor";
  $("#collect span").textContent = state.job.running
    ? state.job.status === "queued"
      ? "Queued…"
      : "Collecting…"
    : "Collect evidence";
  let content;
  if (v === "documents") content = documentsView();
  else if (v === "monitoring") content = monitoringView();
  else if (v === "integrations") content = integrationsView();
  else if (v === "reports") content = reportsView();
  else if (!run)
    content = `<section class="panel empty">${icon("folder")}<h2>Your evidence trail starts here.</h2><p>Configure a read-only integration, then collect your first snapshot. Unconfigured controls will stay unknown.</p><a class="button primary" href="#integrations">Set up integrations ${icon("arrow")}</a><p class="small">To explore with synthetic data: <code>python -m cleartrail serve --demo</code></p></section>`;
  else if (v === "evidence") content = evidenceView();
  else
    content =
      (v === "overview" ? stats() + overviewPanels() : "") +
      controlsTable() +
      (v === "overview"
        ? `<div class="bottom-callout">${icon("file")}<div><h3>A little documentation goes a long way.</h3><p>Add an owner and review notes for the work that happens beyond the API.</p></div><button class="text-button" data-control="MAN-POLICY">Add team evidence ${icon("arrow")}</button></div>`
        : "");
  $("#content").innerHTML = content;
  if (v === "documents" && state.mode === "hosted") loadDocuments();
  if (run) {
    filterRows();
    if (v === "evidence") evidenceRows();
  }
  decorateWorkspace();
  renderHealthStatus();
  if (state.job.error && state.mode !== "hosted")
    toast(
      "Collection did not complete: " +
        state.job.error +
        ". Review access and retry.",
      true,
    );
}
function showDialog(title, content, eyebrow = "EVIDENCE DETAIL") {
  $("#dialog-eyebrow").textContent = eyebrow;
  $("#dialog-body").innerHTML =
    `<h2 id="dialog-title">${esc(title)}</h2>${content}`;
  if (!$("#detail").open) $("#detail").showModal();
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
  if (loading || !authenticated) return;
  loading = true;
  try {
    const response = await fetch(
      "/api/state" +
        (state?.run?.id ? "?since=" + encodeURIComponent(state.run.id) : ""),
      { cache: "no-store" },
    );
    if (response.status === 401) {
      authenticated = false;
      state = null;
      showSignIn();
      return;
    }
    if (!response.ok) throw new Error("The workspace could not be loaded.");
    const next = await response.json();
    if (next.unchanged && state?.run) next.run = state.run;
    const changed =
      !state ||
      next.run?.id !== state.run?.id ||
      next.job.running !== state.job.running ||
      next.job.error !== state.job.error ||
      next.workspace_id !== state.workspace_id ||
      next.role !== state.role ||
      monitoringKey(next) !== monitoringKey(state);
    state = next;
    if (full || changed) {
      if (!full && document.activeElement?.closest("#schedule-form"))
        renderHealthStatus();
      else render();
    }
    if (lastRunning && !state.job.running && !state.job.error)
      toast("Collection saved. Your latest evidence package is ready.");
    lastRunning = state.job.running;
  } catch (e) {
    toast(
      e.message || "Connection lost. Check the service and try again.",
      true,
    );
  } finally {
    loading = false;
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
$("#close-dialog").addEventListener("click", () => $("#detail").close());
document.addEventListener("click", (e) => {
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
  if (e.target.id === "evidence-search") evidenceRows(e.target.value);
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
  button.disabled = true;
  try {
    const result = await request("/api/attest", {
      control_id: form.dataset.id,
      owner: form.owner.value,
      note: form.note.value,
    });
    await refresh(false);
    $("#detail").close();
    toast(result.message);
  } catch (err) {
    $("#form-error").textContent = err.message;
  } finally {
    button.disabled = false;
  }
});
window.addEventListener("hashchange", () => {
  query = "";
  selected = "all";
  provider = "all";
  framework = "all";
  render();
});
let authenticated = false,
  authMode = "local";

function showSignIn() {
  documentLibrary = null;
  $("#export").hidden = true;
  $("#collect").disabled = true;
  $("#banner").hidden = true;
  $("#health-status").hidden = true;
  $("#monitoring-nav").hidden = true;
  $("#documents-nav").hidden = true;
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
    `<label class="sr-only" for="workspace-switch">Workspace</label><select id="workspace-switch">${state.workspaces.map((w) => `<option value="${esc(w.id)}" ${w.id === state.workspace_id ? "selected" : ""}>${esc(w.name)} · ${esc(w.role)}</option>`).join("")}</select>${state.role === "admin" ? '<button class="text-button" id="manage-members">Members</button>' : ""}<button class="text-button" id="sign-out">Sign out</button>`;
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
    showDialog(
      "Workspace access",
      `<p>Membership uses the exact subject from the configured identity provider. Each identity must sign in through that provider.</p><ul>${result.members.map((m) => `<li><code>${esc(m.subject)}</code> · ${esc(m.role)}</li>`).join("")}</ul><form id="member-form"><div class="field"><label for="member-subject">Identity provider subject</label><input id="member-subject" name="subject" required maxlength="255"></div><div class="field"><label for="member-role">Role</label><select id="member-role" name="role"><option value="auditor">Auditor · read and export</option><option value="operator">Operator · collect and add notes</option><option value="admin">Administrator · manage integrations and access</option><option value="remove">Remove access</option></select></div><p class="form-error" id="member-error" role="alert"></p><button class="button primary" type="submit">Save membership</button></form>`,
      "WORKSPACE ADMINISTRATION",
    );
  } catch (error) {
    toast(error.message, true);
  }
}

document.addEventListener("change", async (event) => {
  if (event.target.id !== "workspace-switch") return;
  try {
    await request("/api/workspace", { tenant_id: event.target.value });
    if ($("#detail").open) $("#detail").close();
    documentLibrary = null;
    state = null;
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
});

document.addEventListener("click", async (event) => {
  if (event.target.closest("#manage-members")) manageMembers();
  if (event.target.closest("#sign-out")) {
    try {
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
  if (!["local-login", "integration-form", "member-form"].includes(form.id))
    return;
  event.preventDefault();
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
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
    button.disabled = false;
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
  element.innerHTML = `<div><strong>${esc(healthLabels[health.status] || "Evidence status")}</strong><p>${esc(health.message + extra)}</p></div><a class="text-button" href="#monitoring">Review monitoring ${icon("arrow")}</a>`;
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
  button.disabled = true;
  try {
    const values = new FormData(form);
    await request("/api/schedule", {
      enabled: values.has("enabled"),
      interval_hours: Number(values.get("interval_hours")),
      freshness_hours: Number(values.get("freshness_hours")),
    });
    await refresh();
    toast("Monitoring policy saved.");
  } catch (error) {
    $("#schedule-error").textContent = error.message;
  } finally {
    button.disabled = false;
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
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
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
        (await response.json()).error || "Package generation failed.",
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
    $("#audit-package-result").innerHTML =
      `<p>Package downloaded. Retain this manifest SHA-256 separately through a trusted channel:</p><p class="mono document-hash">${esc(response.headers.get("X-ClearTrail-Manifest-SHA256"))}</p><p class="small">Verify offline: <code>python -m cleartrail verify-audit cleartrail-audit-package.zip --manifest-sha256 &lt;trusted hash&gt;</code></p>`;
  } catch (error) {
    form.querySelector('[role="alert"]').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
let documentLoadSequence = 0;
const documentDate = (seconds) =>
  seconds ? date(new Date(seconds * 1000).toISOString()) : "No expiry";
const documentStatus = (status) =>
  `<span class="tag ${status === "approved" ? "pass" : status === "rejected" || status === "expired" ? "fail" : "unknown"}">${esc(status)}</span>`;

function documentsView() {
  if (state.mode !== "hosted")
    return '<section class="panel"><h2>Team documents</h2><p>Versioned documents and independent review require a hosted organization workspace.</p></section>';
  return `<section class="panel"><div class="section-title"><div><h2>Team evidence</h2><p>Each upload is encrypted and retained as an immutable version. Approval requires someone other than its uploader and owner.</p></div><div class="document-actions"><button class="button secondary" data-document-refresh>Refresh</button>${state.role !== "auditor" ? '<button class="button primary" data-document-new>Upload evidence</button>' : ""}</div></div><p class="small muted">Text, PDF, DOCX, XLSX and PPTX · 512 KiB per file. Binary files require fresh ClamAV scanning and download as attachments. Customer evidence and approvals do not change automated control results. Auditors see approved, unexpired versions.</p></section><div id="document-library" class="section-space" aria-live="polite"><p>Loading team evidence…</p></div>`;
}

async function documentGet(path, workspace) {
  const response = await fetch(path, { cache: "no-store" });
  const data = await response.json();
  if (workspace !== state?.workspace_id)
    throw new Error(
      "Workspace changed. Reopen the evidence in the current workspace.",
    );
  if (!response.ok)
    throw new Error(data.error || "Evidence could not be loaded.");
  return data;
}

async function loadDocuments() {
  const workspace = state.workspace_id;
  const sequence = ++documentLoadSequence;
  try {
    const data = await documentGet("/api/documents", workspace);
    if (!$("#document-library") || sequence !== documentLoadSequence) return;
    documentLibrary = { ...data, workspace };
    $("#document-library").innerHTML =
      `<div class="table-panel"><div class="table-scroll"><table><thead><tr><th scope="col">DOCUMENT / CONTROLS</th><th scope="col">OWNER</th><th scope="col">LATEST VERSION</th><th scope="col">REVIEW</th><th scope="col">EXPIRES</th></tr></thead><tbody>${data.documents.map((item) => `<tr><td><button class="control-title" data-document-open="${esc(item.id)}">${esc(item.title)}</button><div class="control-sub">${item.control_ids.map(esc).join(" · ")}</div></td><td class="document-subject">${esc(item.owner)}</td><td>v${item.latest_version.number} · ${esc(item.latest_version.filename)}</td><td>${documentStatus(item.latest_version.status)}</td><td>${documentDate(item.latest_version.expires_at)}</td></tr>`).join("") || '<tr><td colspan="5" class="empty-cell">No evidence available. Upload a policy, access review, or incident exercise record to begin.</td></tr>'}</tbody></table></div><div class="table-bottom"><span>${data.documents.length} ${state.role === "auditor" ? "approved documents" : "documents"}</span><span>${data.used_bytes === null ? "Historical approved versions remain available from document details." : `${(data.used_bytes / 1048576).toFixed(2)} / 25 MiB retained`}</span></div></div>`;
  } catch (error) {
    if ($("#document-library") && sequence === documentLoadSequence)
      $("#document-library").textContent = error.message;
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
    `<p>Retain the original bytes and request independent review. Uploading a replacement starts a new pending review.</p><form id="document-upload-form">${item ? `<p><strong>${esc(item.title)}</strong><br>${item.control_ids.map(esc).join(" · ")} · Owner: ${esc(item.owner)}</p>` : `<div class="field"><label for="document-title">Document title</label><input id="document-title" name="title" maxlength="160" required></div><div class="field"><label for="document-owner">Responsible owner</label><select id="document-owner" name="owner">${owners.owners.map((owner) => `<option value="${esc(owner)}"${owner === state.subject ? " selected" : ""}>${esc(owner)}</option>`).join("")}</select></div><fieldset class="document-controls"><legend>Controls supported by this evidence</legend>${controls.map((control) => `<label><input type="checkbox" name="control_ids" value="${esc(control.id)}"> <span>${esc(control.id)} · ${esc(control.title)}</span></label>`).join("")}</fieldset>`}<div class="field"><label for="document-file">Evidence file (text, PDF or modern Office)</label><input id="document-file" name="file" type="file" accept=".txt,.md,.csv,.pdf,.docx,.xlsx,.pptx" required><small>Up to 512 KiB. PDF and modern Office files require fresh scanning; encrypted files, macros and embedded objects are rejected. Do not upload credentials.</small></div><div class="field"><label for="document-expiry">Expires at (optional, your local time)</label><input id="document-expiry" name="expires_at" type="datetime-local"></div><p class="form-error" role="alert"></p><button class="button primary" type="submit">Save pending version</button></form>`,
    "TEAM EVIDENCE",
  );
  $("#document-upload-form").evidenceContext = { workspace, item };
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
    `<p>${item.control_ids.map(esc).join(" · ")}<br>Responsible owner: <strong class="document-subject">${esc(item.owner)}</strong></p>${writer ? '<div class="document-actions"><button class="button secondary" id="document-replace">Upload next version</button><button class="button secondary" id="document-assign">Assign owner</button></div>' : ""}<h3 class="section-space">Version history</h3>${item.versions.map((version) => `<section class="document-version"><div class="section-title"><h3>Version ${version.number} · ${esc(version.filename)}</h3>${documentStatus(version.status)}</div><p class="small">Uploaded ${documentDate(version.created_at)} by <span class="document-subject">${esc(version.uploaded_by)}</span><br>${version.size} bytes · Expires: ${documentDate(version.expires_at)}</p><p class="mono document-hash">SHA-256 ${esc(version.sha256)}</p><p class="small">Scan: ${esc(version.scan?.status || "legacy text; not scanned")}${version.scan?.engine ? " · " + esc(version.scan.engine) + " · definitions " + esc(version.scan.definitions_version) : ""}</p><a class="text-button" href="/api/documents/versions/${encodeURIComponent(version.id)}/download">Download exact version ${icon("download")}</a><ol class="document-reviews">${version.reviews.map((review) => `<li><strong>${esc(review.decision)}</strong> · <span class="document-subject">${esc(review.reviewer)}</span> · ${documentDate(review.created_at)}<p>${esc(review.comment)}</p></li>`).join("") || "<li>Pending independent review.</li>"}</ol>${writer && version.reviews.at(-1)?.decision === "approved" ? `<button class="button secondary" data-document-withdraw="${esc(version.id)}">Withdraw this version’s approval</button>` : ""}</section>`).join("")}${independent ? `<form id="document-review-form" class="section-space"><h3>Review version ${latest.number}</h3><p class="small">Download and inspect the exact version above. Your decision applies to those bytes. The review history is retained.</p><div class="field"><label for="document-decision">Decision</label><select id="document-decision" name="decision"><option value="approved">Approve</option><option value="rejected">Reject</option><option value="withdrawn">Withdraw approval</option></select></div><div class="field"><label for="document-comment">Review rationale</label><textarea id="document-comment" name="comment" maxlength="2000" required></textarea></div><p class="form-error" role="alert"></p><button class="button primary" type="submit">Record review</button></form>` : writer ? '<p class="small section-space">An independent administrator or operator must review this version. Its uploader and owner cannot approve their own evidence.</p>' : ""}`,
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
          `<form id="document-assign-form"><p>${esc(item.title)}</p><div class="field"><label for="document-new-owner">Owner</label><select id="document-new-owner" name="owner">${data.owners.map((owner) => `<option value="${esc(owner)}"${owner === item.owner ? " selected" : ""}>${esc(owner)}</option>`).join("")}</select></div><p class="small">Ownership changes retain all version and review history.</p><p class="form-error" role="alert"></p><button class="button primary" type="submit">Assign owner</button></form>`,
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
  button.disabled = true;
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
    $("#detail").close();
    await loadDocuments();
    toast("Evidence history saved.");
  } catch (error) {
    form.querySelector('[role="alert"]').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

initialize();
setInterval(() => {
  if (!document.hidden) refresh(false);
}, 5000);
