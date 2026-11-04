// Certadillo console.
//
// Everything this page shows comes from the API, and much of it comes from outside Certadillo:
// a certificate found by a discovery scan carries whatever subject the scanned server chose.
// So no string is ever treated as markup. HTML is built only with the html`...` tag below, which
// escapes every interpolated value unless it is itself html`...` output, and render() is the only
// function that writes markup into the page. The server sends
// "Content-Security-Policy: require-trusted-types-for 'script'; trusted-types certadillo-console",
// so in browsers that support Trusted Types any other innerHTML assignment throws.

const $ = s => document.querySelector(s);

class SafeHtml {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}
const escText = v => String(v ?? "").replace(/[&<>"'`]/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;"}[c]));
const part = v => v instanceof SafeHtml ? v.s : Array.isArray(v) ? v.map(part).join("") : escText(v);
function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += part(v) + strings[i + 1]; });
  return new SafeHtml(out);
}
const policy = window.trustedTypes ? window.trustedTypes.createPolicy("certadillo-console", {createHTML: s => s}) : null;
function render(el, safe) {
  if (!(safe instanceof SafeHtml)) throw new TypeError("render() only accepts html`...` output");
  el.innerHTML = policy ? policy.createHTML(safe.s) : safe.s;
}

let KEY = "";
try { KEY = sessionStorage.getItem("cdl_key") || ""; } catch (e) { /* storage may be blocked */ }
$("#apikey").value = KEY;

async function api(path, opts = {}) {
  const r = await fetch(path, {...opts, headers: {"X-API-Key": KEY, "Content-Type": "application/json", ...(opts.headers || {})}});
  const text = await r.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  if (!r.ok) {
    const msg = body && body.violations ? body.violations.map(v => `${v.rule}: ${v.message}`).join("\n") : (body.message || body.detail || text);
    throw new Error(msg);
  }
  return body;
}

const TABS = [["overview", "Overview"], ["onboard", "Onboard"], ["inventory", "Inventory"], ["approvals", "Approvals"], ["discovery", "Discovery"],
  ["provisioning", "Provisioning"], ["policy", "Policy"], ["issuers", "Issuers"], ["signing", "Signing"], ["sshkeys", "SSH keys"], ["audit", "Audit"], ["reports", "Reports"]];
render($("#tabs"), html`${TABS.map(([k, v]) => html`<button data-tab="${k}">${v}</button>`)}`);
function show(tab) {
  TABS.forEach(([k]) => { $("#view-" + k).classList.toggle("hide", k !== tab); });
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === tab));
  try { sessionStorage.setItem("cdl_tab", tab); } catch (e) { /* ignore */ }
  const loaders = {overview: loadOverview, onboard: loadOnboard, inventory: loadInventory, approvals: loadApprovals, discovery: loadDiscovery,
    provisioning: loadProvisioning, policy: loadPolicy, issuers: loadIssuers, signing: loadSigning, sshkeys: loadSshKeys, audit: loadAudit, reports: loadReports};
  if (KEY && loaders[tab]) loaders[tab]().catch(e => toast(e.message));
}
document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => show(b.dataset.tab));

$("#connect").onclick = async () => {
  KEY = $("#apikey").value.trim();
  try { sessionStorage.setItem("cdl_key", KEY); } catch (e) { /* ignore */ }
  try {
    const me = await api("/api/v1/me"); $("#who").textContent = `${me.name} (${me.role})`;
    document.body.classList.toggle("ro", !["admin", "operator"].includes(me.role));  // hide changes this role cannot make
    document.body.classList.toggle("noadmin", me.role !== "admin");
  }
  catch (e) { $("#who").textContent = "invalid key"; return; }
  show(currentTab());
};
function currentTab() { try { return sessionStorage.getItem("cdl_tab") || "overview"; } catch (e) { return "overview"; } }

const pill = s => html`<span class="pill ${s}">${s}</span>`;
// a section the current role may not read shows why instead of failing the whole tab
async function part403(el, fn) {
  try { await fn(); } catch (e) { render($(el), html`<span class="muted">${e.message}</span>`); }
}
function toast(msg) { $("#who").textContent = msg.slice(0, 120); }
// shared lookups for the forms
const options = (rows, label, value = r => r.id, first = null) =>
  html`${first ? html`<option value="">${first}</option>` : ""}${rows.map(r => html`<option value="${value(r)}">${label(r)}</option>`)}`;
function parseJson(text, what) {
  if (!text.trim()) return {};
  try { const v = JSON.parse(text); if (v && typeof v === "object" && !Array.isArray(v)) return v; } catch (e) { /* fall through */ }
  throw new Error(`${what} must be a JSON object`);
}
function say(sel, msg, ok = false) { const el = $(sel); el.textContent = msg; el.className = ok ? "okmsg" : "err"; }
function outcome(r, done) { return r && r.approval_id ? `Sent: approval #${r.approval_id} is waiting for an approver.` : done; }
const when = t => t ? t.slice(0, 16).replace("T", " ") : "";
function left(x) { return x.hours_left < 0 ? `${Math.ceil(-x.hours_left / 24)}d ago` : x.hours_left < 48 ? `${x.hours_left}h` : `${x.days_left}d`; }

async function loadOverview() {
  const [s, alerts, exp] = await Promise.all([api("/api/v1/reports/summary"), api("/api/v1/alerts"), api("/api/v1/certificates?status=active&renewal_due=true")]);
  const c = s.certificates, a = s.alerts;
  const mood = s.health === "critical" ? "rolled" : s.health === "warning" ? "worried" : "";
  $("#mascot").src = `/static/dilly${mood ? "-" + mood : ""}.svg`;
  $("#bubble").textContent = s.health === "critical"
    ? `I've rolled up. ${a.critical} critical alert${a.critical === 1 ? "" : "s"} need someone now; start with the list below.`
    : s.health === "warning"
      ? `${a.warning} thing${a.warning === 1 ? "" : "s"} to look at soon. Nothing is broken yet.`
      : `All quiet. ${c.active} active certificates, ${Math.round(s.automation_coverage * 100)}% issued through automation.`;
  const k = [["Active certificates", c.active], ["Renewal overdue (critical)", c.renewal_critical, c.renewal_critical ? "crit" : ""], ["Renewal window open", c.renewal_warning, c.renewal_warning ? "warn" : ""],
    ["Expired, still deployed", c.expired, c.expired ? "crit" : ""], ["Unmanaged (no owner)", c.unmanaged, c.unmanaged ? "warn" : ""],
    ["Critical alerts", a.critical, a.critical ? "crit" : ""], ["Pending approvals", s.pending_approvals], ["Automated issuance", Math.round(s.automation_coverage * 100) + "%"],
    ["SSH certificates", s.ssh_certificates], ["Teams", s.teams]];
  render($("#kpis"), html`${k.map(([l, v, cl]) => html`<div class="kpi ${cl || ""}"><b>${v}</b><span>${l}</span></div>`)}`);
  render($("#alerts"), alerts.length
    ? html`<table><tr><th>Severity</th><th>Alert</th><th>Owner</th></tr>${alerts.slice(0, 25).map(x =>
      html`<tr><td>${pill(x.severity)}</td><td><b>${x.rule}</b><br>${x.summary}</td><td>${x.labels.team || "unowned"}</td></tr>`)}</table>`
    : html`No open alerts.`);
  render($("#expiring"), exp.length
    ? html`<table><tr><th>Name</th><th>Location</th><th class="num">Left</th></tr>${exp.slice(0, 25).map(x =>
      html`<tr><td>${x.common_name}</td><td>${x.location || x.source}</td><td class="num">${left(x)}</td></tr>`)}</table>`
    : html`Nothing is inside its renewal window.`);
}

// ---------------- onboarding wizard
const OB = {team: null, app: null, approval: null, profiles: {}};
function step(n) { [1, 2, 3, 4].forEach(i => $("#ob-" + i).classList.toggle("hide", i !== n)); document.querySelectorAll("#steps span").forEach((s, i) => s.classList.toggle("on", i === n - 1)); $("#ob-err").textContent = ""; }
async function loadOnboard() {
  const [teams, profiles] = await Promise.all([api("/api/v1/teams"), api("/api/v1/profiles")]);
  OB.profiles = profiles;
  render($("#ob-team"), teams.length ? html`${teams.map(t => html`<option value="${t.id}">${t.name} (${t.apps} apps)</option>`)}` : html`<option value="">no teams yet</option>`);
  render($("#a-profile"), html`${Object.entries(profiles).map(([k, v]) => html`<option value="${k}">${k}: ${v.description}</option>`)}`);
  hint(); step(1);
}
function hint() {
  const p = OB.profiles[$("#a-profile").value] || {}; const lim = p.max_validity_hours ? `${p.max_validity_hours}h` : `${p.max_validity_days}d`;
  $("#a-hint").textContent = `Max validity ${lim}.` + (p.dual_control ? " Every issuance needs a second approver." : "") + ($("#a-env").value === "prod" ? " Production onboarding needs a second approver." : "");
}
$("#a-profile").onchange = hint; $("#a-env").onchange = hint;
$("#t-create").onclick = async () => {
  try {
    const t = await api("/api/v1/teams", {method: "POST", body: JSON.stringify({name: $("#t-name").value, contact_email: $("#t-email").value, chat_channel: $("#t-chat").value || null, webhook_url: $("#t-hook").value || null, cost_center: $("#t-cc").value || null})});
    await loadOnboard(); $("#ob-team").value = t.id;
  } catch (e) { $("#ob-err").textContent = e.message; }
};
$("#ob-next1").onclick = () => { OB.team = +$("#ob-team").value; if (OB.team) step(2); else $("#ob-err").textContent = "Pick or create a team first."; };
$("#ob-back2").onclick = () => step(1);
$("#ob-next2").onclick = async () => {
  try {
    const app = await api("/api/v1/apps", {method: "POST", body: JSON.stringify({team_id: OB.team, name: $("#a-name").value.trim(), environment: $("#a-env").value, profile: $("#a-profile").value, data_classification: $("#a-class").value, allowed_domains: $("#a-domains").value.split(/\s+/).filter(Boolean)})});
    OB.app = app; if (app.status === "active") step(4); else { step(3); obStatus(); }
  } catch (e) { $("#ob-err").textContent = e.message; }
};
async function obStatus() {
  const a = await api(`/api/v1/apps/${encodeURIComponent(OB.app.id)}`); OB.app = a;
  if (a.status === "active") return step(4);
  render($("#ob-status"), html`${a.name} is ${pill(a.status)}. Approval #${OB.app.approval_id || ""} must be approved by someone other than ${a.created_by}.`);
}
$("#ob-refresh").onclick = obStatus;
$("#cred-api").onclick = async () => {
  try {
    const c = await api(`/api/v1/apps/${encodeURIComponent(OB.app.id)}/credentials`, {method: "POST"}); const base = location.origin;
    render($("#cred-out"), html`<label>API key (store it in your secrets manager)</label><pre>${c.api_key}</pre>
  <label>CLI: request and auto-renew</label><pre>export CERTADILLO_SERVER=${base} CERTADILLO_API_KEY=${c.api_key}
certadillo cert request --cn app.example --san app.example --out /etc/ssl/app
certadillo cert renew-if-due --dir /etc/ssl/app   # run from a systemd timer</pre>
  <label>EST (devices, appliances)</label><pre>curl --cacert root.pem -u client:${c.api_key} -H 'Content-Type: application/pkcs10' \\
  --data-binary @csr.b64 ${base}/.well-known/est/simpleenroll</pre>`);
  } catch (e) { $("#ob-err").textContent = e.message; }
};
$("#cred-eab").onclick = async () => {
  try {
    const c = await api(`/api/v1/apps/${encodeURIComponent(OB.app.id)}/acme-eab`, {method: "POST"});
    render($("#cred-out"), html`<label>ACME External Account Binding (single use)</label><pre>kid:  ${c.kid}\nhmac: ${c.hmac_key}</pre><label>certbot</label><pre>${c.example}</pre>
  <label>cert-manager ClusterIssuer</label><pre>spec:
  acme:
    server: ${location.origin}/acme/directory
    externalAccountBinding:
      keyID: ${c.kid}
      keySecretRef: {name: certadillo-eab, key: secret}
    privateKeySecretRef: {name: certadillo-acme-account}
    solvers: [{http01: {ingress: {}}}]</pre>`);
  } catch (e) { $("#ob-err").textContent = e.message; }
};

// ---------------- inventory
let INV = [];
async function loadInventory() { INV = await api("/api/v1/certificates?limit=5000"); renderInv(); }
function renderInv() {
  const st = $("#f-status").value, so = $("#f-source").value, q = $("#f-q").value.toLowerCase();
  const rows = INV.filter(x => (!st || x.status === st) && (!so || x.source === so) && (!q || [x.common_name, x.serial, x.location, (x.sans || []).join(" ")].join(" ").toLowerCase().includes(q)));
  render($("#inv"), html`<p class="muted">${rows.length} of ${INV.length}</p><table><tr><th>Name</th><th>Status</th><th>Source</th><th>Key</th><th>Profile</th><th>Location</th><th class="num">Expires</th><th></th></tr>${rows.map(x =>
    html`<tr><td>${x.common_name}<br><span class="muted">${x.serial.slice(0, 16)}…</span></td><td>${pill(x.status)}</td><td>${x.source}${x.protocol ? " / " + x.protocol : ""}</td><td>${x.key}</td><td>${x.profile || ""}</td><td>${x.location || ""}</td><td class="num">${left(x)}</td>
    <td>${x.status === "active" && x.source === "issued" ? html`<button data-revoke="${x.id}">Revoke</button>` : ""}</td></tr>`)}</table>`);
  document.querySelectorAll("[data-revoke]").forEach(b => b.onclick = async () => {
    const reason = prompt("Reason (key_compromise, superseded, cessation_of_operation, affiliation_changed)", "superseded"); if (!reason) return;
    const change = prompt("Change ticket (required for prod unless key_compromise)", "") || null;
    try { await api(`/api/v1/certificates/${encodeURIComponent(b.dataset.revoke)}/revoke`, {method: "POST", body: JSON.stringify({reason, change_ref: change})}); loadInventory(); } catch (e) { alert(e.message); }
  });
}
["#f-status", "#f-source"].forEach(s => $(s).onchange = renderInv); $("#f-q").oninput = renderInv;

// ---------------- approvals
async function loadApprovals() {
  const rows = await api("/api/v1/approvals");
  render($("#appr"), rows.length
    ? html`<table><tr><th>#</th><th>Action</th><th>Details</th><th>Requested by</th><th>Status</th><th></th></tr>${rows.map(r =>
      html`<tr><td>${r.id}</td><td>${r.action}</td><td><pre>${JSON.stringify(r.payload)}</pre></td><td>${r.requested_by}</td><td>${pill(r.status)}${r.decided_by ? html`<br>by ${r.decided_by}` : ""}</td>
    <td>${r.status === "pending" ? html`<button class="primary" data-ok="${r.id}">Approve</button> <button data-no="${r.id}">Reject</button>` : ""}</td></tr>`)}</table>`
    : html`No approval requests.`);
  document.querySelectorAll("[data-ok],[data-no]").forEach(b => b.onclick = async () => {
    const id = b.dataset.ok || b.dataset.no, verb = b.dataset.ok ? "approve" : "reject";
    try { await api(`/api/v1/approvals/${encodeURIComponent(id)}/${verb}`, {method: "POST", body: JSON.stringify({comment: null})}); loadApprovals(); } catch (e) { alert(e.message); }
  });
}

// ---------------- discovery
$("#d-run").onclick = async () => {
  $("#d-out").textContent = "Scanning…";
  try {
    const r = await api("/api/v1/discovery/scan", {method: "POST", body: JSON.stringify({targets: $("#d-targets").value.split(/\s+/).filter(Boolean)})});
    render($("#d-out"), html`<table><tr><th>Target</th><th>Result</th><th>Findings</th></tr>${r.map(x => html`<tr><td>${x.target}</td><td>${x.error
      ? html`<span class="muted">${x.error}</span>`
      : html`${x.common_name} ${x.new ? pill("new") : ""}<br><span class="muted">expires ${x.not_after.slice(0, 10)}</span>`}</td><td>${(x.findings || []).map(f => html`${pill(f.rule)} `)}</td></tr>`)}</table>`);
  } catch (e) { render($("#d-out"), html`<p class="err">${e.message}</p>`); }
};

async function loadDiscovery() {
  await Promise.all([part403("#findings", loadFindings), part403("#sources", loadSources)]);
}
async function loadFindings() {
  const kind = $("#fd-kind").value;
  const rows = await api("/api/v1/discovery/findings" + (kind ? `?kind=${encodeURIComponent(kind)}` : ""));
  const label = f => {
    const d = f.detail || {};
    if (f.kind.startsWith("ssh_")) return html`${d.key_type || ""} ${d.bits || ""} ${d.comment ? html`<span class="muted">${d.comment}</span>` : ""}<br><code>${d.fingerprint || ""}</code>`;
    if (f.kind === "unknown_public_cert") return html`${(d.dns_names || []).join(", ")}<br><span class="muted">${d.issuer || ""}</span>`;
    if (f.kind === "untracked_certificate") return html`${d.name}<br><span class="muted">apps: ${(d.applications || []).join(", ") || "none linked"}</span>`;
    return html`mode ${d.mode || ""} owner ${d.owner || ""}`;
  };
  render($("#findings"), rows.length
    ? html`<table><tr><th>Kind</th><th>Where</th><th>What</th><th>Since</th><th></th></tr>${rows.map(f =>
      html`<tr><td>${pill(f.kind)}</td><td>${f.location}</td><td>${label(f)}</td><td>${when(f.first_seen)}</td><td><button class="act" data-ack="${f.id}">Acknowledge</button></td></tr>`)}</table>`
    : html`No open findings.`);
  document.querySelectorAll("[data-ack]").forEach(b => b.onclick = async () => {
    const comment = prompt("Why is this expected? (recorded in the audit trail)"); if (!comment) return;
    try { await api(`/api/v1/discovery/findings/${encodeURIComponent(b.dataset.ack)}/acknowledge`, {method: "POST", body: JSON.stringify({comment})}); loadFindings(); } catch (e) { alert(e.message); }
  });
}
$("#fd-kind").onchange = () => loadFindings().catch(e => toast(e.message));
async function loadSources() {
  const rows = await api("/api/v1/discovery/sources");
  render($("#sources"), rows.length
    ? html`<table><tr><th>Source</th><th>Type</th><th>Last run</th><th>Result</th><th></th></tr>${rows.map(r => {
      const last = r.last_run || {};
      return html`<tr><td>${r.name}</td><td>${r.type}</td><td>${when(last.started_at)}</td><td>${last.status ? pill(last.status) : ""} ${last.found != null ? html`<span class="muted">${last.found} found, ${last.new} new</span>` : ""}${last.error ? html`<br><span class="err">${last.error}</span>` : ""}</td>
      <td><button class="act" data-src="${r.name}">Run now</button></td></tr>`;
    })}</table>`
    : html`No scheduled sources configured (AWS ACM, Azure Key Vault, GCP Certificate Manager, Certificate Transparency).`);
  document.querySelectorAll("[data-src]").forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { await api(`/api/v1/discovery/sources/${encodeURIComponent(b.dataset.src)}/run`, {method: "POST"}); } catch (e) { alert(e.message); }
    loadSources();
  });
}

// ---------------- provisioning
let TARGETS = {};
const TARGET_TEMPLATES = {
  ssh: {host: "web1.pay.bank.internal", username: "certadillo", host_key: "ssh-ed25519 AAAA... (from ssh-keyscan, not a first connection)", allowed_dirs: ["/etc/nginx/tls"], reload_command: "sudo systemctl reload nginx"},
  kubernetes: {api_server: "https://aks-prod.bank.internal:443", namespaces: ["payments"], ca_cert: "-----BEGIN CERTIFICATE-----..."},
  f5: {host: "https://bigip-dc1.bank.internal", username: "certadillo", partition: "Payments"},
  "aws-acm": {region: "us-east-1"},
};
async function loadProvisioningForms() {
  const [apps, teams, kinds] = await Promise.all([api("/api/v1/apps").catch(() => []), api("/api/v1/teams").catch(() => []), api("/api/v1/provisioning/kinds")]);
  render($("#in-app"), options(apps, a => a.name));
  render($("#in-target"), options(Object.values(TARGETS), t => `${t.name} (${t.kind})`));
  render($("#tg-team"), options(teams, t => t.name));
  render($("#tg-kind"), options(kinds, k => k, k => k));
  if (!$("#tg-config").value) $("#tg-config").value = JSON.stringify(TARGET_TEMPLATES[kinds[0]] || {}, null, 2);
}
$("#tg-kind").onchange = () => { $("#tg-config").value = JSON.stringify(TARGET_TEMPLATES[$("#tg-kind").value] || {}, null, 2); };
$("#tg-save").onclick = async () => {
  say("#tg-err", "");
  try {
    await api("/api/v1/targets", {method: "POST", body: JSON.stringify({name: $("#tg-name").value.trim(), kind: $("#tg-kind").value,
      team_id: +$("#tg-team").value, config: parseJson($("#tg-config").value, "Configuration"), credential_ref: $("#tg-cred").value.trim() || null})});
    say("#tg-err", "Target added.", true); loadProvisioning();
  } catch (e) { say("#tg-err", e.message); }
};
$("#in-save").onclick = async () => {
  say("#in-err", "");
  try {
    await api("/api/v1/installations", {method: "POST", body: JSON.stringify({app_id: +$("#in-app").value, target_id: +$("#in-target").value,
      common_name: $("#in-cn").value.trim(), sans: $("#in-sans").value.split(/\s+/).filter(Boolean), key_type: $("#in-key").value,
      key_location: $("#in-loc").value, params: parseJson($("#in-params").value, "Placement"), validate_endpoint: $("#in-check").value.trim() || null,
      auto_renew: $("#in-auto").value === "true"})});
    say("#in-err", "Installation added. Push it now from the list.", true); loadProvisioning();
  } catch (e) { say("#in-err", e.message); }
};
async function loadProvisioning() {
  await part403("#targets", async () => {
    const t = await api("/api/v1/targets"); TARGETS = Object.fromEntries(t.map(x => [x.id, x]));
    render($("#targets"), t.length
      ? html`<table><tr><th>Name</th><th>Kind</th><th>Where</th><th>Credential</th><th>Status</th></tr>${t.map(x =>
        html`<tr><td>${x.name}</td><td>${x.kind}</td><td>${x.config.host || x.config.api_server || x.config.region || ""}${x.config.allowed_dirs ? html`<br><span class="muted">${x.config.allowed_dirs.join(", ")}</span>` : ""}</td><td>${x.credential || "none"}</td><td>${pill(x.status)}</td></tr>`)}</table>`
      : html`No push targets yet. An admin adds them with POST /api/v1/targets.`);
  });
  await part403("#installs", async () => {
    const rows = await api("/api/v1/installations");
    render($("#installs"), rows.length
      ? html`<table><tr><th>Name</th><th>Target</th><th>Key</th><th>Status</th><th>Next renewal check</th><th></th></tr>${rows.map(i =>
        html`<tr><td>${i.common_name}${i.validate_endpoint ? html`<br><span class="muted">checks ${i.validate_endpoint}</span>` : ""}</td><td>${(TARGETS[i.target_id] || {}).name || i.target_id}</td><td>${i.key_type}<br><span class="muted">${i.key_location}</span></td>
        <td>${pill(i.status)}${i.failures ? html`<br><span class="err">${i.failures} failure(s): ${i.last_error || ""}</span>` : ""}</td><td>${when(i.next_attempt_at)}</td>
        <td><button data-runs="${i.id}">Runs</button> <button class="primary act" data-push="${i.id}">Push now</button></td></tr>`)}</table>`
      : html`No installations yet.`);
    document.querySelectorAll("[data-runs]").forEach(b => b.onclick = () => showRuns(b.dataset.runs));
    if (!document.body.classList.contains("ro")) loadProvisioningForms().catch(e => { $("#in-err").textContent = e.message; });
    document.querySelectorAll("[data-push]").forEach(b => b.onclick = async () => {
      b.disabled = true; b.textContent = "Pushing…";
      try { await api(`/api/v1/installations/${encodeURIComponent(b.dataset.push)}/provision`, {method: "POST"}); } catch (e) { /* the run detail shows why */ }
      await showRuns(b.dataset.push); loadProvisioning();
    });
  });
}
async function showRuns(id) {
  const i = await api(`/api/v1/installations/${encodeURIComponent(id)}`);
  const r = (i.runs || [])[0];
  render($("#run-detail"), r
    ? html`<p><b>${i.common_name}</b> run #${r.id} ${pill(r.status)} by ${r.actor} at ${when(r.started_at)}</p><ol class="steps-list">${(r.steps || []).map(st => html`<li>${st}</li>`)}</ol>${r.error ? html`<p class="err">${r.error}</p>` : ""}`
    : html`No runs yet for ${i.common_name}.`);
}

// ---------------- policy tree
let FOLDERS = [], SETTINGS = {}, EDITING = null;
const SETTING_KIND = {allowed_profiles: "list", allowed_zones: "list", ec_curves: "list", rsa_min_bits: "int",
  max_validity_days: "int", dual_control: "bool", issuing_ca: "text", issuer: "text"};
function ruleRow(key = "", value = "", locked = false) {
  return html`<tr><td><select class="fe-key">${Object.keys(SETTINGS).map(k => html`<option value="${k}" ${k === key ? html`selected` : ""}>${k}</option>`)}</select></td>
    <td><input class="fe-val" value="${Array.isArray(value) ? value.join(", ") : value}" placeholder="value; lists comma separated"></td>
    <td><label class="inline"><input type="checkbox" class="fe-lock" ${locked ? html`checked` : ""}> locked</label></td>
    <td><button class="fe-del">Remove</button></td></tr>`;
}
function drawRules(rules) {
  render($("#fe-rules"), html`<tr><th>Rule</th><th>Value</th><th></th><th></th></tr>${rules.map(([k, v]) => ruleRow(k, v.value, v.locked))}`);
  wireRules();
}
function wireRules() {
  document.querySelectorAll(".fe-del").forEach(b => b.onclick = () => { b.closest("tr").remove(); });
  document.querySelectorAll(".fe-key").forEach(sel => sel.title = SETTINGS[sel.value] || "");
}
function readRules() {
  const out = {};
  document.querySelectorAll("#fe-rules tr").forEach(tr => {
    const key = tr.querySelector(".fe-key"); if (!key) return;
    const raw = tr.querySelector(".fe-val").value.trim(), kind = SETTING_KIND[key.value] || "text";
    if (!raw) throw new Error(`${key.value} needs a value`);
    const value = kind === "list" ? raw.split(/[\s,]+/).filter(Boolean) : kind === "int" ? Number(raw) : kind === "bool" ? ["true", "yes", "1"].includes(raw.toLowerCase()) : raw;
    if (kind === "int" && !Number.isInteger(value)) throw new Error(`${key.value} must be a whole number`);
    out[key.value] = {value, locked: tr.querySelector(".fe-lock").checked};
  });
  return out;
}
function editFolder(f) {
  EDITING = f;
  $("#fe-title").textContent = f ? `Edit rules of ${f.path}` : "New folder";
  $("#fe-name").value = f ? f.name : ""; $("#fe-name").disabled = !!f; $("#fe-parent").disabled = !!f;
  drawRules(f ? Object.entries(f.settings || {}) : []);
  $("#fe-err").textContent = "";
  if (f) { $("#fe-card").open = true; $("#fe-card").scrollIntoView({behavior: "smooth"}); }
}
$("#fe-add").onclick = () => {
  // keep what is typed so far, unvalidated, and append an empty rule
  const cur = [...document.querySelectorAll("#fe-rules tr")].filter(tr => tr.querySelector(".fe-key")).map(tr =>
    [tr.querySelector(".fe-key").value, {value: tr.querySelector(".fe-val").value, locked: tr.querySelector(".fe-lock").checked}]);
  const used = new Set(cur.map(([k]) => k));
  drawRules([...cur, [Object.keys(SETTINGS).find(k => !used.has(k)) || Object.keys(SETTINGS)[0], {value: "", locked: false}]]);
};
$("#fe-reset").onclick = () => editFolder(null);
$("#fe-save").onclick = async () => {
  say("#fe-err", "");
  try {
    const settings = readRules();
    const r = EDITING
      ? await api(`/api/v1/folders/${encodeURIComponent(EDITING.id)}/settings`, {method: "PUT", body: JSON.stringify({settings})})
      : await api("/api/v1/folders", {method: "POST", body: JSON.stringify({name: $("#fe-name").value.trim(), parent_id: $("#fe-parent").value ? +$("#fe-parent").value : null, settings})});
    say("#fe-err", outcome(r, "Applied."), true); loadPolicy();
  } catch (e) { say("#fe-err", e.message); }
};
$("#mv-go").onclick = async () => {
  say("#mv-err", "");
  try {
    const r = await api(`/api/v1/apps/${encodeURIComponent($("#pol-app").value)}/move`, {method: "POST", body: JSON.stringify({folder_id: $("#mv-folder").value ? +$("#mv-folder").value : null})});
    say("#mv-err", outcome(r, "Moved."), true); loadPolicy();
  } catch (e) { say("#mv-err", e.message); }
};
async function loadPolicy() {
  SETTINGS = await api("/api/v1/folders/settings").catch(() => ({}));
  await part403("#tree", async () => {
    const fs = await api("/api/v1/folders"); FOLDERS = fs;
    render($("#fe-parent"), options(fs, f => f.path, f => f.id, "(top level)"));
    render($("#mv-folder"), options(fs, f => f.path, f => f.id, "(no folder: profile rules only)"));
    if (!EDITING) drawRules([]);
    const kids = id => fs.filter(f => f.parent_id === id);
    const fmt = v => Array.isArray(v) ? v.join(", ") : String(v);
    const node = f => html`<li><b>${f.name}</b> <span class="muted">${f.apps} app${f.apps === 1 ? "" : "s"}</span> <button class="adm small" data-edit="${f.id}">Edit rules</button>
      <div class="rules">${Object.entries(f.settings || {}).map(([k, v]) => html`<span class="rule ${v.locked ? "locked" : ""}" title="${v.locked ? "cannot be changed below this folder" : "set here"}">${k}: ${fmt(v.value)}</span>`)}</div>
      ${kids(f.id).length ? html`<ul class="tree">${kids(f.id).map(node)}</ul>` : ""}</li>`;
    render($("#tree"), fs.length ? html`<ul class="tree">${kids(null).map(node)}</ul>` : html`No folders yet. Apps use their profile's rules only.`);
    document.querySelectorAll("[data-edit]").forEach(b => b.onclick = () => editFolder(FOLDERS.find(f => f.id === +b.dataset.edit)));
  });
  await part403("#pol-out", async () => {
    const apps = await api("/api/v1/apps"), keep = $("#pol-app").value;
    render($("#pol-app"), html`<option value="">pick an app</option>${apps.map(a => html`<option value="${a.id}">${a.name}</option>`)}`);
    if (keep) { $("#pol-app").value = keep; $("#pol-app").onchange(); }
  });
}
$("#pol-app").onchange = async () => {
  const id = $("#pol-app").value; if (!id) return;
  try {
    const r = await api(`/api/v1/apps/${encodeURIComponent(id)}/policy`);
    const fr = Object.entries(r.folder_rules || {});
    render($("#pol-out"), html`<p>${r.app} uses profile <b>${r.profile}</b>${r.folder && r.folder !== "\\" ? html` in <b>${r.folder}</b>` : " and sits in no policy folder"}.</p>
      ${fr.length ? html`<table><tr><th>Rule</th><th>Value</th><th>Set at</th><th>Locked</th></tr>${fr.map(([k, v]) => html`<tr><td>${k}</td><td>${Array.isArray(v.value) ? v.value.join(", ") : String(v.value)}</td><td>${v.folder}</td><td>${v.locked ? "yes" : ""}</td></tr>`)}</table>` : html`<p class="muted">No folder rules; the profile alone applies.</p>`}`);
  } catch (e) { render($("#pol-out"), html`<p class="err">${e.message}</p>`); }
};

// ---------------- code signing
$("#sg-save").onclick = async () => {
  say("#sg-err", "");
  try {
    const r = await api("/api/v1/signing/keys", {method: "POST", body: JSON.stringify({name: $("#sg-name").value.trim(), app_id: +$("#sg-app").value,
      purpose: $("#sg-purpose").value, alg: $("#sg-alg").value})});
    say("#sg-err", outcome(r, "Created."), true); loadSigning();
  } catch (e) { say("#sg-err", e.message); }
};
async function loadSigning() {
  $("#tsa-url").textContent = location.origin + "/tsa";
  if (!document.body.classList.contains("ro")) api("/api/v1/apps").then(apps => render($("#sg-app"), options(apps, a => a.name))).catch(() => {});
  await part403("#sign-keys", async () => {
    const keys = await api("/api/v1/signing/keys");
    render($("#sign-keys"), keys.length
      ? html`<table><tr><th>Key</th><th>App</th><th>Purpose</th><th>Held in</th><th>Certificate until</th><th>Status</th></tr>${keys.map(k =>
        html`<tr><td>${k.name}</td><td>${k.app}</td><td>${k.purpose === "release" ? html`release <span class="muted">(approver per signature)</span>` : "test"}</td><td>${k.signer}</td><td>${(k.not_after || "").slice(0, 10)}</td><td>${pill(k.status)}</td></tr>`)}</table>`
      : html`No signing keys yet. Ask for one with POST /api/v1/signing/keys; an approver decides.`);
  });
  await part403("#sign-reqs", async () => {
    const rows = await api("/api/v1/signing/requests");
    render($("#sign-reqs"), rows.length
      ? html`<table><tr><th>#</th><th>Artifact</th><th>Key</th><th>Requested by</th><th>Digest</th><th>Status</th></tr>${rows.map(r =>
        html`<tr><td>${r.id}</td><td>${r.artifact.name}${r.artifact.version ? html` <span class="muted">${r.artifact.version}</span>` : ""}</td><td>${r.key}</td><td>${r.requested_by}<br><span class="muted">${when(r.created_at)}</span></td>
        <td><code>${r.digest_alg}:${r.digest.slice(0, 16)}…</code></td><td>${pill(r.status)}${r.status === "pending" && r.approval_id ? html`<br><span class="muted">approval #${r.approval_id}</span>` : ""}</td></tr>`)}</table>`
      : html`No signing requests yet.`);
  });
}

// ---------------- issuers
async function loadIssuers() {
  const rows = await api("/api/v1/issuers");
  const kv = obj => Object.entries(obj || {}).filter(([k]) => k !== "cas").map(([k, v]) =>
    html`<tr><td class="muted">${k}</td><td>${typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}</td></tr>`);
  render($("#issuers"), html`<div class="issuers">${rows.map(i => html`<div class="issuer">
    <h3>${i.name} ${pill(i.type)}</h3>
    <div class="kpis small"><div class="kpi"><b>${i.active}</b><span>active certificates</span></div><div class="kpi"><b>${i.issued}</b><span>issued in total</span></div><div class="kpi"><b>${i.last_issued ? i.last_issued.slice(0, 10) : "never"}</b><span>last issued</span></div></div>
    <p><span class="muted">Profiles:</span> ${i.profiles.length ? i.profiles.map(x => html`<span class="rule">${x}</span> `) : html`<span class="muted">none</span>`}
    <br><span class="muted">Policy folders:</span> ${i.folders.length ? i.folders.map(x => html`<span class="rule">${x}</span> `) : html`<span class="muted">none</span>`}</p>
    ${i.type === "local" ? html`<table><tr><th>CA</th><th>Role</th><th>Key</th><th>Expires</th></tr>${i.config.cas.map(c => html`<tr><td>${c.name}${c.name === i.config.default_issuing_ca ? html` ${pill("default")}` : ""}</td><td>${c.root ? "root" : "issuing"}</td><td>${c.signer === "offline" ? pill("offline") : c.signer}</td><td>${c.not_after.slice(0, 10)}</td></tr>`)}</table>`
      : html`<table>${kv(i.config)}${Object.entries(i.credentials).map(([k, v]) => html`<tr><td class="muted">${k}</td><td>${v}</td></tr>`)}</table>`}
  </div>`)}</div>`);
}

// ---------------- SSH keys
let SSH = [];
async function loadSshKeys() {
  const f = $("#sk-filter").value;
  SSH = await api("/api/v1/ssh-keys" + (f === "none" ? "?owner=none" : f === "removed" ? "?status=removed" : ""));
  renderSsh();
}
function renderSsh() {
  const q = $("#sk-q").value.toLowerCase();
  const rows = SSH.filter(k => !q || [k.host, k.account, k.comment, k.fingerprint, k.owner].join(" ").toLowerCase().includes(q));
  render($("#sshkeys"), html`<p class="muted">${rows.length} of ${SSH.length}</p><table><tr><th>Host</th><th>Account</th><th>Key</th><th>Restrictions</th><th>Last change</th><th>Owner</th><th></th></tr>${rows.map(k =>
    html`<tr><td>${k.host}<br><span class="muted">${k.kind}</span></td><td>${k.account || "(host key)"}${k.account_exists ? "" : html` ${pill("orphaned")}`}</td>
    <td>${k.key_type} ${k.bits || ""}<br><code>${k.fingerprint}</code>${k.comment ? html`<br><span class="muted">${k.comment}</span>` : ""}</td>
    <td>${Object.keys(k.options || {}).length ? Object.entries(k.options).map(([n, v]) => html`<span class="rule">${v === true ? n : n + "=" + v}</span> `) : html`<span class="muted">none</span>`}</td>
    <td>${(k.file_mtime || "").slice(0, 10)}</td><td>${k.owner || html`<span class="muted">unclaimed</span>`}</td>
    <td>${k.status === "present" ? html`<button class="act" data-own="${k.id}">Set owner</button>` : pill(k.status)}</td></tr>`)}</table>`);
  document.querySelectorAll("[data-own]").forEach(b => b.onclick = async () => {
    const owner = prompt("Team or person responsible for this key (applies everywhere it appears)"); if (!owner) return;
    const note = prompt("Note or change ticket (optional)") || null;
    try { await api(`/api/v1/ssh-keys/${encodeURIComponent(b.dataset.own)}/owner`, {method: "PUT", body: JSON.stringify({owner, note})}); loadSshKeys(); } catch (e) { alert(e.message); }
  });
}
$("#sk-filter").onchange = () => loadSshKeys().catch(e => toast(e.message)); $("#sk-q").oninput = renderSsh;

// ---------------- audit
async function loadAudit() {
  part403("#audit-ship", async () => {
    const [ship, key] = await Promise.all([api("/api/v1/audit/shipping"), api("/api/v1/audit/signing-key").catch(() => null)]);
    render($("#audit-ship"), html`${ship.length
      ? html`<table><tr><th>Sink</th><th class="num">Behind</th><th>Oldest unsent</th><th>Failures</th><th>Last error</th></tr>${ship.map(r => html`<tr><td>${r.sink}</td><td class="num">${r.behind}</td><td>${when(r.oldest_unsent)}</td><td>${r.failures ? pill("critical") : pill("ok")} ${r.failures || ""}</td><td class="muted">${r.last_error || ""}</td></tr>`)}</table>`
      : html`<p>No sinks configured. Set CERTADILLO_AUDIT_SHIP to send every event, signed, to a SIEM or an S3 Object Lock bucket.</p>`}
      ${key ? html`<p class="muted">Receivers verify records with the Ed25519 key <code>${key.key_id}</code>.</p>` : ""}`);
  });
  const [v, rows] = await Promise.all([api("/api/v1/audit/verify"), api("/api/v1/audit?limit=200")]);
  render($("#audit-verify"), v.valid ? html`Hash chain verified over ${v.events} events. Head ${v.head.slice(0, 16)}…` : html`<span class="err">Hash chain broken at event ${v.broken_at}.</span>`);
  render($("#audit"), html`<table><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr>${rows.map(e => html`<tr><td>${e.ts.slice(0, 19).replace("T", " ")}</td><td>${e.actor}</td><td>${e.action}</td><td>${e.target.length > 24 ? e.target.slice(0, 24) + "…" : e.target}</td><td class="muted">${JSON.stringify(e.details).slice(0, 140)}</td></tr>`)}</table>`);
}

// ---------------- reports
async function loadReports() {
  part403("#cas", async () => {
    const [cas, keys] = await Promise.all([api("/api/v1/cas"), api("/api/v1/cas/keys").catch(() => [])]);
    const health = Object.fromEntries(keys.map(k => [k.ca, k]));
    render($("#cas"), html`<table><tr><th>CA</th><th>Role</th><th>Key</th><th>Health</th><th>Expires</th><th class="num">CRL #</th></tr>${cas.map(c => {
      const h = health[c.name];
      return html`<tr><td>${c.name}<br><span class="muted">${c.subject}</span></td><td>${c.root ? "root" : "issuing"}</td><td>${c.signer === "offline" ? html`${pill("offline")} <span class="muted">signed at the ceremony</span>` : c.signer}</td>
      <td>${h ? (h.ok ? pill("ok") : html`${pill("critical")} <span class="err">${h.problems.join("; ")}</span>`) : ""}</td><td>${c.not_after.slice(0, 10)}</td><td class="num">${c.crl_number}</td></tr>`;
    })}</table>`);
  });
  const r = await api("/api/v1/reports/crypto");
  render($("#crypto"), html`<div class="kpis"><div class="kpi"><b>${r.active_certificates}</b><span>Active certificates</span></div><div class="kpi warn"><b>${r.quantum_vulnerable}</b><span>RSA/ECC (quantum-vulnerable)</span></div><div class="kpi"><b>${r.pqc_signed}</b><span>PQC-signed</span></div><div class="kpi"><b>${r.valid_past_2030_deprecation}</b><span>Valid past 2030</span></div></div>
  <table><tr><th>CA</th><th>Algorithm</th><th>Key custody</th><th>Expires</th><th>Outlives 2035 cutoff</th></tr>${r.certificate_authorities.map(c => html`<tr><td>${c.ca}</td><td>${c.algorithm}</td><td>${c.signer}</td><td>${c.not_after.slice(0, 10)}</td><td>${c.outlives_2035_cutoff ? pill("warning") : pill("ok")}</td></tr>`)}</table>
  <h2 class="recs-title">Recommendations</h2><ul>${r.recommendations.map(x => html`<li>${x}</li>`)}</ul>`);
}
document.querySelectorAll("[data-dl]").forEach(b => b.onclick = async () => {
  const r = await fetch(b.dataset.dl, {headers: {"X-API-Key": KEY}}); const blob = await r.blob();
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = b.dataset.name; a.click();
});

show(currentTab());
if (KEY) $("#connect").click();
