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

const TABS = [["overview", "Overview"], ["onboard", "Onboard"], ["inventory", "Inventory"], ["approvals", "Approvals"], ["discovery", "Discovery"], ["audit", "Audit"], ["reports", "Reports"]];
render($("#tabs"), html`${TABS.map(([k, v]) => html`<button data-tab="${k}">${v}</button>`)}`);
function show(tab) {
  TABS.forEach(([k]) => { $("#view-" + k).classList.toggle("hide", k !== tab); });
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === tab));
  try { sessionStorage.setItem("cdl_tab", tab); } catch (e) { /* ignore */ }
  if (KEY) ({overview: loadOverview, onboard: loadOnboard, inventory: loadInventory, approvals: loadApprovals, audit: loadAudit, reports: loadReports}[tab] || (() => {}))();
}
document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => show(b.dataset.tab));

$("#connect").onclick = async () => {
  KEY = $("#apikey").value.trim();
  try { sessionStorage.setItem("cdl_key", KEY); } catch (e) { /* ignore */ }
  try { const me = await api("/api/v1/me"); $("#who").textContent = `${me.name} (${me.role})`; }
  catch (e) { $("#who").textContent = "invalid key"; return; }
  show(currentTab());
};
function currentTab() { try { return sessionStorage.getItem("cdl_tab") || "overview"; } catch (e) { return "overview"; } }

const pill = s => html`<span class="pill ${s}">${s}</span>`;
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

// ---------------- audit
async function loadAudit() {
  const [v, rows] = await Promise.all([api("/api/v1/audit/verify"), api("/api/v1/audit?limit=200")]);
  render($("#audit-verify"), v.valid ? html`Hash chain verified over ${v.events} events. Head ${v.head.slice(0, 16)}…` : html`<span class="err">Hash chain broken at event ${v.broken_at}.</span>`);
  render($("#audit"), html`<table><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr>${rows.map(e => html`<tr><td>${e.ts.slice(0, 19).replace("T", " ")}</td><td>${e.actor}</td><td>${e.action}</td><td>${e.target.length > 24 ? e.target.slice(0, 24) + "…" : e.target}</td><td class="muted">${JSON.stringify(e.details).slice(0, 140)}</td></tr>`)}</table>`);
}

// ---------------- reports
async function loadReports() {
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
