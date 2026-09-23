/* Knowledge base shell: hash routing (#slug), nav, search, copy buttons, scene mounting. */
(function () {
  "use strict";
  var pages = window.KB_PAGES || [];
  var bySlug = {};
  pages.forEach(function (p, i) { p.index = i; bySlug[p.slug] = p; });
  var nav = document.getElementById("kb-nav");
  var main = document.getElementById("kb-main");
  var current = null;
  var sceneView = null;

  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  // ------------------------------------------------------------ nav
  var groups = [];
  pages.forEach(function (p) {
    if (p.hidden) return;
    var g = groups.filter(function (x) { return x.name === p.group; })[0];
    if (!g) { g = { name: p.group, items: [] }; groups.push(g); }
    g.items.push(p);
  });
  nav.innerHTML = groups.map(function (g) {
    return "<h3>" + esc(g.name) + "</h3>" + g.items.map(function (p) {
      return '<a href="#' + p.slug + '" data-slug="' + p.slug + '">' + esc(p.nav || p.title) + (p.scene ? '<span class="tag">3D</span>' : "") + "</a>";
    }).join("");
  }).join("");

  // ------------------------------------------------------------ render
  function render(slug, anchor) {
    var p = bySlug[slug] || pages[0];
    if (sceneView && sceneView.dispose) { sceneView.dispose(); sceneView = null; }
    current = p;
    document.title = (p.slug === "home" ? "" : p.title + " · ") + "Certadillo knowledge base";
    var html = "";
    if (p.slug === "home") html = p.html;
    else {
      html = '<article class="kb-page">';
      if (p.scene) {
        html += '<div class="kb-prose"><div class="kb-eyebrow">' + esc(p.group) + "</div>" + p.pre + "</div>";
        html += '<div class="kb-scene-wrap"><div class="kb-scene" data-scene="' + p.scene + '"></div>' +
          '<div class="kb-legend"><span><i style="background:#14b8a6"></i>request</span><span><i style="background:#f2b233"></i>response</span>' +
          '<span><i style="background:#8b5cf6"></i>encrypted or secret</span><span><i style="background:#e5484d"></i>rejected or alert</span>' +
          '<span><i style="background:#3b82f6"></i>local step</span><span><i style="background:linear-gradient(#2dd4bf,#f2b233)"></i>audit chain block</span></div></div>';
        html += '<div class="kb-prose">' + p.post + "</div>";
      } else {
        html += '<div class="kb-prose"><div class="kb-eyebrow">' + esc(p.group) + "</div>" + p.html + "</div>";
      }
      var prev = pages[p.index - 1], next = pages[p.index + 1];
      while (prev && prev.hidden) prev = pages[prev.index - 1];
      while (next && next.hidden) next = pages[next.index + 1];
      html += '<nav class="kb-pager" aria-label="Previous and next">' +
        (prev ? '<a href="#' + prev.slug + '"><small>Previous</small>' + esc(prev.nav || prev.title) + "</a>" : "<span></span>") +
        (next ? '<a href="#' + next.slug + '" style="text-align:right"><small>Next</small>' + esc(next.nav || next.title) + "</a>" : "<span></span>") + "</nav>";
      html += "</article>";
    }
    main.innerHTML = html;
    enhance(main);
    var holder = main.querySelector(".kb-scene");
    if (holder && window.CertadilloScenes) sceneView = window.CertadilloScenes.mount(holder, holder.getAttribute("data-scene"));
    nav.querySelectorAll("a").forEach(function (a) { a.classList.toggle("on", a.getAttribute("data-slug") === p.slug); });
    nav.classList.remove("open");
    if (anchor) {
      var t = document.getElementById(anchor);
      if (t) { t.scrollIntoView(); return; }
    }
    window.scrollTo(0, 0);
    try { sessionStorage.setItem("kb-last", p.slug); } catch (e) { /* storage may be blocked */ }
  }

  function enhance(root) {
    root.querySelectorAll(".kb-prose table").forEach(function (t) {
      if (t.parentElement.classList.contains("kb-table")) return;
      var w = document.createElement("div"); w.className = "kb-table"; t.parentNode.insertBefore(w, t); w.appendChild(t);
    });
    root.querySelectorAll(".kb-prose pre").forEach(function (pre) {
      var b = document.createElement("button"); b.type = "button"; b.className = "kb-copy"; b.textContent = "Copy";
      b.addEventListener("click", function () {
        var text = pre.querySelector("code") ? pre.querySelector("code").innerText : pre.innerText;
        var done = function () { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1400); };
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { select(pre); });
        else select(pre);
      });
      pre.appendChild(b);
    });
    root.querySelectorAll("a[data-anchor]").forEach(function (a) {
      a.addEventListener("click", function (e) {
        var slug = a.getAttribute("href").slice(1), anchor = a.getAttribute("data-anchor");
        if (current && slug === current.slug) { e.preventDefault(); var t = document.getElementById(anchor); if (t) t.scrollIntoView({ behavior: "smooth" }); }
        else { pendingAnchor = anchor; }
      });
    });
  }
  function select(el) { var r = document.createRange(); r.selectNodeContents(el); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); }

  var pendingAnchor = null;
  function route() {
    var slug = (location.hash || "").replace(/^#/, "");
    if (!slug) { try { slug = sessionStorage.getItem("kb-last") || "home"; } catch (e) { slug = "home"; } }
    var a = pendingAnchor; pendingAnchor = null;
    render(slug, a);
  }
  window.addEventListener("hashchange", route);

  // ------------------------------------------------------------ search
  var input = document.getElementById("kb-q");
  var results = document.getElementById("kb-results");
  var index = pages.filter(function (p) { return !p.hidden; }).map(function (p) {
    var div = document.createElement("div"); div.innerHTML = p.html;
    return { p: p, text: (p.title + " " + div.textContent).toLowerCase() };
  });
  function search(q) {
    q = q.trim().toLowerCase();
    if (q.length < 2) { results.hidden = true; return; }
    var words = q.split(/\s+/);
    var hits = index.map(function (e) {
      var score = 0;
      words.forEach(function (w) { var n = e.text.split(w).length - 1; score += n + (e.p.title.toLowerCase().indexOf(w) >= 0 ? 20 : 0); if (!n) score -= 1000; });
      return { e: e, score: score };
    }).filter(function (h) { return h.score > 0; }).sort(function (a, b) { return b.score - a.score; }).slice(0, 8);
    results.innerHTML = hits.length ? hits.map(function (h) {
      var i = h.e.text.indexOf(words[0]);
      var snip = h.e.text.slice(Math.max(0, i - 40), i + 80).replace(/\s+/g, " ");
      return '<a href="#' + h.e.p.slug + '">' + esc(h.e.p.title) + "<small>…" + esc(snip) + "…</small></a>";
    }).join("") : '<a href="#home">No matches<small>Try "SCEP challenge", "revoke", "EAB"</small></a>';
    results.hidden = false;
  }
  input.addEventListener("input", function () { search(input.value); });
  input.addEventListener("keydown", function (e) {
    if (e.key === "Escape") { results.hidden = true; input.blur(); }
    if (e.key === "Enter") { var first = results.querySelector("a"); if (first) { location.hash = first.getAttribute("href"); results.hidden = true; } }
  });
  results.addEventListener("click", function () { results.hidden = true; input.value = ""; });
  document.addEventListener("click", function (e) { if (!e.target.closest(".kb-search")) results.hidden = true; });
  document.addEventListener("keydown", function (e) { if (e.key === "/" && document.activeElement !== input && !e.target.closest("input,select,textarea")) { e.preventDefault(); input.focus(); } });

  document.getElementById("kb-menu").addEventListener("click", function () { nav.classList.toggle("open"); });

  route();
})();
