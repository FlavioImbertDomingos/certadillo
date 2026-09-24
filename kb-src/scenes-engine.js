/* Certadillo 3D protocol walkthroughs.
 * A small sequence-diagram engine on three.js: actors stand on a platform,
 * messages fly between them as envelopes, and each step shows the real
 * protocol payload. Scene definitions live in scenes-data.js. */
(function () {
  "use strict";
  var THREE = window.THREE;
  var REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // The scene chrome is a fixed template; the one value in it (the scene title) is escaped.
  // Under the server's Trusted Types CSP this named policy is the only way to set markup.
  var policy = window.trustedTypes ? window.trustedTypes.createPolicy("kb-scene", { createHTML: function (s) { return s; } }) : null;
  function setHTML(el, s) { el.innerHTML = policy ? policy.createHTML(s) : s; }
  function esc(s) { return String(s).replace(/[&<>"'`]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" }[c]; }); }

  var COLORS = {
    teal: 0x0f766e, tealBright: 0x2dd4bf, gold: 0xf2b233, ink: 0x10201e, graphite: 0x2a3634,
    slate: 0x5b6b69, paper: 0xe9efed, violet: 0x7c5cff, red: 0xe5484d, green: 0x22c55e, blue: 0x3b82f6,
    request: 0x14b8a6, response: 0xf2b233, secret: 0x8b5cf6, reject: 0xe5484d, local: 0x3b82f6
  };

  function isDark() {
    var root = document.documentElement;
    var t = root.getAttribute("data-theme");
    if (t === "dark") return true;
    if (t === "light") return false;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  // ---------------------------------------------------------------- materials
  function mat(color, opts) {
    opts = opts || {};
    return new THREE.MeshStandardMaterial({
      color: color, roughness: opts.rough == null ? 0.55 : opts.rough, metalness: opts.metal || 0.05,
      emissive: opts.emissive || 0x000000, emissiveIntensity: opts.ei || 0,
      transparent: !!opts.opacity, opacity: opts.opacity || 1
    });
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r); ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h); ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y); ctx.closePath();
  }

  // Readable in both themes: a dark plate with light text and a colored rule.
  function makeLabel(text, sub, accent, scale) {
    var dpr = 2, pad = 14 * dpr;
    var canvas = document.createElement("canvas");
    var ctx = canvas.getContext("2d");
    var f1 = "600 " + 26 * dpr + "px 'IBM Plex Sans', system-ui, sans-serif";
    var f2 = "500 " + 18 * dpr + "px 'IBM Plex Mono', ui-monospace, monospace";
    ctx.font = f1; var w1 = ctx.measureText(text).width;
    var w2 = 0; if (sub) { ctx.font = f2; w2 = ctx.measureText(sub).width; }
    var w = Math.ceil(Math.max(w1, w2) + pad * 2 + 6 * dpr);
    var h = Math.ceil((sub ? 70 : 46) * dpr);
    canvas.width = w; canvas.height = h;
    ctx = canvas.getContext("2d");
    ctx.fillStyle = "rgba(12,24,22,0.88)"; roundRect(ctx, 0, 0, w, h, 10 * dpr); ctx.fill();
    ctx.fillStyle = "#" + new THREE.Color(accent || COLORS.tealBright).getHexString();
    roundRect(ctx, 0, 0, 6 * dpr, h, 3 * dpr); ctx.fill();
    ctx.fillStyle = "#f2f6f5"; ctx.font = f1; ctx.textBaseline = "top";
    ctx.fillText(text, pad + 4 * dpr, 10 * dpr);
    if (sub) { ctx.fillStyle = "#9fb7b3"; ctx.font = f2; ctx.fillText(sub, pad + 4 * dpr, 42 * dpr); }
    var tex = new THREE.CanvasTexture(canvas);
    tex.anisotropy = 4;
    if (THREE.SRGBColorSpace) tex.colorSpace = THREE.SRGBColorSpace; else tex.encoding = THREE.sRGBEncoding;
    var sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthTest: false, transparent: true }));
    var s = (scale || 1) * 0.0125;
    sprite.scale.set(w * s / dpr, h * s / dpr, 1);
    sprite.renderOrder = 10;
    return sprite;
  }

  // ---------------------------------------------------------------- actor models
  function box(w, h, d, m) { var g = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), m); g.castShadow = true; g.receiveShadow = true; return g; }
  function cyl(rt, rb, h, seg, m) { var g = new THREE.Mesh(new THREE.CylinderGeometry(rt, rb, h, seg || 32), m); g.castShadow = true; return g; }

  function keyhole(size, color) {
    var g = new THREE.Group();
    var m = mat(color || COLORS.gold, { metal: 0.6, rough: 0.3, emissive: color || COLORS.gold, ei: 0.25 });
    var disc = cyl(size, size, 0.05, 32, m); disc.rotation.x = Math.PI / 2; g.add(disc);
    var hole = mat(COLORS.ink);
    var c = cyl(size * 0.3, size * 0.3, 0.06, 20, hole); c.rotation.x = Math.PI / 2; c.position.set(0, size * 0.15, 0.01); g.add(c);
    var t = box(size * 0.26, size * 0.5, 0.06, hole); t.position.set(0, -size * 0.2, 0.01); g.add(t);
    return g;
  }

  var MODELS = {
    laptop: function () {
      var g = new THREE.Group();
      var body = mat(0xc9d3d1, { metal: 0.4, rough: 0.35 });
      var base = box(1.5, 0.08, 1.0, body); base.position.y = 0.04; g.add(base);
      var screen = new THREE.Group();
      var lid = box(1.5, 0.95, 0.06, body); lid.position.y = 0.475; screen.add(lid);
      var glass = box(1.36, 0.8, 0.02, mat(COLORS.ink, { emissive: COLORS.tealBright, ei: 0.35 })); glass.position.set(0, 0.48, 0.035); screen.add(glass);
      screen.position.set(0, 0.08, -0.47); screen.rotation.x = -0.28; g.add(screen);
      return g;
    },
    server: function () {
      var g = new THREE.Group();
      for (var i = 0; i < 3; i++) {
        var u = box(1.2, 0.36, 0.95, mat(COLORS.graphite, { metal: 0.3 })); u.position.y = 0.2 + i * 0.4; g.add(u);
        for (var j = 0; j < 3; j++) {
          var led = box(0.08, 0.05, 0.02, mat(COLORS.green, { emissive: COLORS.green, ei: 0.9 }));
          led.position.set(-0.45 + j * 0.12, 0.2 + i * 0.4, 0.48); g.add(led);
        }
      }
      return g;
    },
    gateway: function () {
      var g = new THREE.Group();
      var slab = box(1.5, 1.7, 0.55, mat(0xdfe7e5, { rough: 0.4 })); slab.position.y = 0.85; g.add(slab);
      var stripe = box(1.52, 0.16, 0.57, mat(COLORS.teal, { emissive: COLORS.tealBright, ei: 0.4 })); stripe.position.y = 1.3; g.add(stripe);
      for (var i = 0; i < 4; i++) {
        var port = box(0.22, 0.12, 0.02, mat(COLORS.ink)); port.position.set(-0.45 + i * 0.3, 0.55, 0.285); g.add(port);
      }
      return g;
    },
    shield: function () {
      var s = new THREE.Shape();
      s.moveTo(0, 1.5); s.lineTo(0.62, 1.28); s.quadraticCurveTo(0.66, 0.45, 0, 0); s.quadraticCurveTo(-0.66, 0.45, -0.62, 1.28); s.closePath();
      var geo = new THREE.ExtrudeGeometry(s, { depth: 0.28, bevelEnabled: true, bevelThickness: 0.05, bevelSize: 0.05, bevelSegments: 3 });
      var m = new THREE.Mesh(geo, mat(COLORS.teal, { metal: 0.25, rough: 0.35, emissive: COLORS.teal, ei: 0.15 }));
      m.castShadow = true; m.position.set(0, 0.15, -0.14);
      var g = new THREE.Group(); g.add(m);
      var k = keyhole(0.26); k.position.set(0, 0.95, 0.2); g.add(k);
      return g;
    },
    ca: function () {
      var g = new THREE.Group();
      var tower = cyl(0.38, 0.62, 2.1, 6, mat(0xe7eceb, { rough: 0.4 })); tower.position.y = 1.05; g.add(tower);
      var band = cyl(0.5, 0.5, 0.12, 6, mat(COLORS.teal, { emissive: COLORS.tealBright, ei: 0.3 })); band.position.y = 0.6; g.add(band);
      var crown = new THREE.Mesh(new THREE.OctahedronGeometry(0.34), mat(COLORS.gold, { metal: 0.7, rough: 0.25, emissive: COLORS.gold, ei: 0.3 }));
      crown.position.y = 2.4; crown.castShadow = true; g.add(crown);
      return g;
    },
    hsm: function () {
      var g = new THREE.Group();
      var b = box(1.2, 0.7, 0.9, mat(0x1c2524, { metal: 0.5, rough: 0.3 })); b.position.y = 0.35; g.add(b);
      var k = keyhole(0.2); k.position.set(0.25, 0.38, 0.46); g.add(k);
      for (var i = 0; i < 3; i++) { var led = box(0.07, 0.07, 0.02, mat(COLORS.gold, { emissive: COLORS.gold, ei: 1 })); led.position.set(-0.4 + i * 0.13, 0.55, 0.46); g.add(led); }
      return g;
    },
    db: function () {
      var g = new THREE.Group();
      for (var i = 0; i < 3; i++) {
        var c = cyl(0.62, 0.62, 0.36, 40, mat(i % 2 ? 0x5b6b69 : 0x74868a, { metal: 0.3, rough: 0.4 }));
        c.position.y = 0.2 + i * 0.42; g.add(c);
        var ring = cyl(0.63, 0.63, 0.04, 40, mat(COLORS.tealBright, { emissive: COLORS.tealBright, ei: 0.6 })); ring.position.y = 0.4 + i * 0.42; g.add(ring);
      }
      return g;
    },
    atm: function () {
      var g = new THREE.Group();
      var b = box(1.0, 1.7, 0.7, mat(0x2f4a7a, { rough: 0.45 })); b.position.y = 0.85; g.add(b);
      var sc = box(0.66, 0.46, 0.04, mat(COLORS.ink, { emissive: COLORS.blue, ei: 0.5 })); sc.position.set(0, 1.2, 0.36); sc.rotation.x = -0.15; g.add(sc);
      var slot = box(0.5, 0.05, 0.05, mat(COLORS.ink)); slot.position.set(0, 0.7, 0.36); g.add(slot);
      var pad = box(0.5, 0.06, 0.3, mat(0x9fb1c9)); pad.position.set(0, 0.86, 0.45); g.add(pad);
      return g;
    },
    router: function () {
      var g = new THREE.Group();
      var b = box(1.3, 0.3, 0.8, mat(0x39413f, { metal: 0.3 })); b.position.y = 0.15; g.add(b);
      [-0.45, 0.45].forEach(function (x) { var a = cyl(0.03, 0.04, 0.9, 8, mat(0x39413f)); a.position.set(x, 0.72, -0.3); a.rotation.z = x > 0 ? -0.15 : 0.15; g.add(a); });
      for (var i = 0; i < 5; i++) { var led = box(0.06, 0.04, 0.02, mat(COLORS.green, { emissive: COLORS.green, ei: 0.9 })); led.position.set(-0.4 + i * 0.2, 0.2, 0.41); g.add(led); }
      return g;
    },
    cloud: function () {
      var g = new THREE.Group(); var m = mat(0xf0f4f3, { rough: 0.8 });
      [[0, 0.7, 0, 0.5], [0.5, 0.6, 0, 0.38], [-0.5, 0.6, 0, 0.4], [0.2, 0.95, 0.1, 0.38]].forEach(function (p) {
        var s = new THREE.Mesh(new THREE.SphereGeometry(p[3], 24, 16), m); s.position.set(p[0], p[1], p[2]); s.castShadow = true; g.add(s);
      });
      return g;
    },
    globe: function () {
      var g = new THREE.Group();
      var s = new THREE.Mesh(new THREE.SphereGeometry(0.62, 32, 24), mat(COLORS.blue, { rough: 0.5, emissive: COLORS.blue, ei: 0.15 })); s.position.y = 0.8; s.castShadow = true; g.add(s);
      var w = new THREE.Mesh(new THREE.SphereGeometry(0.64, 12, 8), new THREE.MeshBasicMaterial({ color: 0xdbeafe, wireframe: true, transparent: true, opacity: 0.35 })); w.position.y = 0.8; g.add(w);
      var st = cyl(0.3, 0.4, 0.14, 24, mat(COLORS.graphite)); st.position.y = 0.07; g.add(st);
      return g;
    },
    person: function (color) {
      var g = new THREE.Group();
      var body = new THREE.Mesh(new THREE.CapsuleGeometry ? new THREE.CapsuleGeometry(0.3, 0.6, 6, 16) : new THREE.CylinderGeometry(0.3, 0.3, 1.1, 16), mat(color || 0x3f6f9f));
      body.position.y = 0.65; body.castShadow = true; g.add(body);
      var head = new THREE.Mesh(new THREE.SphereGeometry(0.24, 24, 16), mat(0xf2d3a7)); head.position.y = 1.42; head.castShadow = true; g.add(head);
      return g;
    },
    bell: function () {
      var g = new THREE.Group();
      var b = new THREE.Mesh(new THREE.CylinderGeometry(0.2, 0.62, 0.9, 32, 1, true), mat(COLORS.gold, { metal: 0.7, rough: 0.3, emissive: COLORS.gold, ei: 0.15 }));
      b.material.side = THREE.DoubleSide; b.position.y = 0.95; b.castShadow = true; g.add(b);
      var top = new THREE.Mesh(new THREE.SphereGeometry(0.2, 16, 12), b.material); top.position.y = 1.4; g.add(top);
      var cl = new THREE.Mesh(new THREE.SphereGeometry(0.13, 16, 12), mat(COLORS.graphite)); cl.position.y = 0.48; g.add(cl);
      return g;
    },
    chart: function () {
      var g = new THREE.Group();
      var base = box(1.4, 0.08, 0.8, mat(COLORS.graphite)); base.position.y = 0.04; g.add(base);
      [0.5, 0.9, 0.7, 1.3, 1.0].forEach(function (h, i) {
        var b = box(0.2, h, 0.2, mat(i === 3 ? COLORS.gold : COLORS.tealBright, { emissive: i === 3 ? COLORS.gold : COLORS.teal, ei: 0.25 }));
        b.position.set(-0.52 + i * 0.26, h / 2 + 0.08, 0); g.add(b);
      });
      return g;
    },
    radar: function () {
      var g = new THREE.Group();
      var post = cyl(0.08, 0.12, 0.9, 12, mat(COLORS.graphite)); post.position.y = 0.45; g.add(post);
      var dish = new THREE.Mesh(new THREE.SphereGeometry(0.6, 32, 16, 0, Math.PI * 2, 0, Math.PI / 3), mat(0xe7eceb, { rough: 0.35 }));
      dish.material.side = THREE.DoubleSide; dish.rotation.x = Math.PI * 0.72; dish.position.y = 1.05; g.add(dish);
      return g;
    },
    terminal: function () {
      var g = new THREE.Group();
      var b = box(1.3, 0.85, 0.12, mat(0x1b2423)); b.position.y = 0.75; g.add(b);
      var sc = box(1.18, 0.72, 0.02, mat(COLORS.ink, { emissive: COLORS.green, ei: 0.25 })); sc.position.set(0, 0.75, 0.07); g.add(sc);
      var st = box(0.14, 0.35, 0.14, mat(0x1b2423)); st.position.y = 0.17; g.add(st);
      return g;
    },
    k8s: function () {
      var g = new THREE.Group();
      var hep = cyl(0.62, 0.62, 0.22, 7, mat(0x326ce5, { emissive: 0x326ce5, ei: 0.2 })); hep.position.y = 0.3; g.add(hep);
      for (var i = 0; i < 4; i++) { var pod = box(0.28, 0.28, 0.28, mat(0xe7eceb)); var a = i * Math.PI / 2 + 0.4; pod.position.set(Math.cos(a) * 0.35, 0.58, Math.sin(a) * 0.35); g.add(pod); }
      return g;
    }
  };

  // ---------------------------------------------------------------- Dilly billboard
  var DILLY_SRC = {};
  function dillyTexture(mood) {
    var key = mood || "happy";
    if (DILLY_SRC[key]) return DILLY_SRC[key];
    var file = key === "happy" ? "dilly.svg" : "dilly-" + key + ".svg";
    var base = window.CERTADILLO_KB_ASSETS || "img/";
    var tex = new THREE.TextureLoader().load(base + file);
    if (THREE.SRGBColorSpace) tex.colorSpace = THREE.SRGBColorSpace; else tex.encoding = THREE.sRGBEncoding;
    DILLY_SRC[key] = tex;
    return tex;
  }

  // ---------------------------------------------------------------- view
  function SceneView(container, def) {
    this.container = container;
    this.def = def;
    this.stepIndex = -1;
    this.playing = false;
    this.speed = 1;
    this.packets = [];
    this.effects = [];
    this.chain = [];
    this.buildDom();
    this.buildScene();
    this.bindEvents();
    this.goTo(0, false);
    this.loop = this.loop.bind(this);
    this.visible = true;
    this.last = performance.now();
    requestAnimationFrame(this.loop);
  }

  SceneView.prototype.buildDom = function () {
    var d = this.def;
    this.container.classList.add("scene");
    setHTML(this.container,
      '<div class="scene-stage"><canvas class="scene-canvas" aria-label="' + esc(d.title) + ' 3D walkthrough"></canvas>' +
      '<div class="scene-hint">Drag to rotate · double-click to reset</div>' +
      '<div class="scene-zoom"><button type="button" data-z="in" aria-label="Zoom in">+</button><button type="button" data-z="out" aria-label="Zoom out">−</button></div></div>' +
      '<div class="scene-panel">' +
      '<div class="scene-controls" role="group" aria-label="Walkthrough controls">' +
      '<button type="button" data-a="restart">Restart</button>' +
      '<button type="button" data-a="prev">Back</button>' +
      '<button type="button" data-a="play" class="primary">Play</button>' +
      '<button type="button" data-a="next">Next</button>' +
      '<span class="scene-count" aria-live="polite"></span>' +
      '<label class="scene-speed">Speed <select><option value="0.6">0.6×</option><option value="1" selected>1×</option><option value="1.6">1.6×</option></select></label>' +
      "</div>" +
      '<div class="scene-step"><div class="scene-eyebrow"></div><h4></h4><p></p><pre class="scene-payload"><code></code></pre></div>' +
      '<ol class="scene-steps"></ol></div>');
    var ol = this.container.querySelector(".scene-steps");
    d.steps.forEach(function (s, i) {
      var li = document.createElement("li");
      var b = document.createElement("button"); b.type = "button"; b.textContent = s.title; b.dataset.i = i;
      li.appendChild(b); ol.appendChild(li);
    });
    this.canvas = this.container.querySelector("canvas");
    this.stage = this.container.querySelector(".scene-stage");
  };

  SceneView.prototype.buildScene = function () {
    var r = new THREE.WebGLRenderer({ canvas: this.canvas, antialias: true, alpha: true });
    r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    r.shadowMap.enabled = true; r.shadowMap.type = THREE.PCFSoftShadowMap;
    if (THREE.SRGBColorSpace) r.outputColorSpace = THREE.SRGBColorSpace; else r.outputEncoding = THREE.sRGBEncoding;
    this.renderer = r;
    var scene = new THREE.Scene();
    this.scene = scene;
    this.camera = new THREE.PerspectiveCamera(34, 16 / 9, 0.1, 200);
    this.orbit = { theta: this.def.camera ? this.def.camera.theta : 0.0, phi: this.def.camera ? this.def.camera.phi : 1.02, radius: this.def.camera ? this.def.camera.radius : 17 };
    this.home = { theta: this.orbit.theta, phi: this.orbit.phi, radius: this.orbit.radius };
    this.target = new THREE.Vector3(0, -0.6, 0.4);

    this.hemi = new THREE.HemisphereLight(0xffffff, 0x3a4a48, 0.9);
    scene.add(this.hemi);
    var sun = new THREE.DirectionalLight(0xffffff, 1.1);
    sun.position.set(6, 12, 8); sun.castShadow = true;
    sun.shadow.mapSize.set(1024, 1024);
    var sc = sun.shadow.camera; sc.left = -14; sc.right = 14; sc.top = 14; sc.bottom = -14;
    scene.add(sun);

    var R = this.def.platformRadius || 9;
    this.platform = new THREE.Mesh(new THREE.CylinderGeometry(R, R + 0.3, 0.4, 96), mat(0xdfe6e4, { rough: 0.9 }));
    this.platform.position.y = -0.2; this.platform.receiveShadow = true; scene.add(this.platform);
    var rim = new THREE.Mesh(new THREE.TorusGeometry(R + 0.05, 0.05, 8, 128), mat(COLORS.teal, { emissive: COLORS.tealBright, ei: 0.5 }));
    rim.rotation.x = Math.PI / 2; rim.position.y = 0.01; scene.add(rim);
    var grid = new THREE.PolarGridHelper(R - 0.2, 12, 6, 64, 0x9fb1ae, 0xc3cfcc);
    grid.position.y = 0.012; grid.material.transparent = true; grid.material.opacity = 0.45; scene.add(grid);
    this.grid = grid;
    this.applyTheme();
    var selfT = this;
    this._mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
    this._onTheme = function () { selfT.applyTheme(); };
    if (this._mq && this._mq.addEventListener) this._mq.addEventListener("change", this._onTheme);
    if ("MutationObserver" in window) {
      this._mo = new MutationObserver(this._onTheme);
      this._mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    }

    this.actors = {};
    var self = this;
    this.def.actors.forEach(function (a) {
      var g = new THREE.Group();
      var model = (MODELS[a.kind] || MODELS.server)(a.color);
      if (a.scale) model.scale.setScalar(a.scale);
      g.add(model);
      g.position.set(a.x, 0, a.z);
      // face the default camera so every actor shows its front
      model.rotation.y = (self.def.camera ? self.def.camera.theta : 0) + (a.turn || 0);
      var halo = new THREE.Mesh(new THREE.RingGeometry(0.95, 1.15, 48), new THREE.MeshBasicMaterial({ color: COLORS.tealBright, transparent: true, opacity: 0, side: THREE.DoubleSide }));
      halo.rotation.x = -Math.PI / 2; halo.position.y = 0.02; g.add(halo);
      var label = makeLabel(a.label, a.sub, a.accent);
      label.position.set(0, (a.labelY || 2.2) * (a.scale || 1), 0); g.add(label);
      scene.add(g);
      self.actors[a.id] = { def: a, group: g, model: model, halo: halo, glow: 0, anchor: new THREE.Vector3(a.x, (a.anchorY || 1.0) * (a.scale || 1), a.z) };
    });

    if (this.def.dilly) {
      var at = this.actors[this.def.dilly];
      var sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: dillyTexture("happy"), transparent: true, depthTest: true }));
      sp.scale.set(1.9, 1.47, 1);
      sp.position.set(at.def.x * 0.78, 3.15, at.def.z * 0.78 + 0.01);
      scene.add(sp);
      this.dilly = sp;
    }
    this.chainGroup = new THREE.Group();
    if (this.def.chainAt) {
      var ca = this.actors[this.def.chainAt];
      this.chainGroup.position.set(ca.def.x + (this.def.chainOffset ? this.def.chainOffset[0] : 1.1), 0, ca.def.z + (this.def.chainOffset ? this.def.chainOffset[1] : 0));
    }
    scene.add(this.chainGroup);
    this.resize();
  };

  SceneView.prototype.applyTheme = function () {
    var dark = isDark();
    this.platform.material.color.setHex(dark ? 0x1b2a28 : 0xdfe6e4);
    this.grid.material.opacity = dark ? 0.35 : 0.45;
    this.hemi && (this.hemi.intensity = dark ? 0.75 : 0.9);
  };

  SceneView.prototype.bindEvents = function () {
    var self = this;
    var ctr = this.container;
    ctr.querySelector(".scene-controls").addEventListener("click", function (e) {
      var a = e.target && e.target.dataset && e.target.dataset.a;
      if (!a) return;
      if (a === "play") self.togglePlay();
      if (a === "next") { self.pause(); self.goTo(Math.min(self.stepIndex + 1, self.def.steps.length - 1), true); }
      if (a === "prev") { self.pause(); self.goTo(Math.max(self.stepIndex - 1, 0), true); }
      if (a === "restart") { self.goTo(0, true); self.play(); }
    });
    ctr.querySelector(".scene-speed select").addEventListener("change", function (e) { self.speed = parseFloat(e.target.value); });
    ctr.querySelector(".scene-steps").addEventListener("click", function (e) {
      var i = e.target && e.target.dataset && e.target.dataset.i;
      if (i != null) { self.pause(); self.goTo(parseInt(i, 10), true); }
    });
    ctr.querySelector(".scene-zoom").addEventListener("click", function (e) {
      var z = e.target && e.target.dataset && e.target.dataset.z; if (!z) return;
      self.orbit.radius = Math.max(8, Math.min(30, self.orbit.radius * (z === "in" ? 0.86 : 1.16)));
    });
    var drag = null;
    this.canvas.addEventListener("pointerdown", function (e) { drag = { x: e.clientX, y: e.clientY }; self.canvas.setPointerCapture(e.pointerId); self.userMoved = true; });
    this.canvas.addEventListener("pointermove", function (e) {
      if (!drag) return;
      self.orbit.theta -= (e.clientX - drag.x) * 0.006;
      self.orbit.phi = Math.max(0.35, Math.min(1.45, self.orbit.phi - (e.clientY - drag.y) * 0.005));
      drag = { x: e.clientX, y: e.clientY };
    });
    this.canvas.addEventListener("pointerup", function () { drag = null; });
    this.canvas.addEventListener("pointercancel", function () { drag = null; });
    this.canvas.addEventListener("dblclick", function () { self.orbit.theta = self.home.theta; self.orbit.phi = self.home.phi; self.orbit.radius = self.home.radius; self.userMoved = false; });
    this.canvas.addEventListener("keydown", function (e) {
      if (e.key === "ArrowRight") self.goTo(Math.min(self.stepIndex + 1, self.def.steps.length - 1), true);
      if (e.key === "ArrowLeft") self.goTo(Math.max(self.stepIndex - 1, 0), true);
    });
    this.canvas.tabIndex = 0;
    this._onResize = function () { self.resize(); };
    window.addEventListener("resize", this._onResize);
    if ("IntersectionObserver" in window) {
      this._io = new IntersectionObserver(function (entries) { self.visible = entries[0].isIntersecting; });
      this._io.observe(this.container);
    }
  };

  SceneView.prototype.resize = function () {
    var w = this.stage.clientWidth || 600;
    var h = Math.max(300, Math.min(560, Math.round(w * 0.58)));
    this.stage.style.height = h + "px";
    this.renderer.setSize(w, h, false);
    this.canvas.style.width = w + "px"; this.canvas.style.height = h + "px";
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  };

  SceneView.prototype.play = function () {
    this.playing = true;
    this.container.querySelector('[data-a="play"]').textContent = "Pause";
    if (!this.running) {
      if (this.stepIndex >= this.def.steps.length - 1) this.goTo(0, true);
      else this.goTo(this.stepIndex + 1, true);
    }
  };
  SceneView.prototype.pause = function () {
    this.playing = false;
    this.container.querySelector('[data-a="play"]').textContent = "Play";
  };
  SceneView.prototype.togglePlay = function () { if (this.playing) this.pause(); else this.play(); };

  // Deterministic state for a step: chain length and Dilly's mood.
  SceneView.prototype.settle = function (index) {
    var blocks = 0;
    for (var i = 0; i < index; i++) {
      (this.def.steps[i].moves || []).forEach(function (m) { if (m.effect === "store") blocks++; });
      if (this.def.steps[i].effect === "store") blocks++;
    }
    this.setChain(blocks);
    var mood = "happy";
    for (var k = 0; k < index; k++) {
      if (this.def.steps[k].dilly) mood = this.def.steps[k].dilly;
      (this.def.steps[k].moves || []).forEach(function (m) { if (m.dilly) mood = m.dilly; });
    }
    if (this.def.steps[index].dilly) mood = this.def.steps[index].dilly;
    this.pendingMood = mood;
  };

  SceneView.prototype.setChain = function (n) {
    while (this.chain.length > n) this.chainGroup.remove(this.chain.pop());
    while (this.chain.length < n) this.addBlock(false);
  };
  SceneView.prototype.addBlock = function (animate) {
    var i = this.chain.length;
    var b = box(0.42, 0.24, 0.42, mat(i % 2 ? COLORS.gold : COLORS.tealBright, { metal: 0.3, emissive: i % 2 ? COLORS.gold : COLORS.teal, ei: 0.25 }));
    b.position.set(0, 0.14 + i * 0.27, 0);
    if (animate && !REDUCED) { b.position.y += 1.5; b.userData.drop = 0.14 + i * 0.27; }
    this.chainGroup.add(b); this.chain.push(b);
  };

  SceneView.prototype.goTo = function (index, animate) {
    this.clearPackets();
    this.stepIndex = index;
    this.settle(index);
    var s = this.def.steps[index];
    var q = this.container;
    q.querySelector(".scene-eyebrow").textContent = (s.phase ? s.phase + " · " : "") + "Step " + (index + 1) + " of " + this.def.steps.length;
    q.querySelector(".scene-step h4").textContent = s.title;
    q.querySelector(".scene-step p").textContent = s.body;
    var pre = q.querySelector(".scene-payload");
    pre.hidden = !s.payload;
    pre.querySelector("code").textContent = s.payload || "";
    q.querySelector(".scene-count").textContent = (index + 1) + " / " + this.def.steps.length;
    q.querySelectorAll(".scene-steps button").forEach(function (b, i) {
      b.classList.toggle("on", i === index); b.classList.toggle("done", i < index);
      if (i === index) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
    });
    var moves = s.moves || [];
    this.queue = moves.slice();
    this.running = true;
    this.dwell = 0;
    this.startNextMove(animate);
    if (!moves.length && s.effect) this.applyEffect({ effect: s.effect, to: s.actor, from: s.actor }, true);
    if (s.actor) this.pulse(s.actor);
  };

  SceneView.prototype.clearPackets = function () {
    var sc = this.scene;
    this.packets.forEach(function (p) { sc.remove(p.group); });
    this.effects.forEach(function (fx) { sc.remove(fx.obj); });
    this.packets = []; this.effects = [];
  };

  SceneView.prototype.startNextMove = function () {
    var m = this.queue.shift();
    if (!m) { this.running = false; this.readTime = this.readingTime(); return; }
    if (m.local) { this.pulse(m.from); this.applyEffect(m, true); this.waitLocal = 0.9; this.currentLocal = true; return; }
    this.currentLocal = false;
    this.spawnPacket(m);
    this.pulse(m.from);
  };

  SceneView.prototype.readingTime = function () {
    var s = this.def.steps[this.stepIndex];
    var chars = (s.body || "").length + (s.payload || "").length * 0.35;
    return Math.min(9, 2.6 + chars * 0.018);
  };

  SceneView.prototype.pulse = function (id) { var a = this.actors[id]; if (a) a.glow = 1; };

  SceneView.prototype.spawnPacket = function (m) {
    var from = this.actors[m.from], to = this.actors[m.to];
    if (!from || !to) { this.startNextMove(); return; }
    var kind = m.kind || "request";
    var color = COLORS[kind] || COLORS.request;
    var g = new THREE.Group();
    var env = box(0.62, 0.4, 0.08, mat(0xf7faf9, { rough: 0.5 }));
    g.add(env);
    var flap = new THREE.Mesh(new THREE.ConeGeometry(0.44, 0.24, 4, 1), mat(color, { emissive: color, ei: 0.55 }));
    flap.rotation.set(Math.PI / 2, 0, Math.PI / 4); flap.scale.set(1, 1, 0.12); flap.position.set(0, 0.07, 0.05); g.add(flap);
    var band = box(0.64, 0.08, 0.09, mat(color, { emissive: color, ei: 0.55 })); band.position.y = -0.12; g.add(band);
    if (kind === "secret") { var lk = keyhole(0.14, COLORS.gold); lk.position.set(0, -0.02, 0.06); g.add(lk); }
    if (m.label) { var lab = makeLabel(m.label, m.sub, color, 0.8); lab.position.set(0, 0.62, 0); g.add(lab); }
    var p0 = from.anchor.clone(), p2 = to.anchor.clone();
    var mid = p0.clone().add(p2).multiplyScalar(0.5);
    mid.y += 1.4 + p0.distanceTo(p2) * 0.18;
    var curve = new THREE.QuadraticBezierCurve3(p0, mid, p2);
    var lineGeo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(40));
    var line = new THREE.Line(lineGeo, new THREE.LineDashedMaterial({ color: color, dashSize: 0.18, gapSize: 0.12, transparent: true, opacity: 0.7 }));
    line.computeLineDistances();
    this.scene.add(line); this.effects.push({ obj: line, life: 999 });
    this.scene.add(g);
    this.packets.push({ group: g, curve: curve, t: 0, move: m, dur: REDUCED ? 0.01 : (m.dur || 1.5) });
  };

  SceneView.prototype.applyEffect = function (m, arrived) {
    if (m.dilly) this.pendingMood = m.dilly;
    var fx = m.effect; if (!fx) return;
    var target = this.actors[m.to || m.from];
    if (fx === "store") { this.addBlock(true); this.pulse(m.to); }
    if (fx === "check" || fx === "sign" || fx === "hsm" || fx === "reject" || fx === "burn" || fx === "unlock") {
      var color = fx === "reject" || fx === "burn" ? COLORS.red : fx === "sign" || fx === "hsm" ? COLORS.gold : fx === "unlock" ? COLORS.secret : COLORS.green;
      var ring = new THREE.Mesh(new THREE.TorusGeometry(0.9, 0.06, 8, 48), new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.9 }));
      ring.position.copy(target.anchor); ring.position.y += 0.4; ring.rotation.x = Math.PI / 2;
      this.scene.add(ring); this.effects.push({ obj: ring, life: 1.2, kind: "ring" });
      if (fx === "burn") this.burst(target.anchor, COLORS.red);
      if (fx === "sign" || fx === "hsm") this.burst(target.anchor, COLORS.gold);
    }
    if (arrived && target) this.pulse(target.def.id);
  };

  SceneView.prototype.burst = function (at, color) {
    for (var i = 0; i < (REDUCED ? 0 : 16); i++) {
      var s = new THREE.Mesh(new THREE.SphereGeometry(0.05, 8, 6), new THREE.MeshBasicMaterial({ color: color, transparent: true }));
      s.position.copy(at); s.position.y += 0.6;
      s.userData.v = new THREE.Vector3((Math.random() - 0.5) * 2.4, Math.random() * 2.2 + 0.6, (Math.random() - 0.5) * 2.4);
      this.scene.add(s); this.effects.push({ obj: s, life: 1.0, kind: "spark" });
    }
  };

  SceneView.prototype.loop = function (now) {
    requestAnimationFrame(this.loop);
    var dt = Math.min(0.05, (now - this.last) / 1000); this.last = now;
    if (!this.visible || document.hidden) return;
    var sdt = dt * this.speed;

    // camera
    if (!this.userMoved && !REDUCED) this.orbit.theta += dt * 0.03;
    var o = this.orbit, c = this.camera;
    var rad = o.radius * Math.max(1, 1.5 / c.aspect);  // back off on narrow screens so the whole ring fits
    c.position.set(this.target.x + rad * Math.sin(o.phi) * Math.sin(o.theta), this.target.y + rad * Math.cos(o.phi), this.target.z + rad * Math.sin(o.phi) * Math.cos(o.theta));
    c.lookAt(this.target);

    // actors
    var t = now / 1000;
    for (var id in this.actors) {
      var a = this.actors[id];
      a.glow = Math.max(0, a.glow - dt * 0.7);
      a.halo.material.opacity = a.glow * 0.85;
      var s = 1 + a.glow * 0.25 * (1 + Math.sin(t * 8) * 0.2);
      a.halo.scale.set(s, s, s);
      if (a.def.kind === "ca" || a.def.kind === "globe") a.model.rotation.y += dt * 0.25;
    }

    // packets
    var self = this;
    this.packets = this.packets.filter(function (p) {
      p.t += sdt / p.dur;
      var k = Math.min(1, p.t);
      var e = k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
      var pos = p.curve.getPoint(e);
      p.group.position.copy(pos);
      p.group.lookAt(self.camera.position.x, pos.y, self.camera.position.z);
      if (p.move.kind === "reject" && k > 0.55) {
        p.group.children[0].material.color.setHex(COLORS.red);
      }
      if (k >= 1) {
        self.applyEffect(p.move, true);
        if (p.move.kind === "reject") self.burst(p.curve.getPoint(1), COLORS.red);
        self.scene.remove(p.group);
        self.startNextMove();
        return false;
      }
      return true;
    });
    if (this.currentLocal && this.waitLocal != null) {
      this.waitLocal -= sdt;
      if (this.waitLocal <= 0) { this.waitLocal = null; this.currentLocal = false; this.startNextMove(); }
    }

    // effects
    this.effects = this.effects.filter(function (fx) {
      fx.life -= dt;
      if (fx.kind === "ring") { var sc = fx.obj.scale.x + dt * 1.2; fx.obj.scale.set(sc, sc, sc); fx.obj.material.opacity = Math.max(0, fx.life / 1.2); }
      if (fx.kind === "spark") { fx.obj.userData.v.y -= dt * 4; fx.obj.position.addScaledVector(fx.obj.userData.v, dt); fx.obj.material.opacity = Math.max(0, fx.life); }
      if (fx.life <= 0) { self.scene.remove(fx.obj); return false; }
      return true;
    });

    // audit chain drop-in
    this.chain.forEach(function (b) {
      if (b.userData.drop != null) { b.position.y = Math.max(b.userData.drop, b.position.y - dt * 4); if (b.position.y === b.userData.drop) b.userData.drop = null; }
    });

    // Dilly
    if (this.dilly) {
      if (this.pendingMood && this.pendingMood !== this.mood) { this.mood = this.pendingMood; this.dilly.material.map = dillyTexture(this.mood); this.dilly.material.needsUpdate = true; }
      this.dilly.position.y = 3.15 + (REDUCED ? 0 : Math.sin(t * 2) * 0.06);
    }

    // autoplay
    if (this.playing && !this.running && this.packets.length === 0) {
      this.readTime -= sdt;
      if (this.readTime <= 0) {
        if (this.stepIndex < this.def.steps.length - 1) this.goTo(this.stepIndex + 1, true);
        else this.pause();
      }
    }
    this.renderer.render(this.scene, this.camera);
  };

  SceneView.prototype.dispose = function () {
    window.removeEventListener("resize", this._onResize);
    if (this._mq && this._mq.removeEventListener) this._mq.removeEventListener("change", this._onTheme);
    if (this._mo) this._mo.disconnect();
    if (this._io) this._io.disconnect();
    this.renderer.dispose();
    this.loop = function () {};
  };

  window.CertadilloScenes = {
    defs: {},
    register: function (def) { this.defs[def.id] = def; },
    mount: function (container, id) {
      if (!THREE) { container.textContent = "3D view needs WebGL and three.js."; return null; }
      var def = this.defs[id];
      if (!def) return null;
      try { return new SceneView(container, def); }
      catch (e) { container.textContent = "This browser could not start the 3D view (" + e.message + "). The steps are described in the text below."; return null; }
    }
  };
})();
