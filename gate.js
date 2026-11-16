// Shared unlock gate for every stage page.
//
// Each page declares, on <body>:
//   data-bundle     URL of its encrypted bundle, relative to the page
//   data-store-key  localStorage key for remembering the passphrase
// and contains #gate / #unlock-form / #passphrase / #unlock-btn / #status /
// #stage / #footer / #lock-btn.
//
// Bundle format must match lib/sitebundle.py:
//   salt (16) || iv (12) || AES-256-GCM ciphertext+tag,
//   key = PBKDF2-SHA256(normalized flag, salt, 600k iterations).
// The decrypted JSON has "html", and optionally "public" + "trace" (stage 2).
(() => {
  "use strict";

  const PBKDF2_ITERATIONS = 600000;
  const BUNDLE_URL = document.body.dataset.bundle;
  const STORE_KEY = document.body.dataset.storeKey;

  const $ = (id) => document.getElementById(id);
  const store = {
    get() { try { return localStorage.getItem(STORE_KEY); } catch { return null; } },
    set(v) { try { localStorage.setItem(STORE_KEY, v); } catch {} },
    clear() { try { localStorage.removeItem(STORE_KEY); } catch {} },
  };

  function normalize(s) {
    s = s.trim();
    if (s.toUpperCase().startsWith("BREAKROOM{") && s.endsWith("}")) s = s.slice(10, -1);
    return s;
  }

  async function decryptBundle(passphrase) {
    const res = await fetch(BUNDLE_URL, { cache: "no-cache" });
    if (!res.ok) throw new Error("fetch");
    const blob = new Uint8Array(await res.arrayBuffer());
    const salt = blob.slice(0, 16), iv = blob.slice(16, 28), ct = blob.slice(28);
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(normalize(passphrase)), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct); // throws on a wrong flag
    return JSON.parse(new TextDecoder().decode(pt));
  }

  async function unlock(passphrase, quiet) {
    const btn = $("unlock-btn"), status = $("status");
    btn.disabled = true;
    status.className = "status";
    status.textContent = "Brewing…";
    try {
      const bundle = await decryptBundle(passphrase);
      store.set(passphrase);
      show(bundle);
    } catch (e) {
      if (quiet) { store.clear(); status.textContent = ""; }
      else {
        status.className = "status bad";
        status.textContent = e.message === "fetch" ? "Couldn't load this stage. Try again in a bit." : "Nope. That's not the right flag.";
      }
    } finally {
      btn.disabled = false;
    }
  }

  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function show(bundle) {
    $("gate").hidden = true;
    const stage = $("stage");
    stage.innerHTML = bundle.html;
    stage.hidden = false;
    $("footer").hidden = false;

    let data = null;
    if (bundle.trace) {
      const bin = atob(bundle.trace.data_b64);
      data = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
    }

    stage.querySelectorAll("[data-download]").forEach((b) => b.addEventListener("click", () => {
      if (b.dataset.download === "params" && bundle.public) {
        download("params.json", JSON.stringify(bundle.public, null, 2) + "\n", "application/json");
      } else if (b.dataset.download === "trace" && data) {
        let csv = "sample,value\n";
        for (let i = 0; i < data.length; i++) csv += i + "," + data[i] + "\n";
        download("trace.csv", csv, "text/csv");
      }
    }));

    if (data && $("scope-main")) scope(data, bundle.trace.sample_rate_hz);
  }

  // ---------------------------------------------------------------- scope ----
  function scope(data, rate) {
    const main = $("scope-main"), over = $("scope-overview"), readout = $("scope-readout");
    const N = data.length, MIN_SPAN = 60;
    let x0 = 0, x1 = N, hover = null;

    const css = getComputedStyle(document.documentElement);
    const C = {
      bg: css.getPropertyValue("--scope-bg").trim(),
      grid: css.getPropertyValue("--scope-grid").trim(),
      trace: css.getPropertyValue("--scope-trace").trim(),
    };

    function fit(c) {
      const dpr = window.devicePixelRatio || 1, r = c.getBoundingClientRect();
      c.width = Math.max(1, Math.round(r.width * dpr));
      c.height = Math.max(1, Math.round(r.height * dpr));
      return dpr;
    }

    function plot(ctx, w, h, a, b, pad) {
      const span = b - a, yOf = (v) => pad + (1 - v / 255) * (h - 2 * pad);
      ctx.beginPath();
      if (span / w > 1) {           // many samples per pixel: min/max columns
        for (let px = 0; px < w; px++) {
          const s = Math.floor(a + (px * span) / w), e = Math.max(s + 1, Math.floor(a + ((px + 1) * span) / w));
          let lo = 255, hi = 0;
          for (let i = s; i < e && i < N; i++) { const v = data[i]; if (v < lo) lo = v; if (v > hi) hi = v; }
          ctx.moveTo(px + 0.5, yOf(hi)); ctx.lineTo(px + 0.5, yOf(lo) + 0.5);
        }
      } else {                       // zoomed in: connect the samples
        const s = Math.max(0, Math.floor(a)), e = Math.min(N - 1, Math.ceil(b));
        for (let i = s; i <= e; i++) {
          const px = ((i - a) / span) * w;
          i === s ? ctx.moveTo(px, yOf(data[i])) : ctx.lineTo(px, yOf(data[i]));
        }
      }
      ctx.stroke();
    }

    function draw() {
      const dpr = fit(main), ctx = main.getContext("2d"), w = main.width, h = main.height;
      ctx.fillStyle = C.bg; ctx.fillRect(0, 0, w, h);
      ctx.strokeStyle = C.grid; ctx.lineWidth = 1;
      ctx.beginPath();
      for (let i = 1; i < 10; i++) { const x = Math.round((i * w) / 10) + 0.5; ctx.moveTo(x, 0); ctx.lineTo(x, h); }
      for (let i = 1; i < 8; i++) { const y = Math.round((i * h) / 8) + 0.5; ctx.moveTo(0, y); ctx.lineTo(w, y); }
      ctx.stroke();
      ctx.strokeStyle = C.trace; ctx.lineWidth = Math.max(1, dpr * 0.9);
      plot(ctx, w, h, x0, x1, 8 * dpr);

      if (hover !== null && hover >= x0 && hover < x1) {
        const px = ((hover - x0) / (x1 - x0)) * w;
        ctx.strokeStyle = "rgba(255,255,255,0.35)"; ctx.lineWidth = dpr;
        ctx.beginPath(); ctx.moveTo(px, 0); ctx.lineTo(px, h); ctx.stroke();
      }

      const o = over.getContext("2d"), ow = (fit(over), over.width), oh = over.height;
      o.fillStyle = C.bg; o.fillRect(0, 0, ow, oh);
      o.strokeStyle = C.trace; o.globalAlpha = 0.6; o.lineWidth = 1;
      plot(o, ow, oh, 0, N, 3 * dpr);
      o.globalAlpha = 1;
      const vx = (x0 / N) * ow, vw = Math.max(2, ((x1 - x0) / N) * ow);
      o.fillStyle = "rgba(217,160,102,0.18)"; o.fillRect(vx, 0, vw, oh);
      o.strokeStyle = "#d9a066"; o.strokeRect(vx + 0.5, 0.5, vw - 1, oh - 1);

      const us = (n) => (n / rate * 1e6).toFixed(1);
      let text = `samples ${Math.floor(x0).toLocaleString()}–${Math.ceil(x1).toLocaleString()} (${us(x1 - x0)} µs)`;
      if (hover !== null) text += `  ·  #${hover.toLocaleString()} = ${data[hover]}`;
      readout.textContent = text;
    }

    function clamp() {
      let span = Math.min(N, Math.max(MIN_SPAN, x1 - x0));
      x0 = Math.max(0, Math.min(N - span, x0)); x1 = x0 + span;
    }
    function zoomAt(f, center) {
      const c = center ?? (x0 + x1) / 2;
      x0 = c - (c - x0) * f; x1 = c + (x1 - c) * f; clamp(); draw();
    }
    const sampleAt = (e) => x0 + ((e.clientX - main.getBoundingClientRect().left) / main.clientWidth) * (x1 - x0);

    main.addEventListener("wheel", (e) => {
      e.preventDefault();
      if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
        const d = (e.deltaX / main.clientWidth) * (x1 - x0); x0 += d; x1 += d; clamp(); draw();
      } else zoomAt(Math.exp(e.deltaY * 0.0015), sampleAt(e));
    }, { passive: false });

    let drag = null;
    main.addEventListener("pointerdown", (e) => {
      drag = { x: e.clientX, a: x0, b: x1 }; main.setPointerCapture(e.pointerId); main.classList.add("dragging");
    });
    main.addEventListener("pointermove", (e) => {
      if (drag) {
        const d = ((drag.x - e.clientX) / main.clientWidth) * (drag.b - drag.a);
        x0 = drag.a + d; x1 = drag.b + d; clamp();
      }
      hover = Math.max(0, Math.min(N - 1, Math.round(sampleAt(e))));
      draw();
    });
    const endDrag = () => { drag = null; main.classList.remove("dragging"); };
    main.addEventListener("pointerup", endDrag);
    main.addEventListener("pointercancel", endDrag);
    main.addEventListener("pointerleave", () => { if (!drag) { hover = null; draw(); } });
    main.addEventListener("dblclick", () => { x0 = 0; x1 = N; draw(); });

    function jump(e) {
      const c = ((e.clientX - over.getBoundingClientRect().left) / over.clientWidth) * N, half = (x1 - x0) / 2;
      x0 = c - half; x1 = c + half; clamp(); draw();
    }
    over.addEventListener("pointerdown", (e) => {
      over.setPointerCapture(e.pointerId); jump(e);
      const move = (ev) => jump(ev);
      over.addEventListener("pointermove", move);
      over.addEventListener("pointerup", () => over.removeEventListener("pointermove", move), { once: true });
    });

    document.querySelectorAll("[data-zoom]").forEach((b) => b.addEventListener("click", () => {
      const z = b.dataset.zoom;
      if (z === "reset") { x0 = 0; x1 = N; draw(); } else zoomAt(z === "in" ? 0.5 : 2);
    }));
    new ResizeObserver(draw).observe(main);
    draw();
  }

  // ------------------------------------------------------------------ init ---
  $("unlock-form").addEventListener("submit", (e) => { e.preventDefault(); unlock($("passphrase").value, false); });
  $("lock-btn").addEventListener("click", () => { store.clear(); location.reload(); });
  const saved = store.get();
  if (saved) unlock(saved, true);
})();
