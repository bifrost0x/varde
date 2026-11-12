// SPDX-License-Identifier: Apache-2.0
// Small progressive enhancements. Everything works without JavaScript; the
// strict CSP forbids inline scripts, so behaviour lives here.
(function () {
  "use strict";

  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute("content") : "";

  // htmx requests carry the CSRF token as a header.
  document.addEventListener("htmx:configRequest", function (e) {
    if (csrf) { e.detail.headers["X-CSRF-Token"] = csrf; }
  });

  // Confirmation for destructive actions: <form data-confirm="...">.
  var dialog = document.getElementById("confirm-dialog");
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement) || !form.dataset.confirm || form.dataset.confirmed === "1") { return; }
    if (!dialog || typeof dialog.showModal !== "function") { return; }
    e.preventDefault();
    dialog.querySelector("[data-confirm-text]").textContent = form.dataset.confirm;
    dialog.returnValue = "";
    dialog.showModal();
    dialog.addEventListener("close", function onClose() {
      dialog.removeEventListener("close", onClose);
      if (dialog.returnValue === "confirm") {
        form.dataset.confirmed = "1";
        if (typeof form.requestSubmit === "function") { form.requestSubmit(e.submitter || undefined); } else { form.submit(); }
      }
    });
  });

  // Copy buttons: <button data-copy="#id">.
  document.addEventListener("click", function (e) {
    var btn = e.target.closest ? e.target.closest("[data-copy]") : null;
    if (!btn) { return; }
    var src = document.querySelector(btn.getAttribute("data-copy"));
    if (!src || !navigator.clipboard) { return; }
    navigator.clipboard.writeText(src.textContent.trim()).then(function () {
      var label = btn.querySelector("[data-copy-label]");
      if (label) { label.textContent = "Copied"; }
    });
  });

  // Product tour: a short walk through the main pages, started from its
  // button. The step survives page changes in sessionStorage. Storage may be
  // unavailable (private windows); the tour then simply does not resume.
  var tourSteps = [
    { path: "/", sel: ".hero, main h1", title: "Overview", text: "The state at a glance. When an urgent finding appears, the beacon lights up and this page names the update that fixes it." },
    { path: "/connections", sel: "#scope", title: "Allow your networks", text: "Varde connects only to the ranges you allow here. A scan then finds Proxmox nodes, Docker hosts and web apps." },
    { path: "/connections", sel: "#next-steps, #integrations", title: "Next steps", text: "Ranked by what they reveal: one Proxmox token shows every guest, the agent reads every package and container of a host. Each step says exactly what Varde may do afterwards." },
    { path: "/systems", sel: "main h1", title: "Systems", text: "Every machine with what is installed, what is affected and where Varde knows it from. Open one for its full inventory." },
    { path: "/findings", sel: "main h1", title: "Findings", text: "Advisories that apply, by priority. Unverified ones stay visible but never notify; each finding says how to update." },
    { path: "/systems/gaps", sel: "main h1", title: "Gaps", text: "What Varde cannot see yet. Every gap comes with the step that closes it." },
    { path: "/settings", sel: "#sources", title: "Optional sources", text: "Each source says what it reveals before you switch it on. Notification secrets are set through environment variables and never pass the UI." }
  ];
  function store(kind) { try { return window[kind]; } catch (err) { return null; } }
  function get(kind, key) { var s = store(kind); try { return s ? s.getItem(key) : null; } catch (err) { return null; } }
  function set(kind, key, v) { var s = store(kind); try { if (s) { if (v === null) { s.removeItem(key); } else { s.setItem(key, v); } } } catch (err) { /* ignore */ } }
  var tourBox = null;
  function endTour() {
    set("sessionStorage", "varde-tour-step", null);
    set("localStorage", "varde-tour-done", "1");
    if (tourBox) { tourBox.remove(); tourBox = null; }
    document.querySelectorAll(".tour-target").forEach(function (el) { el.classList.remove("tour-target"); });
  }
  function showStep(i) {
    if (i >= tourSteps.length) { endTour(); return; }
    var step = tourSteps[i];
    if (location.pathname !== step.path) {
      set("sessionStorage", "varde-tour-step", String(i));
      location.href = step.path;
      return;
    }
    set("sessionStorage", "varde-tour-step", String(i));
    document.querySelectorAll(".tour-target").forEach(function (el) { el.classList.remove("tour-target"); });
    var target = document.querySelector(step.sel);
    if (target) { target.classList.add("tour-target"); target.scrollIntoView({ block: "center" }); }
    if (!tourBox) {
      tourBox = document.createElement("div");
      tourBox.className = "tour";
      tourBox.setAttribute("role", "dialog");
      tourBox.setAttribute("aria-labelledby", "tour-title");
      tourBox.tabIndex = -1;
      document.body.appendChild(tourBox);
    }
    tourBox.innerHTML = "";
    var count = document.createElement("p"); count.className = "small muted"; count.textContent = "Step " + (i + 1) + " of " + tourSteps.length;
    var h = document.createElement("h2"); h.id = "tour-title"; h.textContent = step.title;
    var p = document.createElement("p"); p.textContent = step.text;
    var actions = document.createElement("div"); actions.className = "actions";
    function button(label, cls, fn) {
      var b = document.createElement("button"); b.type = "button"; b.className = "btn " + cls; b.textContent = label;
      b.addEventListener("click", fn); actions.appendChild(b); return b;
    }
    if (i > 0) { button("Back", "btn--ghost", function () { showStep(i - 1); }); }
    var next = button(i === tourSteps.length - 1 ? "Done" : "Next", "btn--primary", function () { showStep(i + 1); });
    button("End tour", "btn--ghost", endTour);
    tourBox.append(count, h, p, actions);
    next.focus();
  }
  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest("[data-tour-start]")) { showStep(0); }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && tourBox) { endTour(); }
  });
  var resume = get("sessionStorage", "varde-tour-step");
  if (resume !== null && /^\d+$/.test(resume)) {
    var at = parseInt(resume, 10);
    // Resume only where the step belongs and only when signed in: a
    // redirect (an expired session to /login) must not navigate again.
    if (at < tourSteps.length && tourSteps[at].path === location.pathname && document.querySelector("[data-tour-start]")) {
      showStep(at);
    } else {
      set("sessionStorage", "varde-tour-step", null);
    }
  }
  // The tour starts only from its button: a fresh Varde leads through the
  // getting-started steps on the overview instead.

  // Toasts fade out after a while.
  var toast = document.querySelector(".toast");
  if (toast) {
    setTimeout(function () { toast.classList.add("toast--hidden"); }, 6000);
  }
})();
