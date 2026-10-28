/* ==========================================================================
   LTAT - shared frontend helpers + the analyze page.
   Vanilla JavaScript. No framework, no bundler, no dependencies.
   ========================================================================== */

/* --------------------------------------------------------------------------
   Small shared utilities (also used by history.js and dashboard.js)
   -------------------------------------------------------------------------- */

/** Escape text before putting it in innerHTML - a URL may contain < or ". */
function esc(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Map a verdict to its CSS modifier class. */
function verdictClass(verdict) {
  switch (verdict) {
    case "Safe":       return "v-safe";
    case "Suspicious": return "v-suspicious";
    case "Malicious":  return "v-malicious";
    default:           return "v-suspicious";
  }
}

/** Map a verdict to its CSS custom property. */
function verdictColor(verdict) {
  switch (verdict) {
    case "Safe":       return "var(--safe)";
    case "Suspicious": return "var(--suspicious)";
    case "Malicious":  return "var(--malicious)";
    default:           return "var(--text-muted)";
  }
}

/** Format an ISO-8601 UTC timestamp in the viewer's local timezone. */
function formatDate(iso) {
  if (!iso) return "-";
  // Timestamps are stored as UTC. If the string carries no zone marker, add
  // 'Z' so the browser does not read it as local time and shift the clock.
  const normalised = /[Z+]|-\d{2}:\d{2}$/.test(iso) ? iso : iso + "Z";
  const date = new Date(normalised);
  if (isNaN(date.getTime())) return esc(iso);
  return date.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit"
  });
}

/** True when the user asked the OS to reduce motion. */
function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/* --------------------------------------------------------------------------
   Toasts - errors never use alert()
   -------------------------------------------------------------------------- */

function showToast(message, kind = "error", timeout = 6000) {
  const stack = document.getElementById("toastStack");
  if (!stack) return;

  const toast = document.createElement("div");
  toast.className = "toast" + (kind === "error" ? "" : " is-" + kind);
  toast.setAttribute("role", "alert");
  toast.innerHTML =
    '<span class="toast-msg">' + esc(message) + "</span>" +
    '<button class="toast-close" aria-label="Dismiss notification">&times;</button>';

  const dismiss = () => {
    toast.classList.add("is-out");
    setTimeout(() => toast.remove(), 220);
  };
  toast.querySelector(".toast-close").addEventListener("click", dismiss);
  stack.appendChild(toast);
  if (timeout > 0) setTimeout(dismiss, timeout);
}

/* --------------------------------------------------------------------------
   API helper - turns any failure into a readable Error message
   -------------------------------------------------------------------------- */

async function apiFetch(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch (networkError) {
    throw new Error("Could not reach the LTAT server. Is it still running?");
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch (parseError) {
    payload = null;
  }

  if (!response.ok) {
    const detail = payload && payload.detail
      ? payload.detail
      : "Request failed with status " + response.status;
    throw new Error(detail);
  }
  return payload;
}

/* --------------------------------------------------------------------------
   Navigation / request progress bar
   -------------------------------------------------------------------------- */

let navTimer = null;

/** Start the top progress bar creeping towards 90%. */
function startNavProgress() {
  const bar = document.getElementById("navProgress");
  if (!bar) return;
  clearInterval(navTimer);
  bar.classList.remove("is-done");
  bar.classList.add("is-active");
  bar.setAttribute("aria-hidden", "false");

  let width = 8;
  bar.style.width = width + "%";
  // Ease towards 90% and stop: the bar must never claim to be finished while
  // the request is still in flight.
  navTimer = setInterval(() => {
    width += (90 - width) * 0.12;
    bar.style.width = width.toFixed(1) + "%";
  }, 180);
}

/** Snap the bar to 100% and fade it out. */
function finishNavProgress() {
  const bar = document.getElementById("navProgress");
  if (!bar) return;
  clearInterval(navTimer);
  bar.style.width = "100%";
  bar.classList.add("is-done");
  setTimeout(() => {
    bar.classList.remove("is-active", "is-done");
    bar.style.width = "0";
    bar.setAttribute("aria-hidden", "true");
  }, 340);
}

/* --------------------------------------------------------------------------
   Global keyboard shortcuts
   -------------------------------------------------------------------------- */

function initKeyboardShortcuts() {
  document.addEventListener("keydown", event => {
    const target = event.target;
    const typing = target && (
      target.tagName === "INPUT" ||
      target.tagName === "TEXTAREA" ||
      target.tagName === "SELECT" ||
      target.isContentEditable
    );

    // "/" focuses the URL field - but never while the user is already typing
    // in a field, and never when a modifier is held (so Ctrl+/ still works).
    if (event.key === "/" && !typing && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const input = document.getElementById("urlInput") || document.getElementById("searchInput");
      if (input) {
        event.preventDefault();
        input.focus();
        input.select();
      }
      return;
    }

    // Escape clears and blurs whichever field is focused.
    if (event.key === "Escape" && typing && target.type !== "checkbox") {
      target.blur();
    }
  });
}

/* --------------------------------------------------------------------------
   Health pill in the header
   -------------------------------------------------------------------------- */

async function refreshHealth() {
  const dot = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  const pill = document.getElementById("statusPill");
  if (!dot || !text) return;

  try {
    const health = await apiFetch("/api/health");

    // Threat-intelligence status is intentionally not surfaced in the UI.
    // /api/health still reports it and the backend still uses it.
    dot.className = "status-dot " + (health.model_loaded ? "is-ok" : "is-partial");
    text.textContent = health.model_loaded ? "ML on" : "ML off";

    if (pill) {
      pill.title =
        "Model: " + (health.model_loaded ? health.model_name : "not trained") +
        "\nDatabase: " + (health.db_ok ? "ok" : "unavailable") +
        "\nVersion: " + health.version;
    }
  } catch (error) {
    dot.className = "status-dot is-down";
    text.textContent = "Offline";
    if (pill) pill.title = "Cannot reach the server.";
  }
}

/* ==========================================================================
   Analyze page
   ========================================================================== */

/** Staged status messages shown while the request is in flight. */
const STAGES = [
  "Extracting URL features…",
  "Inspecting TLS certificate…",
  "Running ML model…",
  "Checking threat intelligence…",
  "Fusing hybrid verdict…"
];

let stageTimer = null;
let currentResult = null;

function startStages() {
  const label = document.getElementById("stageText");
  if (!label) return;
  let index = 0;
  label.textContent = STAGES[0];
  stageTimer = setInterval(() => {
    index = (index + 1) % STAGES.length;
    label.textContent = STAGES[index];
  }, 1300);
}

function stopStages() {
  if (stageTimer) { clearInterval(stageTimer); stageTimer = null; }
}

function setLoading(isLoading) {
  const button = document.getElementById("analyzeBtn");
  const label = document.getElementById("btnLabel");
  const loading = document.getElementById("loadingState");
  const result = document.getElementById("resultState");

  if (isLoading) {
    button.disabled = true;
    label.innerHTML = '<span class="spinner"></span>';
    button.setAttribute("aria-busy", "true");
    result.hidden = true;
    loading.hidden = false;
    loading.setAttribute("aria-hidden", "false");
    startStages();
  } else {
    button.disabled = false;
    label.textContent = "Analyze";
    button.removeAttribute("aria-busy");
    loading.hidden = true;
    loading.setAttribute("aria-hidden", "true");
    stopStages();
  }
}

/* ---------------------------- report builders --------------------------- */

function buildGauge(score, verdict) {
  // r=64 -> circumference 2*pi*64 ~= 402.12. The stroke is drawn by animating
  // stroke-dashoffset from the full circumference down to the target value.
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  return `
    <div class="gauge-wrap">
      <div class="gauge">
        <svg width="148" height="148" viewBox="0 0 148 148" role="img"
             aria-label="Risk score ${Math.round(score)} out of 100">
          <circle class="gauge-track" cx="74" cy="74" r="${radius}"></circle>
          <circle class="gauge-fill" id="gaugeFill" cx="74" cy="74" r="${radius}"
                  stroke="${verdictColor(verdict)}"
                  stroke-dasharray="${circumference.toFixed(2)}"
                  stroke-dashoffset="${circumference.toFixed(2)}"></circle>
        </svg>
        <div class="gauge-center">
          <div class="gauge-value" id="gaugeValue" style="color:${verdictColor(verdict)}">0</div>
          <div class="gauge-label">Risk score</div>
        </div>
      </div>
    </div>`;
}

/** Animate the gauge sweep and count the number up in sync. */
function animateGauge(score) {
  const fill = document.getElementById("gaugeFill");
  const value = document.getElementById("gaugeValue");
  if (!fill || !value) return;

  const circumference = 2 * Math.PI * 64;
  const target = Math.max(0, Math.min(100, Number(score) || 0));
  const offset = circumference * (1 - target / 100);

  if (prefersReducedMotion()) {
    fill.style.strokeDashoffset = offset.toFixed(2);
    value.textContent = Math.round(target);
    return;
  }

  // requestAnimationFrame lets the browser apply the initial offset before the
  // transition target is set, otherwise the CSS transition never runs.
  requestAnimationFrame(() => {
    fill.style.strokeDashoffset = offset.toFixed(2);
  });

  const duration = 900;
  const start = performance.now();
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    // easeOutCubic, matching the CSS easing of the stroke.
    const eased = 1 - Math.pow(1 - progress, 3);
    value.textContent = Math.round(target * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// NOTE ON VIRUSTOTAL
// ------------------
// The VirusTotal card was deliberately removed from this report. The lookup
// still runs on every scan and still contributes its 25% share to the final
// score (see hybrid.py) - it is simply not shown to the user. The raw figures
// remain available in the JSON payload (data.vt) and via GET /api/analyze.
function buildSubscores(data) {
  const heuristic = data.scores.heuristic || 0;
  const mlProb = data.scores.ml_probability;

  // --- ML card ---
  let mlValue, mlNote, mlBar;
  if (mlProb === null || mlProb === undefined) {
    mlValue = "&mdash;";
    mlNote = "Model not trained yet — run <code>python -m app.ml.train</code>";
    mlBar = 0;
  } else {
    mlValue = (mlProb * 100).toFixed(1) + "%";
    mlNote = "Probability this URL is phishing" +
             (data.ml_model ? " (" + esc(data.ml_model) + ")" : "");
    mlBar = mlProb * 100;
  }


  return `
    <div class="subscores">
      <div class="subscore">
        <div class="subscore-head">
          <span class="subscore-name">Heuristic</span>
          <span class="subscore-val" style="color:${verdictColor(data.verdict)}">${heuristic.toFixed(0)}</span>
        </div>
        <div class="subscore-note">${data.reasons.length} rule${data.reasons.length === 1 ? "" : "s"} triggered</div>
        <div class="bar"><div class="bar-fill" data-width="${heuristic}" style="background:${verdictColor(data.verdict)}"></div></div>
      </div>

      <div class="subscore">
        <div class="subscore-head">
          <span class="subscore-name">ML confidence</span>
          <span class="subscore-val" style="color:var(--accent)">${mlValue}</span>
        </div>
        <div class="subscore-note">${mlNote}</div>
        <div class="bar"><div class="bar-fill" data-width="${mlBar}" style="background:var(--accent)"></div></div>
      </div>
    </div>`;
}

function buildMetaStrip(data) {
  const meta = data.metadata || {};
  const ip = (data.ip_addresses && data.ip_addresses.length)
    ? data.ip_addresses[0]
    : "not resolved";
  const items = [
    ["Hostname", meta.hostname || "-"],
    ["Resolved IP", ip],
    ["TLD", meta.tld || "-"],
    ["Domain entropy", (meta.domain_entropy !== undefined ? meta.domain_entropy : "-") + " bits"],
    ["URL length", (meta.url_length || 0) + " chars"]
  ];
  return `
    <div class="meta-strip">
      ${items.map(([key, value]) => `
        <div class="meta-item">
          <div class="meta-key">${esc(key)}</div>
          <div class="meta-val" title="${esc(value)}">${esc(value)}</div>
        </div>`).join("")}
    </div>`;
}

function yesNoPill(condition, goodWhenTrue = true) {
  const isGood = goodWhenTrue ? condition : !condition;
  return `<span class="pill ${isGood ? "pill-yes" : "pill-no"}">${condition ? "Yes" : "No"}</span>`;
}

function buildCertSection(cert) {
  if (!cert || cert.status !== "ok") {
    const reasons = {
      unreachable: "The host did not answer on port 443. It may be offline, parked or already taken down.",
      no_tls: "The host answered but did not complete a TLS handshake.",
      skipped: "The certificate check was skipped for this scan.",
      error: cert && cert.error ? cert.error : "The certificate could not be inspected."
    };
    const message = reasons[cert ? cert.status : "error"] || reasons.error;
    return `
      <div class="cert-section">
        <div class="section-title">TLS certificate</div>
        <div class="empty-state">
          <svg width="46" height="46" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4">
            <rect x="3" y="11" width="18" height="10" rx="2"/>
            <path d="M7 11V7a5 5 0 0 1 9.2-2.7" stroke-linecap="round"/>
            <path d="M3 3l18 18" stroke-linecap="round" opacity="0.5"/>
          </svg>
          <div class="empty-title">No certificate retrieved</div>
          <p class="empty-text">${esc(message)}</p>
        </div>
      </div>`;
  }

  const fingerprint = cert.sha256_fingerprint || "";
  const shortFingerprint = fingerprint.length > 32 ? fingerprint.slice(0, 32) + "…" : fingerprint;

  let expiry = "-";
  if (typeof cert.days_to_expiry === "number") {
    expiry = cert.days_to_expiry < 0
      ? `<span class="pill pill-no">expired ${Math.abs(cert.days_to_expiry)} days ago</span>`
      : `${cert.days_to_expiry} days`;
  }

  const rows = [
    ["Issuer", esc(cert.issuer_org || cert.issuer_cn || "unknown") +
      (cert.is_free_ca ? ' <span class="pill pill-warn">free CA</span>' : "")],
    ["Subject", esc(cert.subject_cn || "-") + (cert.subject_org ? " &middot; " + esc(cert.subject_org) : "")],
    ["Valid from", esc(cert.valid_from || "-")],
    ["Valid to", esc(cert.valid_to || "-")],
    ["Days to expiry", expiry],
    ["Total validity", cert.validity_days !== null && cert.validity_days !== undefined ? cert.validity_days + " days" : "-"],
    ["TLS version", esc(cert.tls_version || "-")],
    ["Cipher", esc(cert.cipher || "-")],
    ["Chain trusted", yesNoPill(cert.chain_trusted, true)],
    ["Hostname match", yesNoPill(cert.hostname_match, true)],
    ["Self-signed", yesNoPill(cert.self_signed, false)],
    ["SAN entries", String(cert.san_count || 0)],
    ["SHA-256", `<span class="mono">${esc(shortFingerprint)}</span>
       <button class="copy-btn" type="button" data-copy="${esc(fingerprint)}"
               aria-label="Copy full SHA-256 fingerprint">Copy</button>`]
  ];

  return `
    <div class="cert-section">
      <div class="section-title">TLS certificate</div>
      <table class="cert-table">
        <tbody>
          ${rows.map(([key, value]) => `<tr><th scope="row">${esc(key)}</th><td>${value}</td></tr>`).join("")}
        </tbody>
      </table>
    </div>`;
}

function buildReasons(reasons) {
  if (!reasons || !reasons.length) {
    return `
      <div class="reasons-section">
        <div style="padding: var(--s-5);">
          <div class="section-title">Why this verdict</div>
          <div class="empty-state">
            <svg width="46" height="46" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4">
              <path d="M20 6 9 17l-5-5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <div class="empty-title">No heuristic rules triggered</div>
            <p class="empty-text">Nothing in this URL matched any of the phishing patterns LTAT checks for.</p>
          </div>
        </div>
      </div>`;
  }

  // The backend already sorts by points descending.
  const items = reasons.map(reason => `
    <div class="reason">
      <span class="sev-dot sev-${esc(reason.severity)}" title="${esc(reason.severity)}"></span>
      <div class="reason-body">
        <div class="reason-msg">${esc(reason.message)}</div>
        <div class="reason-rule">${esc(reason.rule)} &middot; ${esc(reason.severity)}</div>
      </div>
      <span class="points-chip">+${esc(reason.points)}</span>
    </div>`).join("");

  return `
    <div class="reasons-section">
      <button class="reasons-toggle" id="reasonsToggle" aria-expanded="true" aria-controls="reasonsBody">
        <span class="reasons-title">
          Why this verdict
          <span class="reasons-count">${reasons.length}</span>
        </span>
        <svg class="chevron" width="18" height="18" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="m6 9 6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>
      <div class="reasons-body is-open" id="reasonsBody">
        <div class="reasons-inner">
          <div class="reasons-list">${items}</div>
        </div>
      </div>
    </div>`;
}

/**
 * Small "cached" pill shown when the report came from the in-memory cache
 * instead of a fresh scan. Explains why the result appeared instantly.
 */
function cachedBadge(data) {
  if (!data.cached) return "";
  const age = Number(data.cached_age) || 0;
  const when = age < 60
    ? age + "s ago"
    : Math.floor(age / 60) + "m ago";
  return `
    <span class="cached-badge" title="Served from the 5-minute in-memory cache - no new network requests were made">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="2.4" aria-hidden="true">
        <path d="M12 7v5l3 2" stroke-linecap="round" stroke-linejoin="round"/>
        <circle cx="12" cy="12" r="9"/>
      </svg>
      cached ${esc(when)}
    </span>`;
}

function renderResult(data) {
  currentResult = data;
  const container = document.getElementById("resultState");

  // data.formula names every fused signal (including the threat-intelligence
  // term), so it is not rendered here. The backend still returns it.
  const mlPart = (data.scores.ml_probability === null || data.scores.ml_probability === undefined)
    ? "heuristic rules only"
    : "heuristic rules + ML model";
  const confidenceNote = `${data.confidence}% confidence · ${mlPart}`;

  container.innerHTML = `
    <div class="card fade-in">
      <div class="verdict-head">
        <div class="verdict-meta">
          <span class="verdict-badge ${verdictClass(data.verdict)}">
            ${esc(data.verdict)}
          </span>
          ${cachedBadge(data)}
          <span class="verdict-url" style="margin-top: var(--s-3);">${esc(data.url)}</span>
          <span class="verdict-sub">${esc(confidenceNote)}</span>
        </div>
        ${buildGauge(data.final_score, data.verdict)}
      </div>
      ${buildSubscores(data)}
      ${buildMetaStrip(data)}
      ${buildCertSection(data.certificate)}
      ${buildReasons(data.reasons)}
      <div class="result-actions">
        <button class="btn-ghost" id="copyJsonBtn" type="button">Copy JSON</button>
        <button class="btn-ghost" id="scanAnotherBtn" type="button">Scan another</button>
        <span class="result-time">${formatDate(data.analyzed_at)}</span>
      </div>
    </div>`;

  container.hidden = false;

  // Animate the gauge and the sub-score bars once the DOM exists.
  animateGauge(data.final_score);
  requestAnimationFrame(() => {
    container.querySelectorAll(".bar-fill").forEach(bar => {
      const width = Math.max(0, Math.min(100, parseFloat(bar.dataset.width) || 0));
      bar.style.width = width + "%";
    });
  });

  wireResultActions();
  container.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "nearest" });
}

function wireResultActions() {
  const toggle = document.getElementById("reasonsToggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const body = document.getElementById("reasonsBody");
      const isOpen = body.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(isOpen));
    });
  }

  const copyJson = document.getElementById("copyJsonBtn");
  if (copyJson) {
    copyJson.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2));
        showToast("Full JSON report copied to clipboard.", "success", 3000);
      } catch (error) {
        showToast("Could not access the clipboard. Your browser may block it on http://.", "error");
      }
    });
  }

  const scanAnother = document.getElementById("scanAnotherBtn");
  if (scanAnother) {
    scanAnother.addEventListener("click", () => {
      const input = document.getElementById("urlInput");
      document.getElementById("resultState").hidden = true;
      input.value = "";
      input.focus();
      window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? "auto" : "smooth" });
    });
  }

  document.querySelectorAll(".copy-btn[data-copy]").forEach(button => {
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
        const original = button.textContent;
        button.textContent = "Copied";
        setTimeout(() => { button.textContent = original; }, 1600);
      } catch (error) {
        showToast("Could not access the clipboard.", "error");
      }
    });
  });
}

/* ------------------------------- wiring -------------------------------- */

async function analyzeUrl(url) {
  setLoading(true);
  startNavProgress();
  try {
    const data = await apiFetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });
    renderResult(data);
    if (data.save_error) showToast(data.save_error, "info");
  } catch (error) {
    showToast(error.message, "error");
    document.getElementById("resultState").hidden = true;
  } finally {
    setLoading(false);
    finishNavProgress();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshHealth();
  initKeyboardShortcuts();

  const form = document.getElementById("analyzeForm");
  if (!form) return;   // history/dashboard pages share this file for helpers

  const input = document.getElementById("urlInput");

  form.addEventListener("submit", event => {
    event.preventDefault();
    const url = input.value.trim();
    if (!url) {
      showToast("Please enter a URL to analyze.", "info", 3000);
      input.focus();
      return;
    }
    analyzeUrl(url);
  });

  document.querySelectorAll(".chip[data-url]").forEach(chip => {
    chip.addEventListener("click", () => {
      input.value = chip.dataset.url;
      input.focus();
      analyzeUrl(chip.dataset.url);
    });
  });
});
