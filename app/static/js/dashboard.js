/* ==========================================================================
   LTAT - dashboard page.
   Chart.js is loaded from a CDN in dashboard.html. If there is no internet the
   library will be missing, so every chart call is guarded and falls back to a
   readable message instead of a broken page.
   ========================================================================== */

const COLORS = {
  safe: "#10B981",
  suspicious: "#F59E0B",
  malicious: "#EF4444",
  accent: "#22D3EE",
  text: "#8A97A8",
  grid: "rgba(255,255,255,0.06)",
  surface: "#161E29",
  border: "rgba(255,255,255,0.12)"
};

let verdictChart = null;
let dailyChart = null;

/* ----------------------------- shared theme ----------------------------- */

function applyChartDefaults() {
  if (typeof Chart === "undefined") return;
  Chart.defaults.font.family =
    "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
  Chart.defaults.font.size = 12;
  Chart.defaults.color = COLORS.text;
}

/** Tooltip styling shared by both charts. */
function tooltipStyle() {
  return {
    backgroundColor: COLORS.surface,
    titleColor: "#E6EDF6",
    bodyColor: "#E6EDF6",
    borderColor: COLORS.border,
    borderWidth: 1,
    padding: 10,
    cornerRadius: 8,
    displayColors: true,
    boxPadding: 4
  };
}

function emptyChartHtml(title, text) {
  return `
    <div class="empty-state" style="height:100%; display:grid; place-content:center; padding:var(--s-4);">
      <svg width="60" height="60" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.4" style="margin:0 auto var(--s-3);" aria-hidden="true">
        <path d="M3 3v18h18" stroke-linecap="round"/>
        <path d="M7 15l4-4 3 3 5-6" stroke-linecap="round" stroke-linejoin="round" opacity="0.5"/>
      </svg>
      <div class="empty-title">${esc(title)}</div>
      <p class="empty-text">${esc(text)}</p>
    </div>`;
}

/* --------------------------- count-up animation ------------------------- */

function countUp(element, target) {
  const value = Number(target) || 0;
  if (prefersReducedMotion()) {
    element.textContent = value;
    return;
  }
  const duration = 850;
  const start = performance.now();
  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);   // easeOutCubic
    element.textContent = Math.round(value * eased);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* -------------------------------- charts -------------------------------- */

function renderVerdictChart(verdicts) {
  const canvas = document.getElementById("verdictChart");
  const empty = document.getElementById("verdictEmpty");
  const total = (verdicts.Safe || 0) + (verdicts.Suspicious || 0) + (verdicts.Malicious || 0);

  if (!total) {
    canvas.hidden = true;
    empty.hidden = false;
    empty.innerHTML = emptyChartHtml("No data yet", "Analyse a few URLs and the distribution will appear here.");
    return;
  }
  if (typeof Chart === "undefined") {
    canvas.hidden = true;
    empty.hidden = false;
    empty.innerHTML = emptyChartHtml("Charts unavailable offline",
      "Chart.js loads from a CDN. The numbers above are still accurate.");
    return;
  }

  canvas.hidden = false;
  empty.hidden = true;
  if (verdictChart) verdictChart.destroy();

  verdictChart = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Safe", "Suspicious", "Malicious"],
      datasets: [{
        data: [verdicts.Safe || 0, verdicts.Suspicious || 0, verdicts.Malicious || 0],
        backgroundColor: [COLORS.safe, COLORS.suspicious, COLORS.malicious],
        borderColor: "#121821",
        borderWidth: 3,
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "62%",
      plugins: {
        legend: {
          position: "bottom",
          labels: { padding: 16, usePointStyle: true, pointStyle: "circle", boxWidth: 8 }
        },
        tooltip: {
          ...tooltipStyle(),
          callbacks: {
            label(context) {
              const value = context.parsed;
              const percent = total ? ((value / total) * 100).toFixed(1) : 0;
              return ` ${context.label}: ${value} (${percent}%)`;
            }
          }
        }
      }
    }
  });
}

function renderDailyChart(series) {
  const canvas = document.getElementById("dailyChart");
  const empty = document.getElementById("dailyEmpty");
  const hasData = series.some(point => point.count > 0);

  if (!hasData) {
    canvas.hidden = true;
    empty.hidden = false;
    empty.innerHTML = emptyChartHtml("No scans in the last 14 days",
      "Your scanning activity over time will be plotted here.");
    return;
  }
  if (typeof Chart === "undefined") {
    canvas.hidden = true;
    empty.hidden = false;
    empty.innerHTML = emptyChartHtml("Charts unavailable offline",
      "Chart.js loads from a CDN. The numbers above are still accurate.");
    return;
  }

  canvas.hidden = false;
  empty.hidden = true;
  if (dailyChart) dailyChart.destroy();

  // Short axis labels: '2026-08-23' -> 'Aug 23'
  const labels = series.map(point => {
    const date = new Date(point.date + "T00:00:00Z");
    return isNaN(date.getTime())
      ? point.date
      : date.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
  });

  const context = canvas.getContext("2d");
  const gradient = context.createLinearGradient(0, 0, 0, 260);
  gradient.addColorStop(0, "rgba(34, 211, 238, 0.28)");
  gradient.addColorStop(1, "rgba(34, 211, 238, 0.00)");

  const maximum = Math.max(...series.map(point => point.count));

  dailyChart = new Chart(canvas, {
    type: "line",
    data: {
      labels: labels,
      datasets: [{
        label: "Scans",
        data: series.map(point => point.count),
        borderColor: COLORS.accent,
        backgroundColor: gradient,
        borderWidth: 2,
        fill: true,
        tension: 0.35,
        pointRadius: 3,
        pointBackgroundColor: COLORS.accent,
        pointBorderColor: "#0A0E14",
        pointBorderWidth: 2,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          ...tooltipStyle(),
          callbacks: {
            label(item) {
              return ` ${item.parsed.y} scan${item.parsed.y === 1 ? "" : "s"}`;
            }
          }
        }
      },
      scales: {
        x: {
          grid: { display: false },
          border: { color: COLORS.grid },
          ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 }
        },
        y: {
          beginAtZero: true,
          // Force whole-number ticks: half a scan does not exist.
          suggestedMax: Math.max(4, maximum + 1),
          grid: { color: COLORS.grid, drawTicks: false },
          border: { display: false },
          ticks: { precision: 0, padding: 8 }
        }
      }
    }
  });
}

/* ------------------------------ recent list ----------------------------- */

function renderRecent(recent) {
  const list = document.getElementById("recentList");
  if (!recent || !recent.length) {
    list.innerHTML =
      '<p style="color:var(--text-dim); font-size:13px;">No scans yet. ' +
      '<a href="/">Analyse a URL</a> to get started.</p>';
    return;
  }
  list.innerHTML = recent.map(row => `
    <div class="recent-item">
      <span class="verdict-pill ${verdictClass(row.verdict)}">${esc(row.verdict)}</span>
      <span class="recent-url" title="${esc(row.url)}">${esc(row.url)}</span>
      <span class="recent-score" style="color:${verdictColor(row.verdict)}">${Number(row.final_score).toFixed(0)}</span>
      <span class="date-cell">${formatDate(row.created_at)}</span>
    </div>`).join("");
}

/* --------------------------- model information -------------------------- */

async function renderModelInfo() {
  const box = document.getElementById("modelInfo");
  try {
    const metrics = await apiFetch("/api/metrics");
    if (!metrics || !metrics.selected_model) {
      box.innerHTML =
        '<p style="color:var(--text-dim); font-size:13px;">' +
        "No model trained yet. Run <code>python -m app.ml.train</code>.</p>";
      return;
    }
    const selected = (metrics.models || []).find(m => m.model === metrics.selected_model) || {};
    const items = [
      ["Model", metrics.selected_model],
      ["Accuracy", selected.accuracy !== undefined ? (selected.accuracy * 100).toFixed(2) + "%" : "-"],
      ["F1 score", selected.f1 !== undefined ? selected.f1.toFixed(4) : "-"],
      ["ROC-AUC", selected.roc_auc !== undefined ? selected.roc_auc.toFixed(4) : "-"],
      ["CV F1 (5-fold)", selected.cv_f1_mean !== undefined ? selected.cv_f1_mean.toFixed(4) : "-"],
      ["Training rows", metrics.dataset_rows || "-"],
      ["Features", metrics.n_features || "-"]
    ];
    box.innerHTML = items.map(([key, value]) => `
      <div class="meta-item">
        <div class="meta-key">${esc(key)}</div>
        <div class="meta-val">${esc(value)}</div>
      </div>`).join("");
  } catch (error) {
    box.innerHTML =
      '<p style="color:var(--text-dim); font-size:13px;">Model information unavailable.</p>';
  }
}

/* -------------------------------- loader -------------------------------- */

async function loadDashboard() {
  try {
    const stats = await apiFetch("/api/stats?days=14");
    const verdicts = stats.verdicts || {};
    const total = stats.total_scans || 0;

    countUp(document.getElementById("statTotal"), total);
    countUp(document.getElementById("statSafe"), verdicts.Safe || 0);
    countUp(document.getElementById("statSuspicious"), verdicts.Suspicious || 0);
    countUp(document.getElementById("statMalicious"), verdicts.Malicious || 0);

    document.getElementById("statAvg").textContent =
      total ? "Average score " + stats.average_score.toFixed(1) + "/100" : "No scans yet";

    const percent = value => (total ? ((value / total) * 100).toFixed(0) + "% of all scans" : "—");
    document.getElementById("statSafePct").textContent = percent(verdicts.Safe || 0);
    document.getElementById("statSuspiciousPct").textContent = percent(verdicts.Suspicious || 0);
    document.getElementById("statMaliciousPct").textContent = percent(verdicts.Malicious || 0);

    renderVerdictChart(verdicts);
    renderDailyChart(stats.scans_per_day || []);
    renderRecent(stats.recent || []);
  } catch (error) {
    showToast(error.message, "error");
  }
}

document.addEventListener("DOMContentLoaded", () => {
  applyChartDefaults();
  startNavProgress();
  Promise.all([loadDashboard(), renderModelInfo()])
    .finally(finishNavProgress);
});
