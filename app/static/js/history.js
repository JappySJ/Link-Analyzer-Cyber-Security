/* ==========================================================================
   LTAT - history page.
   Depends on helpers defined in app.js (esc, apiFetch, showToast, formatDate,
   verdictClass, verdictColor), which is loaded first by base.html.
   ========================================================================== */

const PAGE_SIZE = 20;

const state = {
  offset: 0,
  verdict: "all",
  search: "",
  sortKey: "created_at",
  sortDir: "desc",
  total: 0,
  items: [],
  expandedId: null
};

let searchDebounce = null;

/* ------------------------------- rendering ------------------------------ */

function emptyStateHtml(isFiltered) {
  return `
    <div class="empty-state" style="padding: var(--s-8) var(--s-4);">
      <svg width="86" height="86" viewBox="0 0 120 120" fill="none" aria-hidden="true">
        <circle cx="60" cy="60" r="42" stroke="currentColor" stroke-width="2" opacity="0.18"/>
        <circle cx="60" cy="60" r="30" stroke="currentColor" stroke-width="2" opacity="0.10"/>
        <path d="M46 58h28M46 68h18" stroke="currentColor" stroke-width="2.4"
              stroke-linecap="round" opacity="0.45"/>
        <path d="M52 44a8 8 0 0 1 16 0v4H52v-4Z" stroke="currentColor" stroke-width="2.4"
              stroke-linejoin="round" opacity="0.45"/>
        <path d="M88 88l16 16" stroke="currentColor" stroke-width="3" stroke-linecap="round" opacity="0.3"/>
        <circle cx="78" cy="78" r="14" stroke="currentColor" stroke-width="3" opacity="0.3"/>
      </svg>
      <div class="empty-title">${isFiltered ? "No scans match your filter" : "No scans yet"}</div>
      <p class="empty-text">
        ${isFiltered
          ? "Try a different verdict tab or clear the search box."
          : 'Analyse your first URL on the <a href="/">Analyze</a> page and it will appear here.'}
      </p>
    </div>`;
}

/** Sort the current page client-side (the server always returns newest first). */
function sortItems(items) {
  const key = state.sortKey;
  const direction = state.sortDir === "asc" ? 1 : -1;
  return [...items].sort((a, b) => {
    let left = a[key];
    let right = b[key];
    if (key === "final_score") {
      left = Number(left) || 0;
      right = Number(right) || 0;
    } else {
      left = String(left || "").toLowerCase();
      right = String(right || "").toLowerCase();
    }
    if (left < right) return -1 * direction;
    if (left > right) return 1 * direction;
    return 0;
  });
}

function reasonsHtml(reasons) {
  if (!reasons || !reasons.length) {
    return '<p style="font-size:13px; color:var(--text-dim);">No heuristic rules triggered for this URL.</p>';
  }
  return reasons.map(reason => `
    <div class="reason">
      <span class="sev-dot sev-${esc(reason.severity)}"></span>
      <div class="reason-body">
        <div class="reason-msg">${esc(reason.message)}</div>
        <div class="reason-rule">${esc(reason.rule)}</div>
      </div>
      <span class="points-chip">+${esc(reason.points)}</span>
    </div>`).join("");
}

function detailHtml(row) {
  const cert = row.cert_info || {};
  const ml = row.ml_probability === null || row.ml_probability === undefined
    ? "not available"
    : (row.ml_probability * 100).toFixed(1) + "%";

  const certLine = cert.status === "ok"
    ? `${esc(cert.issuer_org || cert.issuer_cn || "unknown issuer")} · ${esc(cert.tls_version || "-")}
       · chain ${cert.chain_trusted ? "trusted" : "NOT trusted"}`
    : esc(cert.status || "not retrieved");

  return `
    <div class="detail-inner">
      <div class="meta-strip" style="padding:0; border:none; margin-bottom:var(--s-4);">
        <div class="meta-item"><div class="meta-key">Heuristic</div><div class="meta-val">${Number(row.heuristic_score || 0).toFixed(0)}/100</div></div>
        <div class="meta-item"><div class="meta-key">ML probability</div><div class="meta-val">${esc(ml)}</div></div>
        <div class="meta-item"><div class="meta-key">Certificate</div><div class="meta-val">${certLine}</div></div>
      </div>
      <div class="section-title" style="margin-bottom:var(--s-2);">Why this verdict</div>
      ${reasonsHtml(row.reasons)}
    </div>`;
}

function render() {
  const tbody = document.getElementById("historyBody");
  const emptyBox = document.getElementById("emptyState");
  const pagination = document.getElementById("pagination");
  const tableWrap = document.querySelector(".table-wrap");

  if (!state.items.length) {
    tableWrap.hidden = true;
    emptyBox.hidden = false;
    emptyBox.innerHTML = emptyStateHtml(state.verdict !== "all" || Boolean(state.search));
    pagination.hidden = true;
    return;
  }

  tableWrap.hidden = false;
  emptyBox.hidden = true;

  tbody.innerHTML = sortItems(state.items).map(row => {
    const isOpen = state.expandedId === row.id;
    const main = `
      <tr data-id="${row.id}" tabindex="0" role="button"
          aria-expanded="${isOpen}" aria-label="Show details for ${esc(row.url)}">
        <td class="url-cell" title="${esc(row.url)}">${esc(row.url)}</td>
        <td><span class="verdict-pill ${verdictClass(row.verdict)}">${esc(row.verdict)}</span></td>
        <td class="score-cell" style="color:${verdictColor(row.verdict)}">${Number(row.final_score).toFixed(0)}</td>
        <td class="date-cell">${formatDate(row.created_at)}</td>
      </tr>`;
    const detail = isOpen
      ? `<tr class="detail-row"><td colspan="4">${detailHtml(row)}</td></tr>`
      : "";
    return main + detail;
  }).join("");

  // Row click / keyboard toggles the stored reasons.
  tbody.querySelectorAll("tr[data-id]").forEach(tr => {
    const toggle = () => {
      const id = Number(tr.dataset.id);
      state.expandedId = state.expandedId === id ? null : id;
      render();
    };
    tr.addEventListener("click", toggle);
    tr.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });
  });

  // Pagination
  const totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  const currentPage = Math.floor(state.offset / PAGE_SIZE) + 1;
  pagination.hidden = state.total <= PAGE_SIZE;
  document.getElementById("pageInfo").textContent =
    `Page ${currentPage} of ${totalPages} · ${state.total} scan${state.total === 1 ? "" : "s"}`;
  document.getElementById("prevBtn").disabled = state.offset === 0;
  document.getElementById("nextBtn").disabled = state.offset + PAGE_SIZE >= state.total;
}

/* --------------------------------- data --------------------------------- */

async function loadCounts() {
  try {
    const stats = await apiFetch("/api/stats");
    const verdicts = stats.verdicts || {};
    document.getElementById("countAll").textContent = stats.total_scans || 0;
    document.getElementById("countSafe").textContent = verdicts.Safe || 0;
    document.getElementById("countSuspicious").textContent = verdicts.Suspicious || 0;
    document.getElementById("countMalicious").textContent = verdicts.Malicious || 0;
  } catch (error) {
    /* The counts are decorative; a failure here must not break the table. */
  }
}

async function loadHistory() {
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offset });
  if (state.verdict !== "all") params.set("verdict", state.verdict);
  if (state.search) params.set("search", state.search);

  try {
    const data = await apiFetch("/api/history?" + params.toString());
    state.items = data.items || [];
    state.total = data.total || 0;

    // If a filter change left us past the end, step back to the last page.
    if (state.offset > 0 && state.offset >= state.total) {
      state.offset = Math.max(0, (Math.ceil(state.total / PAGE_SIZE) - 1) * PAGE_SIZE);
      return loadHistory();
    }
    render();
  } catch (error) {
    showToast(error.message, "error");
    document.getElementById("historyBody").innerHTML =
      `<tr><td colspan="4" style="text-align:center; color:var(--text-dim); padding:var(--s-6);">
         Could not load history.</td></tr>`;
  }
}

async function refresh() {
  startNavProgress();
  try {
    await Promise.all([loadHistory(), loadCounts()]);
  } finally {
    finishNavProgress();
  }
}

/* -------------------------------- wiring -------------------------------- */

document.addEventListener("DOMContentLoaded", () => {
  refresh();

  // Verdict tabs
  document.querySelectorAll(".tab[data-verdict]").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(other => {
        other.classList.remove("is-active");
        other.setAttribute("aria-selected", "false");
      });
      tab.classList.add("is-active");
      tab.setAttribute("aria-selected", "true");
      state.verdict = tab.dataset.verdict;
      state.offset = 0;
      state.expandedId = null;
      loadHistory();
    });
  });

  // Debounced search so we do not fire a request per keystroke.
  document.getElementById("searchInput").addEventListener("input", event => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => {
      state.search = event.target.value.trim();
      state.offset = 0;
      state.expandedId = null;
      loadHistory();
    }, 280);
  });

  // Sortable headers
  document.querySelectorAll("th.sortable").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = key === "created_at" || key === "final_score" ? "desc" : "asc";
      }
      document.querySelectorAll("th.sortable").forEach(other => {
        other.classList.remove("is-sorted");
        other.querySelector(".sort-arrow").innerHTML = "&#9650;&#9660;";
      });
      th.classList.add("is-sorted");
      th.querySelector(".sort-arrow").innerHTML = state.sortDir === "asc" ? "&#9650;" : "&#9660;";
      render();
    });
  });

  // Pagination
  document.getElementById("prevBtn").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - PAGE_SIZE);
    state.expandedId = null;
    loadHistory();
  });
  document.getElementById("nextBtn").addEventListener("click", () => {
    state.offset += PAGE_SIZE;
    state.expandedId = null;
    loadHistory();
  });

  // Clear-all with a custom modal
  const modal = document.getElementById("confirmModal");
  const openModal = () => {
    modal.hidden = false;
    document.getElementById("modalCancel").focus();
  };
  const closeModal = () => { modal.hidden = true; };

  document.getElementById("clearBtn").addEventListener("click", () => {
    if (!state.total) {
      showToast("There is no history to clear.", "info", 3000);
      return;
    }
    openModal();
  });
  document.getElementById("modalCancel").addEventListener("click", closeModal);
  modal.addEventListener("click", event => { if (event.target === modal) closeModal(); });
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && !modal.hidden) closeModal();
  });

  document.getElementById("modalConfirm").addEventListener("click", async () => {
    try {
      const data = await apiFetch("/api/history", { method: "DELETE" });
      showToast(data.message, "success", 3500);
      state.offset = 0;
      state.expandedId = null;
      await refresh();
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      closeModal();
    }
  });
});
