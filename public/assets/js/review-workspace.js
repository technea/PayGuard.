(() => {
  "use strict";
  const root = document.getElementById("pg-review-workspace");
  if (!root) return;

  const evidence = [
    { id: "domain", title: "URL / Domain Lexical", detail: "Hostname normalization, Unicode controls, homoglyph and official-domain comparison.", source: "URL Sentinel · local deterministic checks" },
    { id: "contract", title: "Smart Contract Signals", detail: "Provider flags can inform risk, but do not constitute an independent bytecode audit.", source: "GoPlus · provider evidence when a scan is run" },
    { id: "counterparty", title: "Counterparty Reputation", detail: "Address reputation depends on provider coverage and may be incomplete or unavailable.", source: "GoPlus address security · provider evidence when queried" },
    { id: "calldata", title: "Calldata / Permit Analysis", detail: "Current inspector supports approve, transfer and transferFrom selectors. Permit and Permit2 are not currently decoded.", source: "Local calldata inspector · supported selectors only" }
  ];

  root.innerHTML = `
    <div class="pg-workspace-heading">
      <div><p class="pg-eyebrow">ADVISORY INTELLIGENCE / BASE MAINNET</p><h2>Security review workspace</h2><p class="pg-muted">Evidence-first views for transaction impact and independent security checks.</p></div>
      <span class="pg-network"><i></i> CHAIN ID 8453</span>
    </div>
    <div class="pg-review-grid">
      <section class="pg-panel pg-state-panel" aria-labelledby="pg-state-title">
        <div class="pg-panel-head"><div><p class="pg-eyebrow">TRANSACTION IMPACT</p><h3 id="pg-state-title">State diff</h3></div><span class="pg-state-tag">AWAITING SCAN DATA</span></div>
        <div class="pg-diff-columns">
          <div class="pg-diff-side"><span class="pg-diff-label">CONTRACT TARGET</span><strong>—</strong><p>Asset outflow and gas estimates appear after a supported transaction analysis.</p></div>
          <div class="pg-diff-side"><span class="pg-diff-label">POLICY VERDICT</span><strong>—</strong><p>Balance deltas and approval exposure are not inferred without decoded transaction data.</p></div>
        </div>
        <div class="pg-toggle-row" role="group" aria-label="Calldata display mode">
          <button type="button" class="pg-mode-btn is-active" data-mode="summary" aria-pressed="true">Human summary</button>
          <button type="button" class="pg-mode-btn" data-mode="raw" aria-pressed="false">Raw calldata</button>
        </div>
        <div class="pg-mode-content" data-content="summary">No transaction supplied. Run a supported calldata check to see decoded intent and policy findings here.</div>
        <div class="pg-mode-content" data-content="raw" hidden><code>Raw calldata will be shown only when supplied to a scan.</code></div>
      </section>
      <section class="pg-panel pg-trust-panel" aria-labelledby="pg-trust-title">
        <div class="pg-panel-head"><div><p class="pg-eyebrow">FEDERATED EVIDENCE</p><h3 id="pg-trust-title">Trust matrix</h3></div><span class="pg-state-tag">NO ACTIVE SCAN</span></div>
        <div class="pg-trust-list">
          ${evidence.map(item => `<article class="pg-trust-item"><button type="button" class="pg-trust-trigger" aria-expanded="false" aria-controls="pg-evidence-${item.id}"><span class="pg-trust-index">${String(evidence.indexOf(item)+1).padStart(2,"0")}</span><span class="pg-trust-copy"><strong>${item.title}</strong><small>${item.detail}</small></span><span class="pg-unavailable">UNAVAILABLE</span><i class="fa-solid fa-chevron-down pg-chevron" aria-hidden="true"></i></button><div class="pg-evidence" id="pg-evidence-${item.id}" hidden><p>${item.source}</p><small>No timestamp or result is displayed until a real check returns evidence.</small></div></article>`).join("")}
        </div>
        <p class="pg-matrix-note"><i class="fa-solid fa-circle-info"></i> Unavailable means no result is present. It does not mean verified or safe.</p>
      </section>
    </div>
    <section class="pg-panel pg-code-panel" aria-labelledby="pg-code-title">
      <div class="pg-panel-head"><div><p class="pg-eyebrow">INSPECTABLE OUTPUT</p><h3 id="pg-code-title">Policy payload viewer</h3></div><div class="pg-code-actions"><button type="button" data-code-action="format">Format JSON</button><button type="button" data-code-action="copy"><i class="fa-regular fa-copy"></i> Copy</button><button type="button" data-code-action="expand"><i class="fa-solid fa-expand"></i> Expand</button></div></div>
      <p class="pg-muted pg-code-note">Example schema only — no live scan payload is loaded.</p>
      <p class="pg-code-status" role="status" aria-live="polite">Example schema only. No live scan payload is loaded.</p>
      <pre class="pg-code-view" tabindex="0" aria-label="Example policy JSON"><code id="pg-code-content">{ "chainId": 8453, "status": "awaiting_scan", "evidence": [] }</code></pre>
    </section>
  `;

  const codeStatus = root.querySelector(".pg-code-status");
  const codeView = root.querySelector(".pg-code-view");
  const expandButton = root.querySelector('[data-code-action="expand"]');
  const setExpanded = (expanded) => {
    codeView.classList.toggle("is-expanded", expanded);
    document.body.classList.toggle("pg-code-expanded", expanded);
    expandButton.setAttribute("aria-pressed", String(expanded));
    expandButton.innerHTML = expanded ? '<i class="fa-solid fa-compress"></i> Close expanded view' : '<i class="fa-solid fa-expand"></i> Expand';
  };
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && codeView.classList.contains("is-expanded")) setExpanded(false);
  });

  const evidenceCount = new Set();
  window.addEventListener("payguard:evidence-result", (event) => {
    const detail = event.detail || {};
    const id = String(detail.id || "");
    const item = evidence.find(entry => entry.id === id);
    if (!item) return;

    const result = detail.result || {};
    const verdict = String(result.verdict || "UNVERIFIED").toUpperCase();
    const domainVerdicts = {
      EXPECTED_DOMAIN_MATCH: "PASS",
      NO_KNOWN_THREAT: "PASS",
      CAUTION: "REVIEW",
      KNOWN_MALICIOUS: "BLOCK",
      SUSPICIOUS: "BLOCK"
    };
    const mappedVerdict = id === "domain" ? (domainVerdicts[verdict] || verdict) : verdict;
    const allowed = ["PASS", "REVIEW", "BLOCK"];
    const normalized = allowed.includes(mappedVerdict) ? mappedVerdict : "UNVERIFIED";
    const row = root.querySelector('[aria-controls="pg-evidence-' + id + '"]');
    if (!row) return;

    const status = row.querySelector(".pg-unavailable");
    const panel = root.querySelector("#pg-evidence-" + id);
    if (status) {
      status.textContent = normalized;
      status.className = "pg-unavailable pg-evidence-status pg-evidence-status--" + normalized.toLowerCase();
    }
    if (panel) {
      const source = document.createElement("p");
      source.textContent = item.source + " · " + String(detail.subject || "Subject not supplied");
      const explanation = document.createElement("small");
      const findings = Array.isArray(result.findings) ? result.findings : [];
      const reasons = Array.isArray(result.reasons) ? result.reasons : [];
      const messages = findings.map(entry => entry && entry.message).filter(Boolean);
      const notes = messages.length ? messages : reasons;
      explanation.textContent = notes.length
        ? notes.map(String).join(" · ")
        : (result.summary || result.recommendation || (normalized === "UNVERIFIED" ? "The provider returned no usable verdict. Treat this check as inconclusive." : "Provider returned a verdict; no additional finding details were supplied."));
      panel.replaceChildren(source, explanation);
    }
    evidenceCount.add(id);
    const trustTag = root.querySelector(".pg-trust-panel .pg-state-tag");
    if (trustTag) trustTag.textContent = evidenceCount.size + " / 4 EVIDENCE CHECKS LOADED";
    const note = root.querySelector(".pg-matrix-note");
    if (note) note.textContent = "Evidence is provider-specific and time-bound. A PASS means no configured flags were returned; it is not a guarantee of safety.";
  });

  window.addEventListener("payguard:calldata-result", (event) => {
    const detail = event.detail || {};
    const result = detail.result || {};
    const request = detail.request || {};
    const verdict = String(result.verdict || "UNVERIFIED").toUpperCase();
    const operation = String(result.operation || "UNKNOWN_OPERATION");
    const summary = root.querySelector('[data-content="summary"]');
    const raw = root.querySelector('[data-content="raw"]');
    const code = root.querySelector("#pg-code-content");
    const note = root.querySelector(".pg-code-note");
    const stateTag = root.querySelector(".pg-state-panel .pg-state-tag");
    const trustTag = root.querySelector(".pg-trust-panel .pg-state-tag");
    const calldataRow = root.querySelector('[aria-controls="pg-evidence-calldata"]');
    const calldataStatus = calldataRow && calldataRow.querySelector(".pg-unavailable");

    if (stateTag) stateTag.textContent = "CALLDATA CHECK COMPLETE";
    if (trustTag) trustTag.textContent = "LATEST CHECK LOADED";
    if (calldataStatus) {
      calldataStatus.textContent = verdict === "PASS" || verdict === "REVIEW" || verdict === "BLOCK"
        ? "POLICY " + verdict
        : "UNVERIFIED";
      calldataStatus.className = "pg-unavailable pg-evidence-status pg-evidence-status--" +
        (["PASS", "REVIEW", "BLOCK"].includes(verdict) ? verdict.toLowerCase() : "unknown");
    }

    const diffCards = root.querySelectorAll(".pg-diff-side");
    if (diffCards[0]) {
      diffCards[0].querySelector("strong").textContent = request.to || "Target unavailable";
      diffCards[0].querySelector("p").textContent = "Native value (wei): " + String(request.value || "0") +
        ". Token transfers and balance deltas are not returned by this inspector.";
    }
    if (diffCards[1]) {
      diffCards[1].querySelector("strong").textContent = "POLICY " + verdict;
      diffCards[1].querySelector("p").textContent = operation +
        ". This is a policy result, not an independent contract audit or balance simulation.";
    }

    if (summary) {
      const lines = [
        ["Operation", operation],
        ["Policy verdict", verdict],
        ["Contract target", request.to || "Not supplied"],
        ["Native value (wei)", request.value || "0"]
      ];
      const reasons = Array.isArray(result.reasons) ? result.reasons : [];
      summary.replaceChildren();
      const list = document.createElement("dl");
      list.className = "pg-live-summary";
      lines.forEach(([label, value]) => {
        const term = document.createElement("dt");
        const description = document.createElement("dd");
        term.textContent = label;
        description.textContent = String(value);
        list.append(term, description);
      });
      summary.append(list);
      if (reasons.length) {
        const heading = document.createElement("strong");
        heading.textContent = "Review notes";
        const reasonList = document.createElement("ul");
        reasons.forEach(reason => {
          const item = document.createElement("li");
          item.textContent = String(reason);
          reasonList.append(item);
        });
        summary.append(heading, reasonList);
      }
    }

    if (raw) {
      const rawCode = document.createElement("code");
      rawCode.textContent = request.data || "No calldata was supplied.";
      raw.replaceChildren(rawCode);
    }
    if (code) {
      code.textContent = JSON.stringify({ request, result }, null, 2);
      code.closest(".pg-code-view")?.setAttribute("aria-label", "Live calldata request and policy result JSON");
    }
    if (note) note.textContent = "Live calldata check loaded. Provider evidence not included in this response remains unavailable.";
    if (codeStatus) codeStatus.textContent = "Live calldata result loaded. Policy verdicts do not replace an independent contract audit.";
  });

  root.addEventListener("click", async (event) => {
    const target = event.target instanceof Element ? event.target : event.target.parentElement;
    if (!target) return;
    const mode = target.closest("[data-mode]");
    if (mode) {
      root.querySelectorAll("[data-mode]").forEach(button => {
        const active = button === mode;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
      });
      root.querySelectorAll("[data-content]").forEach(panel => { panel.hidden = panel.dataset.content !== mode.dataset.mode; });
    }
    const trigger = target.closest(".pg-trust-trigger");
    if (trigger) {
      const panel = document.getElementById(trigger.getAttribute("aria-controls"));
      const open = trigger.getAttribute("aria-expanded") !== "true";
      trigger.setAttribute("aria-expanded", String(open));
      panel.hidden = !open;
      trigger.closest(".pg-trust-item").classList.toggle("is-open", open);
    }
    const action = target.closest("[data-code-action]");
    if (!action) return;
    const code = root.querySelector("#pg-code-content");
    if (action.dataset.codeAction === "format" || action.dataset.codeAction === "minify") {
      try {
        const parsed = JSON.parse(code.textContent);
        const compact = action.dataset.codeAction === "minify";
        code.textContent = JSON.stringify(parsed, null, compact ? 0 : 2);
        action.dataset.codeAction = compact ? "format" : "minify";
        action.textContent = compact ? "Format JSON" : "Minify JSON";
        codeStatus.textContent = compact ? "JSON minified." : "JSON formatted.";
      } catch (_) { codeStatus.textContent = "This example is not valid JSON and could not be formatted."; }
    } else if (action.dataset.codeAction === "copy") {
      try {
        await navigator.clipboard.writeText(code.textContent);
        action.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
        codeStatus.textContent = "JSON copied to clipboard.";
        window.setTimeout(() => { action.innerHTML = '<i class="fa-regular fa-copy"></i> Copy'; }, 1500);
      } catch (_) { codeStatus.textContent = "Clipboard access is unavailable in this browser context."; }
    } else if (action.dataset.codeAction === "expand") {
      setExpanded(!codeView.classList.contains("is-expanded"));
    }
  });

  if (window.gsap && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    window.gsap.from(root.querySelectorAll(".pg-panel"), { y: 14, opacity: 0, duration: .55, stagger: .1, ease: "power2.out", clearProps: "all" });
  }
})();
