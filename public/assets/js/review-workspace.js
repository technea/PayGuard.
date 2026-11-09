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
          <div class="pg-diff-side"><span class="pg-diff-label">SENT ASSETS & GAS</span><strong>—</strong><p>Asset outflow and gas estimates appear after a supported transaction analysis.</p></div>
          <div class="pg-diff-side"><span class="pg-diff-label">NET BALANCE & ALLOWANCES</span><strong>—</strong><p>Balance deltas and approval exposure are not inferred without decoded transaction data.</p></div>
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
