/**
 * @module agent/plan
 * @section Deterministic assessment planning
 * Converts explicit user-supplied subjects into a fixed set of existing PayGuard tool calls.
 * No model, inferred intent, wallet connection, or autonomous action is used.
 */

const has = (value, key) => Object.hasOwn(value, key);

function task(toolName, input, skipReason = null) {
  return Object.freeze({ toolName, input, required: true, skipReason });
}

export function buildAssessmentPlan(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("Assessment input must be a JSON object.");
  }

  const tasks = [];
  const subject = { type: "multi-signal", checksRequested: [] };

  if (has(input, "url")) {
    tasks.push(task("payguard_analyze_url", {
      url: input.url,
      ...(has(input, "expectedDomain") ? { expectedDomain: input.expectedDomain } : {}),
      ...(has(input, "trustedDomains") ? { trustedDomains: input.trustedDomains } : {}),
      ...(has(input, "checkReputation") ? { checkReputation: input.checkReputation } : {})
    }));
    subject.checksRequested.push("url");
  }

  if (has(input, "contractAddress")) {
    tasks.push(task("payguard_check_token_security", {
      contractAddress: input.contractAddress,
      ...(has(input, "chainId") ? { chainId: input.chainId } : {})
    }));
    subject.checksRequested.push("token");
  }

  if (has(input, "address")) {
    tasks.push(task("payguard_check_address_security", {
      address: input.address,
      ...(has(input, "chainId") ? { chainId: input.chainId } : {})
    }));
    subject.checksRequested.push("address");
  }

  if (has(input, "walletAddress")) {
    tasks.push(task("payguard_scan_wallet_tokens", {
      walletAddress: input.walletAddress,
      ...(has(input, "customTokenAddresses") ? { customTokenAddresses: input.customTokenAddresses } : {})
    }));
    subject.checksRequested.push("wallet");
  }

  if (has(input, "transaction")) {
    const tx = input.transaction;
    const txInput = tx && typeof tx === "object" && !Array.isArray(tx)
      ? Object.fromEntries(["to", "value", "data", "policy"]
          .filter(key => has(tx, key))
          .map(key => [key, tx[key]]))
      : tx;
    tasks.push(task("payguard_inspect_calldata", txInput));
    subject.checksRequested.push("transaction");
  }

  const hasIntent = has(input, "intent");
  const hasRequirements = has(input, "paymentRequirements");
  if (hasIntent || hasRequirements) {
    if (hasIntent && hasRequirements) {
      tasks.push(task("payguard_check_payment_intent", {
        intent: input.intent,
        paymentRequirements: input.paymentRequirements
      }));
    } else {
      tasks.push(task(
        "payguard_check_payment_intent",
        null,
        "Payment policy check requires both trusted user intent and payment requirements."
      ));
    }
    subject.checksRequested.push("payment");
  }

  if (input.prepareThreatReport === true) {
    if (has(input, "url")) {
      tasks.push(task("payguard_prepare_threat_report", {
        url: input.url,
        ...(has(input, "expectedDomain") ? { expectedDomain: input.expectedDomain } : {}),
        ...(has(input, "trustedDomains") ? { trustedDomains: input.trustedDomains } : {}),
        ...(has(input, "checkReputation") ? { checkReputation: input.checkReputation } : {})
      }));
    } else {
      tasks.push(task("payguard_prepare_threat_report", null, "Threat report preparation requires a URL."));
    }
    subject.checksRequested.push("threat-report");
  }

  if (tasks.length === 0) {
    throw new TypeError("Provide at least one supported subject: url, contractAddress, address, walletAddress, transaction, intent/paymentRequirements, or prepareThreatReport.");
  }

  subject.checksRequested = [...new Set(subject.checksRequested)];
  return Object.freeze({ subject, tasks: Object.freeze(tasks) });
}
