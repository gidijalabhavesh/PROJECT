const form = document.querySelector("#review-form");
const messageInput = document.querySelector("#message");
const senderInput = document.querySelector("#sender");
const counter = document.querySelector("#counter");
const report = document.querySelector("#report");
const reportId = document.querySelector("#report-id");
const emptyState = document.querySelector("#empty-state");
const resultContent = document.querySelector("#result-content");
const analyzeButton = form.querySelector("[type='submit']");

const samples = {
  kyc: {
    sender: "+91 98110 23456",
    content: "Dear SBI user, your YONO account is deactivated today due to pending KYC. Click http://sbi-kyc-verify.top/login to update immediately.",
  },
  upi: {
    sender: "Refund Desk",
    content: "PhonePe Cash Back: You have received a scratch card bonus of INR 4,999. Enter your UPI PIN on the prompt to transfer to your bank.",
  },
  bank: {
    sender: "AX-ICICIB",
    content: "INR 1,200.00 debited from A/C XX8902 on 16-OCT-26 via UPI Ref 62910283. Bal: INR 34,210. Not you? SMS BLOCK to 5676766.",
  },
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

function renderReport(data) {
  const flags = data.red_flags.length
    ? data.red_flags.map((flag) => `<li class="flag-item"><div><strong>${escapeHtml(flag.indicator)}</strong><span>${escapeHtml(flag.explanation)}</span></div></li>`).join("")
    : '<li class="flag-item"><div><strong>No strong scam signals found</strong><span>Still verify unexpected requests through an official channel.</span></div></li>';
  const entities = [
    ...data.extracted_entities.urls,
    ...data.extracted_entities.phone_numbers,
    ...data.extracted_entities.upi_ids,
    ...(data.extracted_entities.claimed_organization ? [data.extracted_entities.claimed_organization] : []),
  ];
  const entitySection = entities.length
    ? `<div class="result-block"><h3 class="block-title">EXTRACTED DETAILS</h3><div class="entity-list">${entities.map((item) => `<span class="entity">${escapeHtml(item)}</span>`).join("")}</div></div>`
    : "";
  const scoreColor = ["CRITICAL", "HIGH"].includes(data.risk_level) ? "var(--orange)" : data.risk_level === "MEDIUM" ? "#b88124" : "var(--green)";
  resultContent.innerHTML = `
    <div class="result-summary">
      <div><span class="risk-label ${escapeHtml(data.risk_level)}">${escapeHtml(data.risk_level)} RISK</span><h2 class="result-category">${escapeHtml(data.scam_category.replaceAll("_", " "))}</h2></div>
      <div class="score-ring" style="--score:${Number(data.risk_score)};--score-color:${scoreColor}" aria-label="Risk score ${Number(data.risk_score)} out of 100"><span class="score-value">${Number(data.risk_score)}<small>/ 100</small></span></div>
    </div>
    <div class="result-block"><h3 class="block-title">SIGNALS</h3><ul class="flag-list">${flags}</ul></div>
    <div class="result-block"><h3 class="block-title">WHAT TO DO</h3><ul class="action-list">${data.recommended_actions.map((action) => `<li>${escapeHtml(action)}</li>`).join("")}</ul></div>
    ${entitySection}
    <div class="result-block"><h3 class="block-title">REPORTING</h3><p class="helpline">${escapeHtml(data.helpline_guidance)}</p></div>
  `;
  emptyState.hidden = true;
  resultContent.hidden = false;
}

messageInput.addEventListener("input", () => {
  messageInput.setCustomValidity("");
  counter.textContent = `${messageInput.value.length.toLocaleString()} / 10,000`;
});

document.querySelector("#clear-button").addEventListener("click", () => {
  form.reset();
  counter.textContent = "0 / 10,000";
  emptyState.hidden = false;
  resultContent.hidden = true;
  resultContent.replaceChildren();
  reportId.textContent = "READY";
  report.querySelector(".error-message")?.remove();
  messageInput.focus();
});

document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", () => {
    const sample = samples[button.dataset.sample];
    senderInput.value = sample.sender;
    messageInput.value = sample.content;
    messageInput.dispatchEvent(new Event("input"));
    messageInput.focus();
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  report.querySelector(".error-message")?.remove();
  if (!messageInput.value.trim()) {
    messageInput.setCustomValidity("Enter a message to review.");
    messageInput.reportValidity();
    return;
  }
  messageInput.setCustomValidity("");
  analyzeButton.disabled = true;
  analyzeButton.querySelector("span:first-child").textContent = "Checking...";
  report.setAttribute("aria-busy", "true");
  reportId.textContent = "ANALYZING";
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender: senderInput.value, content: messageInput.value }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "The message could not be analyzed.");
    renderReport(data);
    reportId.textContent = "COMPLETE";
  } catch (error) {
    const errorNode = document.createElement("p");
    errorNode.className = "error-message";
    errorNode.textContent = error.message || "Could not reach the analysis service. Check your connection and try again.";
    report.append(errorNode);
    reportId.textContent = "ERROR";
  } finally {
    report.setAttribute("aria-busy", "false");
    analyzeButton.disabled = false;
    analyzeButton.querySelector("span:first-child").textContent = "Analyze message";
  }
});
