/**
 * Popup: the employee-facing door.
 *
 * A non-analyst sees a colour, a number, and one sentence telling them what to
 * do. The reasoning, the origin trace and the evidence chain live in the
 * dashboard, which is the analyst's door. One product, two audiences, and the
 * wording for both is composed server-side so it cannot drift into
 * overclaiming.
 */

const config = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
document.getElementById("dashboard").href = config.dashboardBase;

const statusEl = document.getElementById("status");
const verdictEl = document.getElementById("verdict");

// Service reachability, reported plainly.
try {
  const res = await fetch(`${config.apiBase}/healthz`);
  const body = await res.json();
  statusEl.textContent = `service reachable · ${body.environment}`;
  statusEl.classList.add("ok");
} catch {
  statusEl.textContent = "service unreachable — is the stack running?";
  statusEl.classList.add("bad");
}

// Show the last verdict for this tab, so reopening the popup does not re-analyse.
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
if (tab?.id !== undefined) {
  const last = await chrome.runtime.sendMessage({ type: "GET_LAST_VERDICT", tabId: tab.id });
  if (last) render(last);
}

document.getElementById("sample").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = "Analysing…";
  try {
    // Demonstrates the full path -- capture, analyse, verdict -- without needing
    // a Gmail session. The bundled sample is synthetic.
    const sample = await (await fetch(chrome.runtime.getURL("sample.eml"))).text();
    const raw = base64url(sample);
    const response = await chrome.runtime.sendMessage({
      type: "ANALYSE_RAW", raw, messageId: "sample", isSample: true,
    });
    if (response?.ok) render(response.verdict);
    else {
      statusEl.textContent = response?.error ?? "Analysis failed";
      statusEl.className = "status bad";
    }
  } finally {
    button.disabled = false;
    button.textContent = "Try a sample email";
  }
});

function render(verdict) {
  verdictEl.hidden = false;
  verdictEl.className =
    "verdict " +
    (verdict.band === "benign"
      ? "benign"
      : verdict.band === "critical" || verdict.band === "high"
        ? "critical"
        : "warn");
  verdictEl.textContent = "";

  const row = document.createElement("div");
  row.className = "row";
  const score = document.createElement("span");
  score.className = "score";
  score.textContent = verdict.score;
  const band = document.createElement("span");
  band.className = "band";
  // The plain label, not the internal band name.
  band.textContent = verdict.band_label ?? verdict.band.replace(/_/g, " ");
  row.append(score, band);

  if (verdict.is_sample) {
    const badge = document.createElement("span");
    badge.className = "sample-badge";
    badge.textContent = "sample";
    badge.title = "The synthetic email bundled with this extension, not a message from your mailbox";
    row.append(badge);
  }

  // Naming the analysed message is not decoration. A verdict with no visible
  // subject or sender is read as a judgement on whatever the user has on
  // screen -- which, from a security tool, is a false alarm.
  const subject = document.createElement("p");
  subject.className = "analysed";
  subject.textContent = verdict.subject || "(no subject)";
  const sender = document.createElement("p");
  sender.className = "analysed from";
  sender.textContent = verdict.from_address || "unknown sender";

  const headline = document.createElement("p");
  headline.textContent = verdict.headline;
  const advice = document.createElement("p");
  advice.textContent = verdict.advice;

  const link = document.createElement("a");
  link.href = verdict.caseUrl;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = "Open the full case →";

  verdictEl.append(row, subject, sender, headline, advice, link);
}

function base64url(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
