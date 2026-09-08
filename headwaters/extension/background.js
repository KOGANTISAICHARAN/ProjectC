/**
 * Service worker: the extension's only network egress.
 *
 * The content script never talks to our API and never holds a credential. It
 * reads one identifier from the page and hands the raw message here; everything
 * that leaves the browser leaves from this file, so there is exactly one place
 * to audit.
 */

const API_BASE = "http://127.0.0.1:8000";
const DASHBOARD_BASE = "http://127.0.0.1:3100";

/** Last verdict per tab, so the popup can render without re-analysing. */
const lastVerdict = new Map();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "ANALYSE_RAW") {
    analyse(message.raw, message.messageId, sender.tab?.id, message.isSample === true)
      .then(sendResponse);
    return true; // keep the channel open for the async reply
  }
  if (message?.type === "GET_LAST_VERDICT") {
    sendResponse(lastVerdict.get(message.tabId) ?? null);
    return false;
  }
  if (message?.type === "GET_CONFIG") {
    sendResponse({ apiBase: API_BASE, dashboardBase: DASHBOARD_BASE });
    return false;
  }
  return false;
});

async function analyse(raw, messageId, tabId, isSample = false) {
  try {
    const res = await fetch(`${API_BASE}/api/v1/cases/from-extension`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw, message_id: messageId ?? null, is_sample: isSample }),
    });

    if (!res.ok) {
      const detail = await res.text();
      return { ok: false, error: `Analysis failed (${res.status})`, detail };
    }

    const verdict = await res.json();
    verdict.caseUrl = `${DASHBOARD_BASE}/cases/${verdict.case_id}`;

    if (tabId !== undefined) {
      lastVerdict.set(tabId, verdict);
      setBadge(tabId, verdict);
    }
    return { ok: true, verdict };
  } catch (err) {
    // The backend being unreachable is a normal condition, not a crash. The
    // extension says so plainly rather than failing silently.
    return {
      ok: false,
      error: "Cannot reach the Headwaters service.",
      detail: String(err),
    };
  }
}

function setBadge(tabId, verdict) {
  const critical = verdict.band === "critical" || verdict.band === "high";
  const benign = verdict.band === "benign";
  chrome.action.setBadgeText({ tabId, text: String(verdict.score) });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: benign ? "#1d6a57" : critical ? "#a4372a" : "#8a6210",
  });
}

chrome.tabs.onRemoved.addListener((tabId) => lastVerdict.delete(tabId));
