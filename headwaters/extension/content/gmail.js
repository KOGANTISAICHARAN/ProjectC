/**
 * Gmail content script.
 *
 * It reads exactly ONE thing from the page: the message identifier. It never
 * reads the message body, and it never sends anything to our servers -- that is
 * the service worker's job.
 *
 * RETRIEVING THE MESSAGE
 * ---------------------
 * The rendered DOM is NOT the source. Scraping it yields the visible body and
 * sender and loses every `Received` header, which is precisely the evidence
 * origin reconstruction depends on. Two correct paths exist, both returning the
 * complete RFC 5322 message:
 *
 *   1. Gmail API `users.messages.get?format=raw` (production). Requires an
 *      OAuth client id and the `gmail.readonly` restricted scope.
 *   2. Gmail's own raw-message endpoint (`view=om`), fetched same-origin with
 *      the session the user already has. No OAuth setup, works immediately.
 *      Undocumented, so it is the demo path rather than the production one.
 *
 * Path 2 is used when no OAuth client is configured. Both give full headers;
 * neither parses the rendered page.
 */

const BUTTON_CLASS = "hw-btn";
const CARD_ID = "hw-verdict-card";

/** Gmail is a single-page app: toolbars appear and vanish as the user navigates. */
const observer = new MutationObserver(() => injectButton());
observer.observe(document.body, { childList: true, subtree: true });
injectButton();

function injectButton() {
  const openMessage = document.querySelector("[data-legacy-message-id]");
  if (!openMessage) return;

  const toolbar =
    document.querySelector("[gh='mtb']") ||
    document.querySelector("[role='toolbar']");
  if (!toolbar || toolbar.querySelector(`.${BUTTON_CLASS}`)) return;

  const button = document.createElement("button");
  button.className = BUTTON_CLASS;
  button.type = "button";
  button.textContent = "Check this email";
  // NOTE: no per-element listener. Gmail's toolbar runs its own click
  // delegation and stops propagation, so a listener bound here never fires --
  // the button renders and appears dead. The document-level capture handler
  // below sees the event first and is immune to that.
  toolbar.appendChild(button);
  log("button injected");
}

// Capture phase on document: runs before Gmail's own handlers, so nothing
// downstream can swallow the click.
document.addEventListener(
  "click",
  (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest(`.${BUTTON_CLASS}`);
    if (!button) return;
    event.preventDefault();
    event.stopPropagation();
    if (button.disabled) return;
    run(button);
  },
  true,
);

function log(...args) {
  // Prefixed so it is findable in a console full of Gmail's own output.
  console.log("[Headwaters]", ...args);
}

async function run(button) {
  const messageId = currentMessageId();
  if (!messageId) {
    renderCard({
      error:
        "No open message was found. Open a single email (not the inbox list) " +
        "and try again.",
    });
    return;
  }

  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const raw = await fetchRawMessage(messageId);
    if (!raw) {
      renderCard({
        error:
          "Could not retrieve the original message from Gmail. Headwaters " +
          "analyses the full raw email, not the rendered page — without it the " +
          "Received chain, and therefore the sending infrastructure, cannot be " +
          "recovered. Open the browser console and look for [Headwaters] lines " +
          "to see which step failed.",
      });
      return;
    }

    const response = await chrome.runtime.sendMessage({
      type: "ANALYSE_RAW",
      raw,
      messageId,
    });
    renderCard(response?.ok ? { verdict: response.verdict } : { error: response?.error });
  } catch (err) {
    renderCard({ error: String(err) });
  } finally {
    button.disabled = false;
    button.textContent = "Check this email";
  }
}

/** The one value read from the DOM. */
function currentMessageId() {
  // Several attributes carry it depending on Gmail's rendering path, and which
  // one is present varies by view and by rollout. The LAST match is preferred:
  // in a thread, that is the message actually expanded on screen.
  const selectors = [
    "[data-legacy-message-id]",
    "[data-message-id]",
    "h7[data-legacy-message-id]",
  ];
  for (const selector of selectors) {
    const nodes = document.querySelectorAll(selector);
    if (nodes.length === 0) continue;
    const node = nodes[nodes.length - 1];
    const raw =
      node.getAttribute("data-legacy-message-id") ??
      node.getAttribute("data-message-id") ??
      "";
    // data-message-id arrives as "#msg-f:1234"; the API wants the digits.
    const cleaned = raw.replace(/^#?msg-[af]:/, "").trim();
    if (cleaned) {
      log("message id", cleaned, "via", selector);
      return cleaned;
    }
  }
  log("no message id found in the DOM");
  return null;
}

/**
 * Fetch the complete RFC 5322 message.
 *
 * Same-origin request carrying the user's existing Gmail session; no token is
 * created, stored, or sent anywhere. Returns base64url, matching what the Gmail
 * API's `format=raw` returns, so the backend has one input shape either way.
 */
async function fetchRawMessage(messageId) {
  const html = document.documentElement.innerHTML;
  const ik =
    html.match(/"ik":"([^"]+)"/)?.[1] ??
    html.match(/GM_ID_KEY\s*=\s*'([^']+)'/)?.[1] ??
    html.match(/ik=([A-Za-z0-9_-]{6,})/)?.[1];
  log("ik token", ik ? "found" : "NOT FOUND");
  if (!ik) return null;

  const account = location.pathname.match(/\/mail\/u\/(\d+)/)?.[1] ?? "0";
  const base = `https://mail.google.com/mail/u/${account}/`;

  // Gmail has shipped several shapes of this endpoint and which one answers
  // depends on the rollout. They are tried in order rather than assuming one.
  const candidates = [
    `${base}?ik=${ik}&view=om&permmsgid=msg-f:${messageId}`,
    `${base}?ui=2&ik=${ik}&view=om&permmsgid=msg-f:${messageId}`,
    `${base}?ik=${ik}&view=om&th=${messageId}`,
    `${base}?ui=2&ik=${ik}&view=om&th=${messageId}`,
  ];

  for (const url of candidates) {
    try {
      const res = await fetch(url, { credentials: "include" });
      if (!res.ok) {
        log("fetch", res.status, url.replace(ik, "<ik>"));
        continue;
      }
      const body = await res.text();
      const message = extractRfc822(body);
      if (message) {
        log("raw message retrieved,", message.length, "bytes");
        return base64url(message);
      }
      log("response was not an RFC 5322 message", url.replace(ik, "<ik>"));
    } catch (err) {
      log("fetch threw", String(err));
    }
  }

  log("every candidate URL failed");
  return null;
}

/**
 * Pull the RFC 5322 message out of whatever the endpoint returned.
 *
 * Gmail sometimes serves the raw bytes directly and sometimes an HTML page with
 * the message inside a <pre>. Assuming the first shape is why this step failed:
 * an HTML wrapper was fetched successfully and then discarded as invalid.
 */
function extractRfc822(body) {
  const looksLikeHeaders = (text) =>
    /^(Received|Return-Path|From|Delivered-To|MIME-Version|Message-ID):/im.test(
      text.slice(0, 2000),
    );

  // Case 1: the raw message, served as-is.
  if (looksLikeHeaders(body) && !/^\s*<(!doctype|html)/i.test(body)) {
    return body;
  }

  // Case 2: an HTML page wrapping it. textContent unescapes entities, which
  // matters -- a message containing &amp; must not survive as the entity.
  try {
    const doc = new DOMParser().parseFromString(body, "text/html");
    const candidates = [
      doc.querySelector("#raw_message_text"),
      doc.querySelector("pre.raw_message_text"),
      ...doc.querySelectorAll("pre"),
    ].filter(Boolean);

    for (const node of candidates) {
      const text = node.textContent ?? "";
      if (looksLikeHeaders(text)) return text;
    }
  } catch (err) {
    log("could not parse the response as HTML", String(err));
  }

  return null;
}

function base64url(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function renderCard({ verdict, error }) {
  document.getElementById(CARD_ID)?.remove();

  const card = document.createElement("div");
  card.id = CARD_ID;
  card.className = "hw-card";

  if (error) {
    card.classList.add("hw-warn");
    card.textContent = error;
  } else {
    const tone =
      verdict.band === "benign"
        ? "hw-benign"
        : verdict.band === "critical" || verdict.band === "high"
          ? "hw-critical"
          : "hw-warn";
    card.classList.add(tone);

    const head = document.createElement("div");
    head.className = "hw-head";
    const score = document.createElement("span");
    score.className = "hw-score";
    score.textContent = verdict.score;
    const label = document.createElement("span");
    label.className = "hw-label";
    label.textContent = verdict.band_label ?? verdict.band.replace(/_/g, " ");
    head.append(score, label);

    // The subject is echoed back from the server so the card names the message
    // it judged. In Gmail the user can see the open message, but the card can
    // outlive a navigation -- and an unlabelled verdict then points at the
    // wrong email.
    const analysed = document.createElement("div");
    analysed.className = "hw-analysed";
    analysed.textContent = `${verdict.subject || "(no subject)"} — ${
      verdict.from_address || "unknown sender"
    }`;

    const headline = document.createElement("div");
    headline.textContent = verdict.headline;

    const advice = document.createElement("div");
    advice.className = "hw-advice";
    advice.textContent = verdict.advice;

    const foot = document.createElement("div");
    foot.className = "hw-foot";
    const link = document.createElement("a");
    link.href = verdict.caseUrl;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.textContent = "Open the full case →";
    foot.append(`${verdict.case_ref} · `, link);

    card.append(head, analysed, headline, advice, foot);
  }

  const anchor =
    document.querySelector("[data-legacy-message-id]") ||
    document.querySelector("[role='main']");
  anchor?.prepend(card);
}
