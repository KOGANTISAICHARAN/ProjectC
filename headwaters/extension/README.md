# Headwaters browser extension

The second door into the product. The analyst gets a dashboard; **everyone else
gets one button in the inbox they already use.**

```
Gmail  ──[Check this email]──▶  service worker  ──▶  Headwaters API
                                                          │
        one sentence + colour  ◀──────────────────────────┘
        "Open the full case →"  ──▶  analyst dashboard
```

---

## It does not scrape the rendered page

The content script reads exactly **one** thing from the DOM: the message id
(`data-legacy-message-id`). It never reads the body, and it never talks to our
API — all network egress is in `background.js`, so there is one file to audit.

The message itself is fetched as the **complete RFC 5322 original**, headers and
all. This is not a preference. Scraping the rendered email gives you the visible
body and sender and loses every `Received` header — and with them origin
reconstruction, the trust boundary, geolocation and the infrastructure locus of
Email DNA. An extension that scrapes cannot do the thing this product exists to
do.

Two correct retrieval paths, both returning full headers:

| Path | Setup | Status |
|---|---|---|
| Gmail's own raw-message endpoint (`view=om`), fetched same-origin with the session the user already has | none | **default** — undocumented, so demo/pilot rather than production |
| Gmail API `users.messages.get?format=raw` | OAuth client id + `gmail.readonly` | production |

No token is created, stored, or transmitted on the default path. Under the API
path the Google token stays **inside the extension** and is never sent to our
backend — our servers must be incapable of reading a mailbox.

---

## Install (about 30 seconds)

1. Start the stack: `make up` from the repository root.
2. Open `chrome://extensions`.
3. Turn on **Developer mode** (top right).
4. **Load unpacked** → select this `extension/` directory.
5. Click the Headwaters icon → **Try a sample email**.

For Gmail: open any message and press **Check this email** in the toolbar.

---

## Why it is not on the Chrome Web Store

`gmail.readonly` is a Google **restricted scope**. Publishing with it requires
OAuth verification *plus* an independent third-party security assessment (CASA)
— weeks of calendar time and a real invoice. That is a fact about Google's
policy, not a gap in the work.

| Channel | Reality | Verdict |
|---|---|---|
| Web Store, public | $5, then verification + CASA for the restricted scope | Not possible now |
| Web Store, unlisted | Same wall for anyone outside the test-user list | Same wall |
| **GitHub release + Developer mode** | Consent screen stays in *Testing*, up to 100 named test users | **This** |
| Self-hosted `.crx` | Chrome blocks side-loaded CRX outside enterprise policy | Dead end |

Start the verification process on day one after the hackathon: it is the only
item on the roadmap that cannot be compressed.

---

## Configuration

`background.js` holds `API_BASE` and `DASHBOARD_BASE`, defaulting to the local
stack (`127.0.0.1:8000` / `127.0.0.1:3100`). Change both, and the matching
entries in `manifest.json` → `host_permissions`, to point at a deployed
instance. MV3 grants cross-origin fetch for hosts listed there, which is why no
CORS entry is needed for the extension.

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3. Minimum permissions: `storage`, `activeTab`, two host permissions |
| `background.js` | Service worker. **All** network egress, badge state, per-tab verdict cache |
| `content/gmail.js` | Button injection, message id, raw-message retrieval, in-page verdict card |
| `popup/` | Employee-facing view: score, one sentence, what to do, link to the case |
| `sample.eml` | Bundled synthetic message so the full path can be shown without a Gmail session |
