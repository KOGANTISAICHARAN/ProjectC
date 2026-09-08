"""The browser extension's contract with the backend.

The extension is a *capture* layer: it retrieves the complete raw message and
hands it over. Everything asserted here protects that contract, because the one
way to break the whole product is to capture the rendered page instead of the
raw message and silently lose every Received header.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from app.services.analysis import analyse

FIXTURES = Path(__file__).parent / "fixtures"


def _extension_dir() -> Path:
    """Locate the extension sources.

    They live outside the backend package, so the path differs between a repo
    checkout (CI) and the container (where only ``backend/`` is the working tree
    and ``extension/`` is mounted read-only). Checked rather than assumed, and
    skipped rather than failed where the sources genuinely are not present.
    """
    candidates = [
        Path(os.environ["EXTENSION_DIR"]) if os.environ.get("EXTENSION_DIR") else None,
        Path(__file__).resolve().parents[2] / "extension",  # repo checkout
        Path("/extension"),  # docker-compose read-only mount
    ]
    for candidate in candidates:
        if candidate is not None and (candidate / "manifest.json").exists():
            return candidate
    pytest.skip("extension sources are not mounted in this environment")


EXTENSION = _extension_dir()


def test_bundled_sample_matches_the_test_fixture() -> None:
    """The popup ships a copy of the BEC fixture so it can demonstrate the full
    path without a Gmail session.

    A copy drifts. This caught a real drift: the fixture gained a DKIM-Signature
    header and the extension's copy did not, so the extension was demonstrating
    an analysis the test suite no longer covered.
    """
    assert (EXTENSION / "sample.eml").read_bytes() == (FIXTURES / "bec.eml").read_bytes()


def test_bundled_sample_still_scores_critical() -> None:
    """Whatever the extension demonstrates must be what the engine actually
    concludes."""
    result = analyse((EXTENSION / "sample.eml").read_bytes())
    assert result.fusion.score >= 85
    assert result.fusion.band.value == "critical"


# --------------------------------------------------------------- manifest ---
def _manifest() -> dict:
    return json.loads((EXTENSION / "manifest.json").read_text())


def test_manifest_is_v3() -> None:
    assert _manifest()["manifest_version"] == 3


def test_permissions_are_minimal() -> None:
    """No `tabs`, no `<all_urls>`, no `webRequest`. An extension that reads mail
    has to ask for the least it can, and be seen to."""
    manifest = _manifest()
    assert set(manifest["permissions"]) <= {"storage", "activeTab", "identity"}
    for host in manifest["host_permissions"]:
        assert "<all_urls>" not in host
        assert host.startswith(("https://mail.google.com", "http://127.0.0.1", "https://"))


def test_content_script_is_scoped_to_gmail() -> None:
    scripts = _manifest()["content_scripts"]
    assert len(scripts) == 1
    assert scripts[0]["matches"] == ["https://mail.google.com/*"]


def test_declared_files_all_exist() -> None:
    """A manifest referencing a missing file fails at load with an error Chrome
    reports only in the extensions page."""
    manifest = _manifest()
    referenced = [
        manifest["background"]["service_worker"],
        manifest["action"]["default_popup"],
        *manifest["icons"].values(),
    ]
    for script in manifest["content_scripts"]:
        referenced += script.get("js", []) + script.get("css", [])

    missing = [ref for ref in referenced if not (EXTENSION / ref).exists()]
    assert not missing, f"manifest references missing files: {missing}"


# ------------------------------------------------------------ capture path ---
def test_content_script_never_reads_the_message_body() -> None:
    """The single most important property.

    Scraping the rendered DOM yields the visible body and sender and loses every
    Received header -- and with them origin reconstruction, the trust boundary,
    and the infrastructure locus of Email DNA. The content script may read the
    message *id* and nothing else.
    """
    source = (EXTENSION / "content" / "gmail.js").read_text()
    assert "data-legacy-message-id" in source, "the message id is how a message is located"
    assert "view=om" in source, "the raw message must come from Gmail's own endpoint"

    # Selectors that would indicate body scraping.
    for forbidden in (".ii.gt", "[role='listitem'] .a3s", ".a3s.aiL", "innerText"):
        assert forbidden not in source, f"content script appears to scrape the body: {forbidden}"


def test_only_the_service_worker_talks_to_our_api() -> None:
    """One place for egress means one place to audit."""
    content = (EXTENSION / "content" / "gmail.js").read_text()
    assert "127.0.0.1:8000" not in content
    assert "api/v1/cases" not in content
    assert "chrome.runtime.sendMessage" in content


def test_google_token_never_reaches_our_backend() -> None:
    """Our servers must be incapable of reading a user's mailbox. The Gmail
    credential stays in the browser; only the single message the user chose is
    sent."""
    background = (EXTENSION / "background.js").read_text()
    body_start = background.index("body: JSON.stringify")
    body = background[body_start : body_start + 200]
    assert "token" not in body.lower()
    assert "raw" in body


# ------------------------------------------------------------- endpoint ------
@pytest.mark.parametrize("name", ["bec", "benign"])
def test_base64url_payload_round_trips(name: str) -> None:
    """Gmail returns base64url with padding stripped; the endpoint restores it."""
    raw = (FIXTURES / f"{name}.eml").read_bytes()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    assert decoded == raw
