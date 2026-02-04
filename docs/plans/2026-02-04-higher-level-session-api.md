# Higher-Level Session API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `xhr()`, `navigate()`, and `form_submit()` methods to `GraftpunkSession` so plugins make browser-correct requests in one line instead of rebuilding header infrastructure from scratch.

**Architecture:** The three methods compose headers from two sources: captured profile headers (from login CDP capture) and canonical Fetch-spec headers (fallback). Each method accepts a `referer` kwarg that the session resolves against `gp_base_url`. Methods delegate to `self.request()`, so all existing `requests.Session` features (cookies, auth, retries, hooks) work unchanged. This also includes the `_detect_profile` fix for non-GET/POST methods (deferred from #49 per updated issue).

**Tech Stack:** Python 3.13, requests, structlog, pytest, ruff

**Branch:** `fix/49-browser-identity-separation` (adding to PR #51)

**Depends on:** #49 work already in this branch (browser identity at init, canonical headers, `_case_insensitive_get`)

---

### Task 1: Fix `_detect_profile` for non-GET/POST methods

**Files:**
- Modify: `src/graftpunk/graftpunk_session.py:146-175` (`_detect_profile`)
- Test: `tests/unit/test_graftpunk_session.py`

Per the HTML spec §4.10.18.6, `<form>` elements only support GET and POST. DELETE, PUT, PATCH, HEAD, and OPTIONS can only originate from `fetch()` or `XMLHttpRequest` — never from navigation. The current heuristic defaults these to `"navigation"`, which is provably incorrect.

**Step 1: Write failing tests**

Add to `TestProfileDetection` in `tests/unit/test_graftpunk_session.py`:

```python
def test_delete_uses_xhr(self):
    session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
    req = requests.Request("DELETE", "https://example.com/api/1")
    prepared = session.prepare_request(req)
    assert prepared.headers.get("X-Requested-With") == "XMLHttpRequest"

def test_head_uses_xhr(self):
    session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
    req = requests.Request("HEAD", "https://example.com/api/1")
    prepared = session.prepare_request(req)
    assert "application/json" in prepared.headers["Accept"]

def test_options_uses_xhr(self):
    session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
    req = requests.Request("OPTIONS", "https://example.com/api/1")
    prepared = session.prepare_request(req)
    assert "application/json" in prepared.headers["Accept"]
```

**Step 2: Run tests, verify they fail**

```bash
uv run pytest tests/unit/test_graftpunk_session.py::TestProfileDetection::test_delete_uses_xhr -v
```

Expected: FAIL — DELETE currently gets navigation headers, not XHR.

**Step 3: Fix `_detect_profile`**

In `src/graftpunk/graftpunk_session.py`, update `_detect_profile` (lines 146-175). Add the non-GET/POST check **before** the json/data checks:

```python
def _detect_profile(self, request: requests.Request) -> str:
    """Auto-detect the appropriate header profile for a request.

    Args:
        request: The request about to be sent.

    Returns:
        Profile name ("navigation", "xhr", or "form").
    """
    if self.gp_default_profile:
        return self.gp_default_profile

    method = (request.method or "GET").upper()

    # Non-GET/POST methods are always XHR — browsers have no mechanism
    # to issue DELETE/PUT/PATCH/HEAD/OPTIONS as navigation requests.
    # HTML forms only support GET and POST (HTML spec §4.10.18.6).
    if method not in ("GET", "POST"):
        return "xhr"

    # Check for explicit Accept: application/json in caller headers
    caller_headers = request.headers or {}
    caller_accept = caller_headers.get("Accept", "")
    if "application/json" in caller_accept:
        return "xhr"

    # POST with json= → xhr
    if method == "POST" and request.json is not None:
        return "xhr"

    # POST with data= (string or dict) → form
    if method == "POST" and request.data:
        return "form"

    # Default: navigation (GET without Accept: application/json)
    return "navigation"
```

Note: the `PUT/PATCH` check for `json is not None` is now redundant (caught by `method not in ("GET", "POST")`), so it's removed.

**Step 4: Run tests, verify they pass**

```bash
uv run pytest tests/unit/test_graftpunk_session.py -v
```

Expected: All tests pass including the 3 new ones.

**Step 5: Commit**

```bash
git add src/graftpunk/graftpunk_session.py tests/unit/test_graftpunk_session.py
git commit -m "fix: treat non-GET/POST methods as XHR per HTML spec §4.10.18.6

DELETE, PUT, PATCH, HEAD, and OPTIONS can only originate from fetch()
or XMLHttpRequest — browsers have no mechanism to issue them as
navigation requests. The previous heuristic defaulted these to
'navigation', which applied incorrect Accept and Sec-Fetch-* headers.

Co-Authored-By: stavxyz <hi@stav.xyz>"
```

---

### Task 2: Add `gp_base_url`, `_resolve_referer()`, and `_profile_headers_for()`

**Files:**
- Modify: `src/graftpunk/graftpunk_session.py` (`__init__`, new methods)
- Test: `tests/unit/test_graftpunk_session.py`

These are the internal building blocks that `xhr()`, `navigate()`, and `form_submit()` use.

**Step 1: Write failing tests**

Add new test classes to `tests/unit/test_graftpunk_session.py`:

```python
class TestResolveReferer:
    """Test Referer URL resolution from path or full URL."""

    def test_path_joined_with_base_url(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        session.gp_base_url = "https://www.example.com"
        assert session._resolve_referer("/invoice/list") == "https://www.example.com/invoice/list"

    def test_full_url_used_as_is(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        session.gp_base_url = "https://www.example.com"
        assert session._resolve_referer("https://other.example.com/page") == "https://other.example.com/page"

    def test_path_without_base_url_warns(self, capsys):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        result = session._resolve_referer("/some/path")
        captured = capsys.readouterr()
        assert "referer_path_without_base_url" in captured.out
        # Returns the path as-is since no base_url to join with
        assert result == "/some/path"

    def test_base_url_trailing_slash_handled(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        session.gp_base_url = "https://www.example.com/"
        assert session._resolve_referer("/invoice/list") == "https://www.example.com/invoice/list"


class TestProfileHeadersFor:
    """Test _profile_headers_for composition of captured + canonical headers."""

    def test_captured_profile_returned(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        headers = session._profile_headers_for("xhr")
        assert headers["X-Requested-With"] == "XMLHttpRequest"
        assert headers["Accept"] == "application/json"

    def test_missing_profile_falls_back_to_canonical(self):
        profiles = {
            "xhr": {
                "User-Agent": "Mozilla/5.0 Test",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
        }
        session = GraftpunkSession(header_profiles=profiles)
        headers = session._profile_headers_for("navigation")
        assert "text/html" in headers["Accept"]
        assert headers["Sec-Fetch-Mode"] == "navigate"

    def test_returns_copy_not_reference(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        headers = session._profile_headers_for("xhr")
        headers["New-Header"] = "value"
        assert "New-Header" not in session._gp_header_profiles.get("xhr", {})

    def test_unknown_profile_returns_empty(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        headers = session._profile_headers_for("nonexistent")
        assert headers == {}

    def test_excludes_identity_headers(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        headers = session._profile_headers_for("navigation")
        # Identity headers should NOT be in profile headers —
        # they're on self.headers already from _apply_browser_identity
        assert "User-Agent" not in headers
        assert "sec-ch-ua" not in headers
        assert "Accept-Language" not in headers
        assert "Accept-Encoding" not in headers
```

**Step 2: Run tests, verify they fail**

```bash
uv run pytest tests/unit/test_graftpunk_session.py::TestResolveReferer -v
uv run pytest tests/unit/test_graftpunk_session.py::TestProfileHeadersFor -v
```

Expected: FAIL — methods don't exist yet.

**Step 3: Implement**

In `src/graftpunk/graftpunk_session.py`:

Add `gp_base_url` to `__init__`:

```python
def __init__(
    self,
    header_profiles: dict[str, dict[str, str]] | None = None,
    *,
    base_url: str = "",
    **kwargs: Any,
) -> None:
    super().__init__(**kwargs)
    self._gp_header_profiles: dict[str, dict[str, str]] = header_profiles or {}
    self.gp_default_profile: str | None = None
    self.gp_base_url: str = base_url
    self._apply_browser_identity()
    self._gp_default_session_headers: dict[str, str] = dict(self.headers)
```

Add `_resolve_referer` method:

```python
def _resolve_referer(self, referer: str) -> str:
    """Resolve a Referer value from a path or full URL.

    Args:
        referer: A URL path ("/invoice/list") or full URL.
            Paths are joined with gp_base_url. Full URLs (starting
            with "http") are returned as-is.

    Returns:
        The resolved Referer URL string.
    """
    if referer.startswith(("http://", "https://")):
        return referer

    if not self.gp_base_url:
        LOG.warning(
            "referer_path_without_base_url",
            referer=referer,
        )
        return referer

    base = self.gp_base_url.rstrip("/")
    path = referer if referer.startswith("/") else f"/{referer}"
    return f"{base}{path}"
```

Add `_profile_headers_for` method:

```python
def _profile_headers_for(self, profile_name: str) -> dict[str, str]:
    """Get request-type headers for a profile, excluding identity headers.

    Returns captured profile headers if available, falling back to
    canonical Fetch-spec headers. Browser identity headers (User-Agent,
    sec-ch-ua, etc.) are excluded — they're already on self.headers.

    Args:
        profile_name: Profile name ("navigation", "xhr", or "form").

    Returns:
        Dict of request-type headers, or empty dict if profile unknown.
    """
    captured = self._gp_header_profiles.get(profile_name)
    if captured:
        headers = dict(captured)
    else:
        canonical = _CANONICAL_REQUEST_HEADERS.get(profile_name)
        if canonical is None:
            return {}
        headers = dict(canonical)

    # Remove identity headers — they're session-level defaults
    for key in _BROWSER_IDENTITY_HEADERS:
        headers.pop(key, None)
        # Also check case-insensitive (CDP headers may have mixed case)
        to_remove = [k for k in headers if k.lower() == key.lower()]
        for k in to_remove:
            headers.pop(k, None)

    return headers
```

**Step 4: Run tests, verify they pass**

```bash
uv run pytest tests/unit/test_graftpunk_session.py -v
```

Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/graftpunk/graftpunk_session.py tests/unit/test_graftpunk_session.py
git commit -m "feat: add gp_base_url, _resolve_referer, and _profile_headers_for

Foundation for xhr/navigate/form_submit methods:
- gp_base_url: session attribute for constructing Referer URLs
- _resolve_referer: joins path with base_url, passes full URLs through
- _profile_headers_for: composes captured + canonical headers, strips
  identity headers (already on session from _apply_browser_identity)

Co-Authored-By: stavxyz <hi@stav.xyz>"
```

---

### Task 3: Add `xhr()`, `navigate()`, `form_submit()` public methods

**Files:**
- Modify: `src/graftpunk/graftpunk_session.py`
- Test: `tests/unit/test_graftpunk_session.py`

**Step 1: Write failing tests**

Add to `tests/unit/test_graftpunk_session.py`:

```python
from unittest.mock import patch


class TestXhr:
    """Test xhr() method for XHR-style requests."""

    def test_xhr_get_applies_xhr_headers(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.xhr("GET", "https://example.com/api/data")
        call_kwargs = mock_request.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers["X-Requested-With"] == "XMLHttpRequest"
        assert "application/json" in headers["Accept"]

    def test_xhr_post_with_json(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.xhr("POST", "https://example.com/api", json={"key": "val"})
        call_kwargs = mock_request.call_args
        assert call_kwargs[0] == ("POST", "https://example.com/api")
        assert call_kwargs.kwargs["json"] == {"key": "val"}

    def test_xhr_with_referer_path(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES, base_url="https://example.com")
        with patch.object(session, "request") as mock_request:
            session.xhr("GET", "https://example.com/api", referer="/invoice/list")
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert headers["Referer"] == "https://example.com/invoice/list"

    def test_xhr_without_referer(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.xhr("GET", "https://example.com/api")
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert "Referer" not in headers

    def test_xhr_caller_headers_override_profile(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.xhr("GET", "https://example.com/api", headers={"Accept": "text/plain"})
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert headers["Accept"] == "text/plain"
        # Profile headers still present for non-overridden keys
        assert headers["X-Requested-With"] == "XMLHttpRequest"

    def test_xhr_passes_kwargs_through(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.xhr("GET", "https://example.com/api", params={"q": "test"}, timeout=10)
        assert mock_request.call_args.kwargs["params"] == {"q": "test"}
        assert mock_request.call_args.kwargs["timeout"] == 10


class TestNavigate:
    """Test navigate() method for navigation-style requests."""

    def test_navigate_applies_navigation_headers(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.navigate("GET", "https://example.com/page")
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert "text/html" in headers["Accept"]

    def test_navigate_with_referer(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES, base_url="https://example.com")
        with patch.object(session, "request") as mock_request:
            session.navigate("GET", "https://example.com/page2", referer="/page1")
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert headers["Referer"] == "https://example.com/page1"

    def test_navigate_uses_canonical_when_profile_missing(self):
        profiles = {
            "xhr": {
                "User-Agent": "Mozilla/5.0 Test",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
        }
        session = GraftpunkSession(header_profiles=profiles)
        with patch.object(session, "request") as mock_request:
            session.navigate("GET", "https://example.com/page")
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert "text/html" in headers["Accept"]
        assert headers["Sec-Fetch-Mode"] == "navigate"


class TestFormSubmit:
    """Test form_submit() method for form submission requests."""

    def test_form_submit_applies_form_headers(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.form_submit("POST", "https://example.com/login", data={"user": "me"})
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert "text/html" in headers["Accept"]

    def test_form_submit_with_referer(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES, base_url="https://example.com")
        with patch.object(session, "request") as mock_request:
            session.form_submit("POST", "https://example.com/login", referer="/login", data={"u": "me"})
        headers = mock_request.call_args.kwargs.get("headers") or mock_request.call_args[1].get("headers", {})
        assert headers["Referer"] == "https://example.com/login"

    def test_form_submit_passes_data_through(self):
        session = GraftpunkSession(header_profiles=SAMPLE_PROFILES)
        with patch.object(session, "request") as mock_request:
            session.form_submit("POST", "https://example.com/submit", data="key=val")
        assert mock_request.call_args.kwargs["data"] == "key=val"
```

**Step 2: Run tests, verify they fail**

```bash
uv run pytest tests/unit/test_graftpunk_session.py::TestXhr -v
```

Expected: FAIL — `xhr()` method doesn't exist.

**Step 3: Implement the three methods**

Add to `GraftpunkSession` in `src/graftpunk/graftpunk_session.py`:

```python
def xhr(
    self,
    method: str,
    url: str,
    *,
    referer: str | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Make a request with XHR profile headers.

    Applies captured XHR headers (or canonical Fetch-spec defaults),
    plus browser identity headers from the session. Caller-supplied
    headers override profile headers.

    Args:
        method: HTTP method (GET, POST, PUT, PATCH, DELETE, etc.).
        url: Request URL.
        referer: Referer path ("/page") or full URL. Paths are joined
            with gp_base_url. Omit to send no Referer.
        headers: Additional headers that override profile headers.
        **kwargs: Passed through to requests.Session.request().

    Returns:
        The response object.
    """
    return self._request_with_profile("xhr", method, url, referer=referer, headers=headers, **kwargs)

def navigate(
    self,
    method: str,
    url: str,
    *,
    referer: str | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Make a request with navigation profile headers.

    Applies captured navigation headers (or canonical Fetch-spec defaults),
    plus browser identity headers from the session. Simulates a browser
    page navigation (clicking a link, entering a URL).

    Args:
        method: HTTP method (typically GET).
        url: Request URL.
        referer: Referer path ("/page") or full URL. Paths are joined
            with gp_base_url. Omit to send no Referer.
        headers: Additional headers that override profile headers.
        **kwargs: Passed through to requests.Session.request().

    Returns:
        The response object.
    """
    return self._request_with_profile("navigation", method, url, referer=referer, headers=headers, **kwargs)

def form_submit(
    self,
    method: str,
    url: str,
    *,
    referer: str | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Make a request with form submission profile headers.

    Applies captured form headers (or canonical Fetch-spec defaults),
    plus browser identity headers from the session. Simulates a browser
    form submission.

    Args:
        method: HTTP method (typically POST).
        url: Request URL.
        referer: Referer path ("/page") or full URL. Paths are joined
            with gp_base_url. Omit to send no Referer.
        headers: Additional headers that override profile headers.
        **kwargs: Passed through to requests.Session.request().

    Returns:
        The response object.
    """
    return self._request_with_profile("form", method, url, referer=referer, headers=headers, **kwargs)

def _request_with_profile(
    self,
    profile_name: str,
    method: str,
    url: str,
    *,
    referer: str | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Make a request with explicit profile headers.

    Internal implementation for xhr(), navigate(), and form_submit().
    Composes profile headers, Referer, and caller overrides, then
    delegates to self.request().

    Args:
        profile_name: Profile to apply ("xhr", "navigation", or "form").
        method: HTTP method.
        url: Request URL.
        referer: Optional Referer path or URL.
        headers: Optional caller headers (override profile headers).
        **kwargs: Passed through to requests.Session.request().

    Returns:
        The response object.
    """
    profile_headers = self._profile_headers_for(profile_name)

    if referer is not None:
        profile_headers["Referer"] = self._resolve_referer(referer)

    # Caller headers override profile headers
    if headers:
        profile_headers.update(headers)

    return self.request(method.upper(), url, headers=profile_headers, **kwargs)
```

**Step 4: Run tests, verify they pass**

```bash
uv run pytest tests/unit/test_graftpunk_session.py -v
```

Expected: All tests pass.

**Step 5: Commit**

```bash
git add src/graftpunk/graftpunk_session.py tests/unit/test_graftpunk_session.py
git commit -m "feat: add xhr(), navigate(), and form_submit() methods

Higher-level request methods that apply the correct browser header
profile automatically. Each composes captured + canonical headers,
adds optional Referer from path or full URL, and delegates to
self.request(). Caller headers override profile headers.

Plugin code goes from:
  headers = _build_headers('invoice.list', ctx.base_url, '/list')
  resp = ctx.session.get(url, headers=headers, params=p, timeout=10)
To:
  resp = ctx.session.xhr('GET', url, referer='/list', params=p, timeout=10)

Closes #50.

Co-Authored-By: stavxyz <hi@stav.xyz>"
```

---

### Task 4: Wire `gp_base_url` in the framework

**Files:**
- Modify: `src/graftpunk/cli/plugin_commands.py:366-376` (set `gp_base_url` on session)
- Test: `tests/unit/test_plugin_commands.py` (verify `gp_base_url` is set)

**Step 1: Write failing test**

Find the existing test for `CommandContext` creation in `tests/unit/test_plugin_commands.py` and add:

```python
def test_session_gets_base_url_from_plugin(self):
    """Verify gp_base_url is set on GraftpunkSession from plugin base_url."""
    # This test uses the existing test infrastructure for plugin command execution.
    # The key assertion is that after the framework creates the session and context,
    # session.gp_base_url == plugin.base_url.
```

Note: The exact test depends on the existing test fixtures in `test_plugin_commands.py`. The implementer should find the existing `CommandContext` creation tests and add a `gp_base_url` assertion. If the existing fixtures don't test this path easily, a minimal test can be:

```python
def test_gp_base_url_set_on_session(self):
    from graftpunk.graftpunk_session import GraftpunkSession
    session = GraftpunkSession(header_profiles={}, base_url="https://example.com")
    assert session.gp_base_url == "https://example.com"
```

**Step 2: Implement**

In `src/graftpunk/cli/plugin_commands.py`, after the session is loaded (around line 314-320) and before `CommandContext` creation (line 367), add:

```python
# Set base_url on session so xhr/navigate/form_submit can resolve Referer paths
base_url = getattr(plugin, "base_url", "")
if base_url and hasattr(session, "gp_base_url"):
    session.gp_base_url = base_url
```

**Step 3: Run tests, verify they pass**

```bash
uv run pytest tests/unit/test_plugin_commands.py -v
uv run pytest tests/unit/test_graftpunk_session.py -v
```

**Step 4: Commit**

```bash
git add src/graftpunk/cli/plugin_commands.py tests/
git commit -m "feat: wire gp_base_url from plugin to session

Set gp_base_url on GraftpunkSession when loading session for plugin
commands. This enables xhr/navigate/form_submit to resolve Referer
paths against the plugin's base_url without plugins passing it
explicitly.

Co-Authored-By: stavxyz <hi@stav.xyz>"
```

---

### Task 5: Update documentation

**Files:**
- Modify: `CHANGELOG.md`
- Modify: `docs/HOW_IT_WORKS.md`

**Step 1: Update CHANGELOG.md**

Add under `### Added` in the `[Unreleased]` section:

```markdown
- **Higher-Level Session API**: Request-type methods eliminate browser header boilerplate
  - `session.xhr(method, url, *, referer=None)` — XHR/fetch-style requests
  - `session.navigate(method, url, *, referer=None)` — Page navigation requests
  - `session.form_submit(method, url, *, referer=None)` — Form submission requests
  - Referer auto-constructed from path + `gp_base_url`: `referer="/invoice/list"` → full URL
  - All methods compose captured profile headers with canonical Fetch-spec fallbacks
  - Caller-supplied headers always override profile headers
```

Add under `### Fixed`:

```markdown
- **`_detect_profile` for non-GET/POST methods**: DELETE, PUT, PATCH, HEAD, and OPTIONS now correctly detected as XHR per HTML spec §4.10.18.6 (previously defaulted to "navigation")
```

**Step 2: Update docs/HOW_IT_WORKS.md**

Add a section documenting the higher-level API. Show before/after comparison from the issue.

**Step 3: Commit**

```bash
git add CHANGELOG.md docs/HOW_IT_WORKS.md
git commit -m "docs: document higher-level session API and _detect_profile fix

Co-Authored-By: stavxyz <hi@stav.xyz>"
```

---

## Summary

| Task | What | Tests Added |
|------|------|-------------|
| 1 | Fix `_detect_profile` for DELETE/HEAD/OPTIONS | 3 |
| 2 | `gp_base_url`, `_resolve_referer()`, `_profile_headers_for()` | 9 |
| 3 | `xhr()`, `navigate()`, `form_submit()` | 12 |
| 4 | Wire `gp_base_url` in plugin framework | 1 |
| 5 | Documentation | — |
| **Total** | | **~25 new tests** |

## What Does NOT Change

- `prepare_request()` — auto-detection still works for `session.get()`/`session.post()`
- `headers_for()` — public API unchanged
- Session serialization — `gp_base_url` is set at runtime, not persisted
- `_detect_profile()` — only the non-GET/POST default changes
- Response parsing / error wrapping — deferred to follow-up PR per issue decision
