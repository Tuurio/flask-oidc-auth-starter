from __future__ import annotations

import json
import html
import re
from datetime import datetime
from urllib.parse import urlencode, urlparse

from authlib.integrations.flask_client import OAuth
from flask import Flask, redirect, request, session, url_for

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

oauth = OAuth(app)
oauth.register(
    name="tuurio",
    client_id=config.CLIENT_ID,
    client_secret=config.CLIENT_SECRET,
    server_metadata_url=config.DISCOVERY_ENDPOINT,
    client_kwargs={"scope": config.SCOPE},
)


@app.route("/")
def index():
    token = session.get("token")
    error = session.pop("error", None)

    status = (
        {"label": "Authenticated", "tone": "good", "authority": config.AUTHORITY}
        if token
        else {"label": "Signed out", "tone": "neutral", "authority": config.AUTHORITY}
    )
    content = (
        render_token_view(token, config.AUTHORITY, config.DISCOVERY_ENDPOINT)
        if token
        else render_login_view(error, authority_host(config.AUTHORITY), not config.HAS_APP_CONFIG)
    )
    return render_page(status, content)


@app.route("/login")
def login():
    if not config.HAS_APP_CONFIG:
        session["error"] = (
            "Configuration missing. Copy .env.example to .env or provide the TUURIO_* "
            "environment variables before signing in."
        )
        return redirect("/")

    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.tuurio.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    try:
        token = oauth.tuurio.authorize_access_token()
        if not token or "access_token" not in token:
            raise RuntimeError("Missing access token.")
        session["token"] = token

        metadata = oauth.tuurio.load_server_metadata()
        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if not userinfo_endpoint:
            raise RuntimeError("UserInfo endpoint missing from discovery metadata.")
        resp = oauth.tuurio.get(userinfo_endpoint, token=token)
        resp.raise_for_status()
        userinfo = resp.json()
        session["userinfo"] = userinfo
    except Exception as exc:  # pylint: disable=broad-except
        session["error"] = str(exc) or "Login failed."
    return redirect("/")


@app.route("/logout")
def logout():
    try:
        metadata = oauth.tuurio.load_server_metadata()
        end_session = metadata.get("end_session_endpoint")
        if not end_session:
            raise RuntimeError("End session endpoint not found.")
        token = session.get("token") or {}
        id_token_hint = token.get("id_token")

        session.clear()

        params = {
            "client_id": config.CLIENT_ID,
            "post_logout_redirect_uri": config.POST_LOGOUT_REDIRECT_URI,
        }
        if id_token_hint:
            params["id_token_hint"] = id_token_hint

        return redirect(end_session + "?" + urlencode(params))
    except Exception as exc:  # pylint: disable=broad-except
        session["error"] = str(exc) or "Logout failed."
        return redirect("/")


@app.route("/logout/callback")
def logout_callback():
    status = {"label": "Signed out", "tone": "neutral", "authority": config.AUTHORITY}
    return render_page(status, render_logout_callback())


@app.post(config.WEBHOOK_LISTEN_PATH)
def receive_webhook():
    provided_api_key = request.headers.get(config.WEBHOOK_API_KEY_HEADER, "")
    if config.WEBHOOK_API_KEY and provided_api_key != config.WEBHOOK_API_KEY:
        app.logger.warning("[tuurio-webhook] rejected request with invalid API key header")
        return {"accepted": False, "error": "invalid_api_key"}, 401

    event_type = request.headers.get("X-Tuurio-Event", "unknown")
    event_id = request.headers.get("X-Tuurio-Event-Id", "")
    signature = request.headers.get("X-Tuurio-Signature", "")
    payload = request.get_json(silent=True)
    if payload is None:
        payload = request.get_data(as_text=True) or ""

    app.logger.info(
        "[tuurio-webhook] event received %s",
        json.dumps(
            {
                "webhookId": config.WEBHOOK_ID or None,
                "eventType": event_type,
                "eventId": event_id,
                "signature": signature,
                "payload": payload,
            },
            indent=2,
            ensure_ascii=False,
        ),
    )
    return {"accepted": True}, 202


@app.errorhandler(404)
def not_found(_):
    status = {"label": "Route not found", "tone": "neutral", "authority": config.AUTHORITY}
    content = render_not_found()
    return render_page(status, content), 404


def render_page(status: dict, content: str) -> str:
    return (
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"utf-8\" />"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
        "<title>Tuurio Auth Studio</title>"
        "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/assets/favicon.svg\" />"
        "<link rel=\"stylesheet\" href=\"/static/assets/app.css\" />"
        "</head>"
        "<body>"
        f"<div id=\"app\">{render_shell(status, content)}</div>"
        f"{render_copy_script()}"
        "</body>"
        "</html>"
    )


def render_shell(status: dict, content: str) -> str:
    tone = html.escape(status.get("tone", "neutral"))
    label = html.escape(status.get("label", ""))
    host = html.escape(authority_host(status.get("authority", "")))

    return f"""
    <div class="app">
      <aside class="side-panel">
        <div class="brand">
          <div class="logo-mark">tu</div>
          <div>
            <p class="brand-name">Tuurio Auth Studio</p>
            <p class="brand-subtitle">OIDC playground for OAuth 2.0</p>
          </div>
        </div>
        <div class="side-card">
          <h1>Design for<br>secure sign in.</h1>
          <p class="muted">
            A minimal Python server that authenticates with OpenID Connect,
            inspects decoded tokens, and handles secure logout.
          </p>
          <div class="status-row">
            <span class="status status-{tone}">{label}</span>
            <span class="muted">{host}</span>
          </div>
        </div>
        <div class="side-list">
          <div class="side-list-item">
            <span class="side-list-icon">{icon("code", 16)}</span>
            <div>
              <span class="side-list-label">Architecture</span>
              <span class="side-list-value">Auth code + PKCE</span>
            </div>
          </div>
          <div class="side-list-item">
            <span class="side-list-icon">{icon("server", 16)}</span>
            <div>
              <span class="side-list-label">Storage</span>
              <span class="side-list-value">Server session</span>
            </div>
          </div>
          <div class="side-list-item">
            <span class="side-list-icon">{icon("layers", 16)}</span>
            <div>
              <span class="side-list-label">Scope</span>
              <span class="side-list-value">openid profile email</span>
            </div>
          </div>
        </div>
      </aside>
      <main class="main-panel">{content}</main>
    </div>
    """


def render_login_view(error: str | None, authority_host_label: str, config_missing: bool) -> str:
    error_html = f"<div class=\"alert alert-error\">{html.escape(error)}</div>" if error else ""
    warning_html = (
        "<div class=\"alert alert-error\">"
        f"<strong>{icon('x-circle', 16)} Configuration missing</strong><br>"
        "Copy <code>.env.example</code> to <code>.env</code> or provide the required "
        "<code>TUURIO_*</code> environment variables before signing in."
        "</div>"
        if config_missing
        else ""
    )
    button_html = (
        "<button class=\"button primary\" type=\"button\" disabled>"
        "Continue with Tuurio ID <span class=\"btn-arrow\">&rarr;</span></button>"
        if config_missing
        else "<a class=\"button primary\" href=\"/login\">"
        "Continue with Tuurio ID <span class=\"btn-arrow\">&rarr;</span></a>"
    )

    return f"""
    <div class="stack">
      {warning_html}
      <section class="card card-hero">
        <div class="card-header">
          <span class="eyebrow">OAuth 2.0 + OpenID Connect</span>
          <h2 class="card-title">Sign in to continue</h2>
          <p class="muted">
            Authenticate with the authorization code flow and PKCE.
            Tokens are exchanged server-side and stored in the Flask session.
          </p>
        </div>
        <div class="button-row">
          {button_html}
          <span class="helper">Redirects to {html.escape(authority_host_label)}</span>
        </div>
        {error_html}
      </section>

      <div class="feature-grid">
        <div class="feature-card">
          <div class="feature-icon">{icon("shield", 18)}</div>
          <h3>PKCE by default</h3>
          <p class="muted">Proof Key for Code Exchange prevents authorization code interception attacks.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">{icon("clock", 18)}</div>
          <h3>Short-lived tokens</h3>
          <p class="muted">Access tokens expire quickly, scoped to openid&nbsp;profile&nbsp;email.</p>
        </div>
        <div class="feature-card">
          <div class="feature-icon">{icon("server", 18)}</div>
          <h3>Session aware</h3>
          <p class="muted">Token state lives server-side. Nothing sensitive reaches the browser.</p>
        </div>
      </div>
    </div>
    """


def render_token_view(token: dict, authority: str, discovery_endpoint: str) -> str:
    scope_label = token.get("scope") or config.SCOPE
    expires_at = token.get("expires_at")
    if expires_at is None and token.get("expires_in"):
        expires_at = int(datetime.utcnow().timestamp()) + int(token.get("expires_in"))

    userinfo = session.get("userinfo")
    profile_json = json.dumps(userinfo, indent=2) if userinfo else "No profile data."

    now = int(datetime.utcnow().timestamp())
    timing_parts: list[str] = []
    if expires_at is not None:
        remaining = int(expires_at) - now
        timing_parts.append(
            f"{format_duration(remaining)} remaining"
            if remaining > 0
            else f"expired {format_duration(abs(remaining))} ago"
        )
    expiry_line = (
        f"<code>{html.escape(scope_label)}</code> &middot; {' &middot; '.join(timing_parts)}"
        if timing_parts
        else f"<code>{html.escape(scope_label)}</code>"
    )

    return f"""
    <div class="stack">
      <section class="card card-hero">
        <div class="card-header">
          <span class="badge badge-success">{icon("check-circle", 14)} Authenticated</span>
          <h2 class="card-title">Session active</h2>
          <p class="muted">{expiry_line}</p>
        </div>
        <div class="button-row">
          <a class="button ghost" href="/logout">Log out and end session</a>
          <span class="helper">Clears local state and notifies the identity provider.</span>
        </div>
      </section>

      <section class="card">
        <div class="section-header">
          <div class="section-icon">{icon("user", 18)}</div>
          <div>
            <h3 class="section-title">User profile</h3>
            <p class="muted">Claims returned by the UserInfo endpoint.</p>
          </div>
        </div>
        <pre class="code-block">{highlight_json_html(html.escape(profile_json))}</pre>
      </section>

      {render_discovery_section(authority, discovery_endpoint)}
    </div>
    """


def render_discovery_section(authority: str, discovery_endpoint: str) -> str:
    safe_authority = html.escape(authority)
    safe_discovery_endpoint = html.escape(discovery_endpoint)
    return f"""
      <section class="card">
        <div class="section-header">
          <div class="section-icon">{icon("globe", 18)}</div>
          <div>
            <h3 class="section-title">Provider discovery</h3>
            <p class="muted">OIDC metadata used to resolve endpoints and session management URLs.</p>
          </div>
        </div>
        <div class="stack">
          <div>
            <span class="eyebrow">Authority</span>
            <p><a class="link" href="{safe_authority}" target="_blank" rel="noreferrer">{safe_authority}</a></p>
          </div>
          <div>
            <span class="eyebrow">Discovery document</span>
            <p><a class="link" href="{safe_discovery_endpoint}" target="_blank" rel="noreferrer">{safe_discovery_endpoint}</a></p>
          </div>
        </div>
      </section>
    """


def render_not_found() -> str:
    return f"""
      <section class="card card-hero">
        <div class="card-header">
          <span class="badge badge-error">{icon("x-circle", 14)} 404</span>
          <h2 class="card-title">Route not found</h2>
          <p class="muted">This path doesn't match any known endpoint.</p>
        </div>
        <div class="button-row">
          <a class="button ghost" href="/">
            Go home
            <span class="btn-arrow">&rarr;</span>
          </a>
        </div>
      </section>
    """


def render_logout_callback() -> str:
    return f"""
      <div class="stack">
        <section class="card card-hero">
          <div class="card-header">
            <span class="badge badge-neutral">{icon("check-circle", 14)} Session ended</span>
            <h2 class="card-title">Successfully signed out</h2>
            <p class="muted">
              Local session destroyed. The identity provider has been notified via RP-Initiated Logout.
            </p>
          </div>
          <div class="button-row">
            <a class="button primary" href="/login">
              Sign in again
              <span class="btn-arrow">&rarr;</span>
            </a>
            <span class="helper">Redirects to the identity provider.</span>
          </div>
        </section>

        <section class="card">
          <div class="section-header">
            <div class="section-icon">{icon("server", 18)}</div>
            <div>
              <h3 class="section-title">Session state</h3>
              <p class="muted">Flask session storage has been cleared before returning to this page.</p>
            </div>
          </div>
          <div class="stack">
            <div>
              <span class="eyebrow">Session</span>
              <p class="muted">Access token, ID token, and UserInfo data removed.</p>
            </div>
            <div>
              <span class="eyebrow">Post-logout URI</span>
              <p class="muted">{html.escape(config.POST_LOGOUT_REDIRECT_URI)}</p>
            </div>
          </div>
        </section>
      </div>
    """


def render_copy_script() -> str:
    return """
    <script>
    document.querySelectorAll('.token-block, .code-block').forEach(function(pre) {
      var wrap = document.createElement('div');
      wrap.className = 'copy-wrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      var btn = document.createElement('button');
      btn.className = 'copy-btn';
      btn.textContent = 'Copy';
      btn.addEventListener('click', function() {
        navigator.clipboard.writeText(pre.textContent).then(function() {
          btn.textContent = 'Copied!';
          btn.classList.add('copied');
          setTimeout(function() {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
          }, 1500);
        });
      });
      wrap.appendChild(btn);
    });
    </script>
    """


def authority_host(authority: str) -> str:
    parsed = urlparse(authority)
    return parsed.netloc or "id.tuurio.com"


def icon(name: str, size: int = 18) -> str:
    paths = {
        "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
        "user": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
        "key": '<path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
        "id-card": '<rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/>',
        "globe": '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
        "code": '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
        "server": '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
        "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
        "check-circle": '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
        "x-circle": '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    }
    inner = paths.get(name, "")
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{inner}</svg>'
    )


def highlight_json_html(escaped_html: str) -> str:
    highlighted = re.sub(
        r'(&quot;)((?:(?!&quot;).)*?)(&quot;)(\s*:)',
        r'<span class="hl-key">\1\2\3</span>\4',
        escaped_html,
    )
    highlighted = re.sub(
        r'(:\s*)(&quot;)((?:(?!&quot;).)*?)(&quot;)',
        r'\1<span class="hl-str">\2\3\4</span>',
        highlighted,
    )
    highlighted = re.sub(
        r'([\[,]\s*)(&quot;)((?:(?!&quot;).)*?)(&quot;)',
        r'\1<span class="hl-str">\2\3\4</span>',
        highlighted,
    )
    highlighted = re.sub(
        r'(:\s*)(-?\d+(?:\.\d+)?)([,\s\n\r}])',
        r'\1<span class="hl-num">\2</span>\3',
        highlighted,
    )
    highlighted = re.sub(
        r'(:\s*)(true|false|null)\b',
        r'\1<span class="hl-bool">\2</span>',
        highlighted,
    )
    return highlighted


def format_duration(seconds: int) -> str:
    seconds = abs(int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        minutes = seconds // 60
        remainder = seconds % 60
        return f"{minutes}m {remainder}s" if remainder else f"{minutes}m"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


if __name__ == "__main__":
    print(f"[tuurio-webhook] listening on http://localhost:8083{config.WEBHOOK_LISTEN_PATH}")
    if config.WEBHOOK_EDIT_URL:
        print(f"[tuurio-webhook] update endpoint URL after deployment at {config.WEBHOOK_EDIT_URL}")
    app.run(port=8083, debug=True)
