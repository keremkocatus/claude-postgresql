"""HTML for the sign-in pages and the security headers every auth page carries.

Every value that reaches the HTML is escaped; the pages have no script, and the CSP allows only the one inline
stylesheet (by hash). ``form-action`` also lists the client's redirect origin, because browsers apply it to the
redirect that follows the POST.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
import unicodedata
from html import escape
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse, Response

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 20px;color:#1a1a1a}"
    "h1{font-size:1.15rem}p{line-height:1.4}.muted{color:#555;font-size:.9rem}.error{color:#b00020}"
    "input{width:100%;padding:10px;margin:0 0 12px;box-sizing:border-box;border:1px solid #bbb;border-radius:6px}"
    "button{width:100%;padding:10px;border:0;border-radius:6px;background:#1a1a1a;color:#fff;cursor:pointer}"
)
_STYLE_SOURCE = "'sha256-" + base64.b64encode(hashlib.sha256(_STYLE.encode()).digest()).decode() + "'"
_MAX_CLIENT_NAME = 80
_UNNAMED_CLIENT = "An unnamed application"
_DNS_NAME = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*")


def _origin_host(host: str) -> str | None:
    """``host`` as it appears in an origin (IPv6 bracketed), or ``None`` unless it is a plain DNS name or IP."""
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return None
        return None if "%" in host else f"[{host}]"
    return host if _DNS_NAME.fullmatch(host) else None


def origin_of(url: str) -> str | None:
    """``scheme://host[:port]`` of an http(s) URL, or ``None`` when the URL has no plain origin.

    The result goes into a CSP header, so anything but a validated scheme, host and port is refused rather than
    copied (a ``;`` or space in the authority would otherwise add directives).
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or not parts.netloc.isascii():
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = _origin_host(parts.hostname or "")
    if host is None:
        return None
    return f"{scheme}://{host}" if port is None else f"{scheme}://{host}:{port}"


def apply_security_headers[R: Response](response: R, *, form_action_origin: str | None = None) -> R:
    form_action = "'self'" if form_action_origin is None else f"'self' {form_action_origin}"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src {_STYLE_SOURCE}; form-action {form_action}; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def _document(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>{body}</body></html>"
    )


def _display_name(client_name: str | None) -> str:
    """The client's self-chosen name without control, format (bidi, zero-width) or line-break characters."""
    raw = (client_name or "")[: _MAX_CLIENT_NAME * 4]
    visible = "".join(" " if ch.isspace() else ch for ch in raw if unicodedata.category(ch)[0] != "C" or ch.isspace())
    name = " ".join(visible.split())[:_MAX_CLIENT_NAME]
    return name or _UNNAMED_CLIENT


def login_page(
    *,
    request_id: str,
    csrf_token: str,
    client_name: str | None,
    redirect_uri: str,
    username: str = "",
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    name = _display_name(client_name)
    redirect_host = urlsplit(redirect_uri).hostname or redirect_uri
    error_html = f'<p class="error" role="alert">{escape(error)}</p>' if error else ""
    body = (
        "<h1>Sign in to Ratatoskr</h1>"
        f"<p><strong>{escape(name)}</strong> is asking for access to your connections.</p>"
        f'<p class="muted">After you sign in you will be sent to <strong>{escape(redirect_host)}</strong>.</p>'
        f"{error_html}"
        '<form method="post" action="/login">'
        f'<input type="hidden" name="request" value="{escape(request_id)}">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        f'<input name="username" autocomplete="username" placeholder="Username" value="{escape(username)}" required>'
        '<input type="password" name="password" autocomplete="current-password" placeholder="Password" required>'
        '<button type="submit">Sign in and authorize</button>'
        "</form>"
    )
    response = HTMLResponse(_document("Sign in — Ratatoskr", body), status_code=status_code)
    return apply_security_headers(response, form_action_origin=origin_of(redirect_uri))


def message_page(title: str, message: str, status_code: int) -> HTMLResponse:
    body = f"<h1>{escape(title)}</h1><p>{escape(message)}</p>"
    return apply_security_headers(HTMLResponse(_document(title, body), status_code=status_code))
