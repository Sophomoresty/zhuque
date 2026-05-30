"""WebSocket, HTTP, CDP transport and browser helpers."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import random
import time
import socket
import ssl as ssl_module
import urllib.parse
from pathlib import Path
from typing import Any

import requests
import websockets
import websockets.sync.client
try:
    from websockets.extensions.permessage_deflate import ClientPerMessageDeflateFactory
except Exception:  # pragma: no cover
    ClientPerMessageDeflateFactory = None
try:
    import socks as pysocks
except Exception:  # pragma: no cover
    pysocks = None

from .config import (
    CODEX_TASKS_ROOT,
    DEFAULT_UA,
    EGRESS_META_CACHE,
    EGRESS_META_LOCK,
    FP_RE,
    HTTP_BASE,
    WINDOWS_CODEX_CHROME_LEVELDB,
    WINDOWS_GOOGLE_CHROME_LEVELDB_ROOTS,
)

from .browser_cdp import (  # compat re-export for existing callers
    BrowserCdpConnection,
    agent_browser_action,
    agent_browser_close_tab,
    agent_browser_eval,
    agent_browser_execute_js,
    agent_browser_get_fp,
    agent_browser_open_new_tab,
    browser_cdp_eval,
    browser_cdp_get_fp,
    browser_cdp_wait_target_ready,
    browser_ws_endpoint,
    build_browser_selector,
    ensure_browser_bridge,
    unwrap_agent_browser_js_result,
    wait_browser_session_ready,
)


def json_dump(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def parse_last_json(stdout: str) -> Any:
    text = stdout.strip()
    if text:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        start = text.find('{')
        end = text.rfind('}')
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise ValueError(f'failed to parse JSON stdout: {stdout[-400:]}')


def make_fp(seed: str | None = None) -> str:
    # Mirrors app.e2822ee9.js setFp(): sha256(`${visitorId}_${Date.now()}_${Math.random()}`).substring(0, 32).
    # In pure protocol mode we cannot run FingerprintJS, so we use a stable browser-like visitor seed plus
    # fresh timestamp/random entropy. This preserves the server-visible fp shape and avoids raw random bytes.
    if seed is None:
        visitor_id = os.environ.get("MATRIX_AI_VISITOR_ID") or hashlib.sha256(
            f"{DEFAULT_UA}|Win32|zh-CN|1920x1080|16|matrix".encode()
        ).hexdigest()
        seed = f"{visitor_id}_{int(time.time() * 1000)}_{random.random()}"
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


def xff_for_iteration(seed: str, iteration: int) -> str:
    if not seed:
        return ""
    if "{i}" in seed:
        return seed.format(i=iteration, n=iteration)
    if seed.endswith("."):
        return f"{seed}{iteration}"
    return seed


def rotate_xff_pool_for_pattern(pattern: str, *, count: int, start: int = 1) -> list[str]:
    count = max(0, int(count or 0))
    return [xff_for_iteration(pattern, i) for i in range(max(1, int(start or 1)), max(1, int(start or 1)) + count)]


def parse_extra_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise SystemExit(f"invalid --header, expected Name: Value: {value}")
    name, val = value.split(":", 1)
    name = name.strip()
    val = val.strip()
    if not name:
        raise SystemExit(f"invalid --header, empty name: {value}")
    return name, val


def build_ws_headers(*, xff: str = "", headers: list[str] | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    if xff:
        out["X-Forwarded-For"] = xff
    for item in headers or []:
        name, val = parse_extra_header(item)
        out[name] = val
    return out


def request_proxies(egress_proxy: str = "") -> dict[str, str] | None:
    proxy = str(egress_proxy or "").strip()
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def proxy_public_ip(egress_proxy: str = "", *, timeout: float = 10.0) -> dict[str, Any]:
    session = requests.Session()
    if egress_proxy:
        session.trust_env = False
    last_error = ""
    for url in ("https://api.ipify.org?format=json", "http://api.ipify.org?format=json"):
        try:
            r = session.get(
                url,
                proxies=request_proxies(egress_proxy),
                timeout=timeout,
            )
            try:
                data = r.json()
                ip = str(data.get("ip") or "").strip()
            except Exception:
                ip = r.text.strip()[:80]
            return {
                "ok": bool(r.ok and ip),
                "status_code": r.status_code,
                "ip": ip,
                "egress_proxy": egress_proxy,
                "probe_url": url,
            }
        except Exception as exc:
            last_error = repr(exc)
    return {"ok": False, "error": last_error, "egress_proxy": egress_proxy}


def make_http_proxy_socket(
    *,
    target_host: str,
    target_port: int,
    proxy_url: str,
    timeout: float,
) -> socket.socket:
    parsed = urllib.parse.urlparse(proxy_url)
    if not parsed.hostname:
        raise ValueError(f"invalid proxy url: {proxy_url}")
    proxy_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    raw = socket.create_connection((parsed.hostname, proxy_port), timeout=timeout)
    if parsed.scheme == "https":
        raw = ssl_module.create_default_context().wrap_socket(raw, server_hostname=parsed.hostname)
    auth_header = ""
    if parsed.username:
        user = urllib.parse.unquote(parsed.username)
        password = urllib.parse.unquote(parsed.password or "")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {token}\r\n"
    req = (
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        "Proxy-Connection: keep-alive\r\n"
        f"{auth_header}"
        "\r\n"
    )
    raw.sendall(req.encode())
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = raw.recv(4096)
        if not chunk:
            break
        data += chunk
    first_line = data.split(b"\r\n", 1)[0]
    if b" 200 " not in first_line:
        with contextlib.suppress(Exception):
            raw.close()
        raise RuntimeError(f"proxy CONNECT failed: {first_line.decode(errors='ignore')}")
    return raw


def make_socks_proxy_socket(
    *,
    target_host: str,
    target_port: int,
    proxy_url: str,
    timeout: float,
) -> socket.socket:
    if pysocks is None:
        raise RuntimeError("PySocks is required for socks egress proxies")
    parsed = urllib.parse.urlparse(proxy_url)
    if not parsed.hostname:
        raise ValueError(f"invalid proxy url: {proxy_url}")
    scheme = parsed.scheme.lower()
    if scheme in {"socks4", "socks4a"}:
        proxy_type = pysocks.SOCKS4
    elif scheme in {"socks5", "socks5h"}:
        proxy_type = pysocks.SOCKS5
    else:
        raise ValueError(f"unsupported socks proxy scheme: {scheme}")
    sock = pysocks.socksocket()
    sock.settimeout(timeout)
    sock.set_proxy(
        proxy_type,
        parsed.hostname,
        parsed.port or 1080,
        username=urllib.parse.unquote(parsed.username) if parsed.username else None,
        password=urllib.parse.unquote(parsed.password) if parsed.password else None,
        rdns=scheme.endswith("h"),
    )
    sock.connect((target_host, target_port))
    return sock


def make_ws_proxy_socket(ws_url: str, egress_proxy: str, *, timeout: float) -> tuple[socket.socket, str]:
    proxy = str(egress_proxy or "").strip()
    if not proxy:
        raise ValueError("missing egress_proxy")
    target = urllib.parse.urlparse(ws_url)
    if target.scheme not in {"ws", "wss"} or not target.hostname:
        raise ValueError(f"invalid ws url: {ws_url}")
    target_port = target.port or (443 if target.scheme == "wss" else 80)
    scheme = urllib.parse.urlparse(proxy).scheme.lower()
    if scheme in {"http", "https"}:
        raw = make_http_proxy_socket(target_host=target.hostname, target_port=target_port, proxy_url=proxy, timeout=timeout)
    elif scheme in {"socks4", "socks4a", "socks5", "socks5h"}:
        raw = make_socks_proxy_socket(target_host=target.hostname, target_port=target_port, proxy_url=proxy, timeout=timeout)
    else:
        raise ValueError(f"unsupported egress proxy scheme: {scheme}")
    return raw, target.hostname


def ws_connect_kwargs(additional_headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers: dict[str, str] = {
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }
    headers.update(additional_headers or {})
    kwargs: dict[str, Any] = {
        'origin': HTTP_BASE,
        'user_agent_header': DEFAULT_UA,
        'additional_headers': headers,
    }
    if ClientPerMessageDeflateFactory is not None:
        kwargs['extensions'] = [
            ClientPerMessageDeflateFactory(
                client_max_window_bits=True,
                server_max_window_bits=15,
                compress_settings={'memLevel': 4},
            )
        ]
    return kwargs


def ws_connect_kwargs_with_egress(
    ws_url: str,
    additional_headers: dict[str, str] | None = None,
    *,
    egress_proxy: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    kwargs = ws_connect_kwargs(additional_headers)
    if egress_proxy:
        sock, server_hostname = make_ws_proxy_socket(ws_url, egress_proxy, timeout=timeout)
        kwargs.update({
            "sock": sock,
            "ssl": ssl_module.create_default_context(),
            "server_hostname": server_hostname,
        })
    return kwargs


def egress_meta(egress_proxy: str = "") -> dict[str, Any]:
    proxy = str(egress_proxy or "").strip()
    if not proxy:
        return {"enabled": False}
    with EGRESS_META_LOCK:
        cached = EGRESS_META_CACHE.get(proxy)
        if cached is not None:
            return dict(cached)
    public = proxy_public_ip(proxy, timeout=float(os.environ.get("MATRIX_AI_EGRESS_IP_TIMEOUT", "4") or "4"))
    meta = {
        "enabled": True,
        "proxy": proxy,
        "public_ip": public.get("ip") or "",
        "public_ip_ok": bool(public.get("ok")),
        "probe": public,
    }
    with EGRESS_META_LOCK:
        EGRESS_META_CACHE[proxy] = dict(meta)
    return meta


def make_fp_for_mode(mode: str, current: str = "") -> str:
    if mode == "fresh":
        return make_fp()
    return current or ""


def candidate_fp_files() -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for root in WINDOWS_GOOGLE_CHROME_LEVELDB_ROOTS:
        if not root.exists():
            continue
        leveldb_files = sorted(
            [
                *root.glob("*.ldb"),
                *root.glob("*.log"),
            ],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in leveldb_files[:12]:
            out.append(("windows-google-chrome-leveldb", path))
    if CODEX_TASKS_ROOT.exists():
        artifact_files = sorted(
            CODEX_TASKS_ROOT.glob("*/artifacts/*"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
            reverse=True,
        )
        for path in artifact_files[:80]:
            if path.is_file():
                out.append(("codex-task-artifact", path))
    if WINDOWS_CODEX_CHROME_LEVELDB is not None and WINDOWS_CODEX_CHROME_LEVELDB.exists():
        leveldb_files = sorted(
            [
                *WINDOWS_CODEX_CHROME_LEVELDB.glob("*.ldb"),
                *WINDOWS_CODEX_CHROME_LEVELDB.glob("*.log"),
            ],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in leveldb_files[:12]:
            out.append(("windows-codex-chrome-leveldb", path))
    return out


def extract_fps_from_file(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except Exception:
        return []
    text = data.decode("utf-8", errors="ignore")
    return sorted(set(FP_RE.findall(text)))


def discover_candidate_fps(
    *,
    preferred_fps: list[str] | None = None,
    bound: str = "",
    session_id: str = "",
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(fp: str, source: str, detail: str = "") -> None:
        if not fp or fp in seen:
            return
        seen.add(fp)
        entry: dict[str, Any] = {"fp": fp, "source": source}
        if detail:
            entry["detail"] = detail
        candidates.append(entry)

    for fp in preferred_fps or []:
        add(fp, "preferred")

    if bound or session_id:
        try:
            from .browser_state import browser_txt_state

            state = browser_txt_state(bound=bound, session_id=session_id, timeout=10.0)
            add(state.get("fp") or "", "browser-state", state.get("href") or "")
        except BaseException:
            pass

    for source, path in candidate_fp_files():
        for fp in extract_fps_from_file(path):
            add(fp, source, str(path))
    return candidates


def recv_json(ws: websockets.sync.client.ClientConnection) -> dict[str, Any]:
    raw = ws.recv(timeout=10)
    if isinstance(raw, bytes):
        raw = raw.decode()
    return json.loads(raw)


def load_text_arg(text: str | None, text_file: str | None) -> str:
    out = Path(text_file).read_text(encoding='utf-8') if text_file else text
    if not out:
        raise SystemExit('missing text')
    return out


def load_ticket_args(ticket: str | None, randstr: str | None, ticket_json: str | None) -> tuple[str, str]:
    if ticket_json:
        obj = json.loads(Path(ticket_json).read_text(encoding='utf-8'))
        payload = obj.get('js_return', {}).get('payload') or obj.get('payload') or {}
        ticket = payload.get('ticket') or obj.get('ticket') or ticket
        randstr = payload.get('randstr') or obj.get('randstr') or randstr
    if not ticket or not randstr:
        raise SystemExit('missing ticket/randstr or valid --ticket-json')
    return ticket, randstr


def normalize_cdp_context_proxy_server(value: str) -> str:
    proxy = str(value or "").strip()
    if not proxy:
        return ""
    parsed = urllib.parse.urlparse(proxy if "://" in proxy else f"http://{proxy}")
    if not parsed.hostname:
        raise ValueError(f"invalid CDP context proxy server: {value}")
    scheme = parsed.scheme.lower() or "http"
    if scheme not in {"http", "https", "socks4", "socks5"}:
        raise ValueError(f"unsupported CDP context proxy scheme: {scheme}")
    port = parsed.port or ({"http": 80, "https": 443, "socks4": 1080, "socks5": 1080}[scheme])
    auth = ""
    if parsed.username:
        auth = urllib.parse.unquote(parsed.username)
        if parsed.password:
            auth += ":" + urllib.parse.unquote(parsed.password)
        auth += "@"
    return f"{scheme}://{auth}{parsed.hostname}:{port}"


def parse_cdp_context_proxy_pool(values: list[str] | None) -> list[str]:
    from .batch import parse_rotate_xff_candidates
    return parse_rotate_xff_candidates(values)
