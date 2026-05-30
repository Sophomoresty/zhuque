"""Agent Browser and browser-level CDP helpers."""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import requests
import websockets.sync.client

from .config import (
    AGENT_BROWSER_CLI,
    AGENT_BROWSER_STATE_FILE,
    DEFAULT_BOUND,
    DEFAULT_MEDIA_BOUND,
    MATRIX_PIC_URL,
    MATRIX_TXT_URL,
)


def _parse_last_json(stdout: str) -> Any:
    text = stdout.strip()
    if text:
        with contextlib.suppress(json.JSONDecodeError):
            return json.loads(text)
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            with contextlib.suppress(json.JSONDecodeError):
                return json.loads(text[start:end + 1])
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            return json.loads(line)
    raise ValueError(f"failed to parse JSON stdout: {stdout[-400:]}")


def _run_json_command(argv: list[str], timeout: float = 30.0) -> Any:
    env = os.environ.copy()
    if argv and Path(argv[0]).name == AGENT_BROWSER_CLI:
        remove_bins = {str(Path.home() / "bin")}
        if env.get("VIRTUAL_ENV"):
            remove_bins.add(str(Path(env["VIRTUAL_ENV"]) / "bin"))
        parts = [p for p in str(env.get("PATH") or "").split(os.pathsep) if p]
        env["PATH"] = os.pathsep.join(p for p in parts if p not in remove_bins)
        env.pop("VIRTUAL_ENV", None)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise SystemExit(
            f'command failed rc={proc.returncode}: {" ".join(argv)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        )
    return _parse_last_json(proc.stdout)


def build_browser_selector(*, bound: str = "", session_id: str = "") -> list[str]:
    if session_id:
        return ["--session-id", str(session_id)]
    return ["--bound", bound or DEFAULT_BOUND]


def unwrap_agent_browser_js_result(raw: Any) -> Any:
    value = raw
    if isinstance(raw, dict):
        for key in ("data", "js_return", "result"):
            if key in raw:
                value = raw.get(key)
                break
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            with contextlib.suppress(Exception):
                return json.loads(stripped)
        return value
    return value


def _ab_data(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        if isinstance(raw.get("data"), dict):
            return raw["data"]
        nested = raw.get("result")
        if isinstance(nested, dict) and isinstance(nested.get("data"), dict):
            return nested["data"]
    return {}


def _ab_target_id(data: dict[str, Any]) -> str:
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    return str(
        data.get("targetId")
        or data.get("id")
        or target.get("targetId")
        or target.get("id")
        or ""
    )


def _target_for_legacy_selector(bound: str = "", session_id: str = "", *, timeout: float = 30.0) -> str:
    if session_id:
        return str(session_id)
    target = MATRIX_PIC_URL if (bound or "") == DEFAULT_MEDIA_BOUND else (MATRIX_TXT_URL if bound else "current")
    raw = agent_browser_action(
        [
            "target",
            "resolve",
            "--target",
            target,
            "--open-policy",
            "reuse-or-new",
            "--owner",
            "matrix-ai-cli",
            "--purpose",
            "cdp-eval",
        ],
        timeout=timeout,
    )
    target_id = str(_ab_data(raw).get("targetId") or "")
    if not target_id:
        raise SystemExit(f"failed to resolve browser target: {raw}")
    return target_id


def _unwrap_runtime_evaluate(raw: Any) -> Any:
    data = _ab_data(raw)
    if not data.get("ok"):
        raise SystemExit(f"agent-browser Runtime.evaluate failed: {raw}")
    result = data.get("result") if isinstance(data.get("result"), dict) else {}
    if result.get("exceptionDetails"):
        raise SystemExit(f"agent-browser Runtime.evaluate exception: {result['exceptionDetails']}")
    inner = result.get("result") if isinstance(result.get("result"), dict) else {}
    if "value" in inner:
        return inner.get("value")
    if inner.get("type") == "undefined":
        return None
    return inner or result


def _direct_cdp_eval_target(target_id: str, *, script: str, timeout: float = 30.0) -> Any:
    ws_endpoint = browser_ws_endpoint()
    with BrowserCdpConnection(ws_endpoint, timeout=max(20.0, timeout)) as conn:
        attach = conn.call(
            "Target.attachToTarget",
            {"targetId": target_id, "flatten": True},
            timeout=10.0,
        )
        cdp_session_id = str(attach.get("sessionId") or "")
        if not cdp_session_id:
            raise RuntimeError(f"missing CDP sessionId: {attach}")
        try:
            with contextlib.suppress(Exception):
                conn.call("Runtime.enable", session_id=cdp_session_id, timeout=10.0)
            return browser_cdp_eval(
                conn,
                session_id=cdp_session_id,
                expression=script,
                timeout=max(20.0, timeout),
            )
        finally:
            with contextlib.suppress(Exception):
                conn.call("Target.detachFromTarget", {"sessionId": cdp_session_id}, timeout=5.0)


def agent_browser_execute_js(*, bound: str = "", session_id: str = "", script: str, timeout: float = 30.0) -> Any:
    if not shutil.which(AGENT_BROWSER_CLI):
        raise SystemExit(f'{AGENT_BROWSER_CLI} not found on PATH')
    target_id = _target_for_legacy_selector(bound=bound, session_id=session_id, timeout=max(30.0, timeout))
    direct_error = ""
    try:
        return _direct_cdp_eval_target(target_id, script=script, timeout=timeout)
    except BaseException as exc:
        direct_error = str(exc)
    with contextlib.suppress(Exception):
        agent_browser_action(["network", "start", "--target-id", target_id, "--filter", "matrix.tencent.com"], timeout=max(10.0, min(timeout, 30.0)))
    params = {
        "expression": script,
        "returnByValue": True,
        "awaitPromise": True,
        "userGesture": True,
    }
    raw = agent_browser_action(
        [
            "network",
            "command",
            "--target-id",
            target_id,
            "--params-json",
            json.dumps(params, ensure_ascii=False, separators=(",", ":")),
            "Runtime.evaluate",
        ],
        timeout=timeout + 20,
    )
    data = _ab_data(raw)
    if str(data.get("error") or "") in {"session_not_attached", "session_not_open"}:
        agent_browser_action(["network", "start", "--target-id", target_id, "--filter", "matrix.tencent.com"], timeout=max(10.0, min(timeout, 30.0)))
        raw = agent_browser_action(
            [
                "network",
                "command",
                "--target-id",
                target_id,
                "--params-json",
                json.dumps(params, ensure_ascii=False, separators=(",", ":")),
                "Runtime.evaluate",
            ],
            timeout=timeout + 20,
        )
    try:
        return _unwrap_runtime_evaluate(raw)
    except SystemExit as exc:
        if direct_error:
            raise SystemExit(f"{exc}; direct_cdp_error={direct_error}") from exc
        raise


def agent_browser_get_fp(*, bound: str = "", session_id: str = "", timeout: float = 10.0) -> str:
    value = agent_browser_execute_js(
        bound=bound,
        session_id=session_id,
        script="(()=>localStorage.getItem('fp')||'')()",
        timeout=timeout,
    )
    return str(value or "")


def agent_browser_eval(*, bound: str = "", session_id: str = "", expr: str, timeout: float = 10.0) -> Any:
    if not shutil.which(AGENT_BROWSER_CLI):
        raise SystemExit(f'{AGENT_BROWSER_CLI} not found on PATH')
    return agent_browser_execute_js(bound=bound, session_id=session_id, script=expr, timeout=timeout)


def agent_browser_action(argv: list[str], timeout: float = 30.0) -> Any:
    if not shutil.which(AGENT_BROWSER_CLI):
        raise SystemExit(f'{AGENT_BROWSER_CLI} not found on PATH')
    return _run_json_command([AGENT_BROWSER_CLI, '--compact', *argv], timeout=timeout)


def _bridge_envelope_usable(envelope: Any) -> bool:
    if not isinstance(envelope, dict):
        return False
    if envelope.get('ok'):
        return True
    data = envelope.get('data') if isinstance(envelope.get('data'), dict) else {}
    health_live = data.get('live_link') if isinstance(data.get('live_link'), dict) else {}
    up_live = data.get('live') if isinstance(data.get('live'), dict) else {}
    chrome = data.get('chrome') if isinstance(data.get('chrome'), dict) else {}
    cdp_http = chrome.get('cdp_http') if isinstance(chrome.get('cdp_http'), dict) else {}
    return bool(
        (data.get('devtools_reachable') and data.get('target_devtools_reachable') and health_live.get('ok'))
        or (cdp_http.get('ok') and up_live.get('ok'))
    )


def _agent_browser_action_lenient(argv: list[str], timeout: float = 30.0) -> Any:
    if not shutil.which(AGENT_BROWSER_CLI):
        raise SystemExit(f'{AGENT_BROWSER_CLI} not found on PATH')
    proc = subprocess.run([AGENT_BROWSER_CLI, '--compact', *argv], capture_output=True, text=True, timeout=timeout)
    if proc.stdout.strip():
        parsed = _parse_last_json(proc.stdout)
        if proc.returncode == 0 or _bridge_envelope_usable(parsed):
            return parsed
    if proc.returncode != 0:
        raise SystemExit(
            f'command failed rc={proc.returncode}: {AGENT_BROWSER_CLI} --compact {" ".join(argv)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}'
        )
    return _parse_last_json(proc.stdout)


def ensure_browser_bridge(timeout: float = 60.0) -> Any:
    try:
        health = _agent_browser_action_lenient(['bridge-health'], timeout=min(timeout, 30.0))
        if _bridge_envelope_usable(health):
            return health
    except BaseException:
        pass
    return _agent_browser_action_lenient(['bridge-up'], timeout=timeout)


def agent_browser_open_new_tab(url: str, timeout: float = 30.0) -> str:
    argv = [
        "target",
        "resolve",
        "--target",
        url,
        "--open-policy",
        "new",
        "--owner",
        "matrix-ai-cli",
        "--purpose",
        "cdp-new-tab",
        "--ttl-sec",
        str(max(300, int(timeout) + 180)),
        "--protect",
    ]
    try:
        result = agent_browser_action(argv, timeout=timeout)
    except BaseException:
        ensure_browser_bridge(timeout=max(timeout, 60.0))
        result = agent_browser_action(argv, timeout=timeout)
    data = _ab_data(result)
    sid = _ab_target_id(data)
    if not sid:
        raise SystemExit(f'failed to open new tab: {result}')
    protected = bool((data.get("lease") or {}).get("protected") or data.get("protected"))
    if not protected:
        protect = agent_browser_action(
            [
                "target",
                "protect",
                "--target-id",
                sid,
                "--owner",
                "matrix-ai-cli",
                "--purpose",
                "cdp-new-tab",
                "--ttl-sec",
                str(max(300, int(timeout) + 180)),
            ],
            timeout=max(10.0, min(timeout, 30.0)),
        )
        protect_data = _ab_data(protect)
        if protect_data and protect_data.get("ok") is False:
            raise SystemExit(f"failed to protect new tab {sid}: {protect}")
    return str(sid)


def wait_browser_session_ready(session_id: str, *, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: Any = None
    while time.time() < deadline:
        try:
            state = agent_browser_eval(
                session_id=session_id,
                expr='(()=>({href:location.href,title:document.title,ready:document.readyState,vueCount:Array.from(document.querySelectorAll("*")).filter(e=>e.__vue__).length,fp:localStorage.getItem("fp")}))()',
                timeout=10.0,
            )
            last = state
            if isinstance(state, dict) and int(state.get("vueCount") or 0) > 0 and state.get("fp"):
                ready = str(state.get("ready") or "")
                if ready in {"interactive", "complete"}:
                    return state
        except (Exception, SystemExit) as exc:
            last = repr(exc)
        time.sleep(0.5)
    raise SystemExit(f"browser session not ready: {session_id} last={last}")


def agent_browser_close_tab(session_id: str, timeout: float = 20.0) -> Any:
    try:
        return agent_browser_action(["target", "release", "--target-id", str(session_id), "--close"], timeout=timeout)
    except BaseException:
        return agent_browser_action(['close-tab', str(session_id)], timeout=timeout)


def browser_ws_endpoint(
    *,
    ws_endpoint: str = "",
    version_url: str = "",
    state_file: str = "",
) -> str:
    if ws_endpoint:
        return ws_endpoint.strip()
    state_path = Path(state_file).expanduser() if state_file else AGENT_BROWSER_STATE_FILE
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        endpoint = (((data.get("chrome") or {}).get("devtools") or {}).get("ws_endpoint") or "").strip()
        if endpoint:
            return endpoint
    except Exception:
        pass
    version_url = (version_url or "http://127.0.0.1:19221/json/version").strip()
    try:
        r = requests.get(version_url, timeout=5.0)
        r.raise_for_status()
        endpoint = str((r.json() or {}).get("webSocketDebuggerUrl") or "").strip()
        if endpoint:
            return endpoint
    except Exception as exc:
        raise SystemExit(f"failed to resolve browser ws endpoint from bridge state/json.version: {exc}") from exc
    raise SystemExit("missing browser ws endpoint")


class BrowserCdpConnection:
    def __init__(self, ws_endpoint: str, *, timeout: float = 20.0):
        self.ws_endpoint = ws_endpoint
        self.timeout = timeout
        self.ws: Any | None = None
        self._next_id = 1

    def __enter__(self) -> "BrowserCdpConnection":
        self.ws = websockets.sync.client.connect(
            self.ws_endpoint,
            open_timeout=max(5.0, self.timeout),
            close_timeout=min(max(5.0, self.timeout), 10.0),
        )
        self.ws.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.ws is not None:
            self.ws.__exit__(exc_type, exc, tb)
            self.ws = None

    def call(self, method: str, params: dict[str, Any] | None = None, *, session_id: str = "", timeout: float | None = None) -> dict[str, Any]:
        if self.ws is None:
            raise RuntimeError("browser cdp connection not open")
        msg_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {
            "id": msg_id,
            "method": method,
            "params": params or {},
        }
        if session_id:
            payload["sessionId"] = session_id
        self.ws.send(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        deadline = time.time() + (timeout if timeout is not None else self.timeout)
        last: dict[str, Any] | None = None
        while time.time() < deadline:
            try:
                raw = self.ws.recv(timeout=max(0.5, min(2.0, deadline - time.time())))
            except TimeoutError:
                continue
            msg = json.loads(raw)
            last = msg if isinstance(msg, dict) else {}
            if isinstance(msg, dict) and msg.get("id") == msg_id:
                if msg.get("error"):
                    raise RuntimeError(f"cdp {method} failed: {msg['error']}")
                return dict(msg.get("result") or {})
        raise RuntimeError(f"cdp {method} timed out last={last}")


def browser_cdp_eval(
    conn: BrowserCdpConnection,
    *,
    session_id: str,
    expression: str,
    await_promise: bool = True,
    timeout: float = 20.0,
) -> Any:
    result = conn.call(
        "Runtime.evaluate",
        {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": await_promise,
            "userGesture": True,
        },
        session_id=session_id,
        timeout=timeout,
    )
    if result.get("exceptionDetails"):
        raise RuntimeError(f"Runtime.evaluate exception: {result['exceptionDetails']}")
    inner = result.get("result") or {}
    if "value" in inner:
        return inner.get("value")
    if inner.get("type") == "undefined":
        return None
    return inner


def browser_cdp_wait_target_ready(
    conn: BrowserCdpConnection,
    *,
    session_id: str,
    timeout: float = 30.0,
) -> dict[str, Any]:
    expr = '(()=>({href:location.href,title:document.title,ready:document.readyState,vueCount:Array.from(document.querySelectorAll("*")).filter(e=>e.__vue__).length,fp:localStorage.getItem("fp")}))()'
    deadline = time.time() + timeout
    last: Any = None
    while time.time() < deadline:
        try:
            state = browser_cdp_eval(conn, session_id=session_id, expression=expr, timeout=min(8.0, max(3.0, deadline - time.time())))
            last = state
            if isinstance(state, dict) and int(state.get("vueCount") or 0) > 0 and state.get("fp"):
                ready = str(state.get("ready") or "")
                if ready in {"interactive", "complete"}:
                    return state
        except Exception as exc:
            last = repr(exc)
        time.sleep(0.5)
    raise RuntimeError(f"browser target not ready session={session_id} last={last}")


def browser_cdp_get_fp(conn: BrowserCdpConnection, *, session_id: str, timeout: float = 10.0) -> str:
    value = browser_cdp_eval(
        conn,
        session_id=session_id,
        expression="(()=>localStorage.getItem('fp')||'')()",
        timeout=timeout,
    )
    return str(value or "")
